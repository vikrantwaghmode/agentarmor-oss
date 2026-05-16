package main

// Minimal Redis RESP2 client for distributed rate limiting.
// No external dependencies — uses net + stdlib only.
//
// When REDIS_URL is set, rate limiting state is shared across all proxy
// instances, enabling horizontal scaling. Falls back to in-memory token
// bucket if Redis is unavailable (fail-open).
//
// Supports:  redis://host:port  or  host:port  or  redis://:password@host:port

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	redisEnabled bool
	redisAddr    string
	redisPass    string
	redisPool    = &rPool{}
)

// ─── Connection pool ──────────────────────────────────────────────────────────

type rPool struct {
	mu    sync.Mutex
	conns []net.Conn
}

func (p *rPool) get() (net.Conn, error) {
	p.mu.Lock()
	for len(p.conns) > 0 {
		c := p.conns[len(p.conns)-1]
		p.conns = p.conns[:len(p.conns)-1]
		p.mu.Unlock()
		// Quick liveness check
		_ = c.SetReadDeadline(time.Now().Add(1 * time.Millisecond))
		buf := make([]byte, 1)
		if _, err := c.Read(buf); err != nil && strings.Contains(err.Error(), "timeout") {
			// No pending data — connection is alive
			_ = c.SetReadDeadline(time.Time{})
			return c, nil
		}
		c.Close()
		p.mu.Lock()
	}
	p.mu.Unlock()
	return net.DialTimeout("tcp", redisAddr, 3*time.Second)
}

func (p *rPool) put(c net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.conns) < 16 {
		p.conns = append(p.conns, c)
	} else {
		c.Close()
	}
}

// ─── Init ─────────────────────────────────────────────────────────────────────

func initRedis() {
	rawURL := os.Getenv("REDIS_URL")
	if rawURL == "" {
		return
	}

	// Parse redis://:password@host:port[/db]  or  host:port
	host := rawURL
	host = strings.TrimPrefix(host, "redis://")
	if at := strings.LastIndex(host, "@"); at != -1 {
		creds := host[:at]
		host = host[at+1:]
		if colon := strings.Index(creds, ":"); colon != -1 {
			redisPass = creds[colon+1:]
		}
	}
	if slash := strings.Index(host, "/"); slash != -1 {
		host = host[:slash]
	}
	if !strings.Contains(host, ":") {
		host += ":6379"
	}
	redisAddr = host

	// Probe connection
	conn, err := net.DialTimeout("tcp", redisAddr, 3*time.Second)
	if err != nil {
		log.Printf("⚠️  Redis unavailable (%s) — using in-memory rate limiting: %v", redisAddr, err)
		return
	}
	if redisPass != "" {
		if err := redisAuth(conn); err != nil {
			conn.Close()
			log.Printf("⚠️  Redis AUTH failed — using in-memory rate limiting: %v", err)
			return
		}
	}
	redisPool.put(conn)

	redisEnabled = true
	log.Printf("🔴 Redis rate limiting enabled (%s)", redisAddr)
}

func redisAuth(conn net.Conn) error {
	conn.SetDeadline(time.Now().Add(3 * time.Second)) //nolint:errcheck
	resp := respCmd("AUTH", redisPass)
	if _, err := conn.Write([]byte(resp)); err != nil {
		return err
	}
	_, err := readRESP(bufio.NewReader(conn))
	return err
}

// ─── RESP command builder ─────────────────────────────────────────────────────

func respCmd(args ...string) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "*%d\r\n", len(args))
	for _, a := range args {
		fmt.Fprintf(&sb, "$%d\r\n%s\r\n", len(a), a)
	}
	return sb.String()
}

// ─── RESP reader ─────────────────────────────────────────────────────────────

func readRESP(r *bufio.Reader) (interface{}, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
	if len(line) == 0 {
		return nil, fmt.Errorf("empty RESP line")
	}
	switch line[0] {
	case '+':
		return line[1:], nil
	case '-':
		return nil, fmt.Errorf("redis: %s", line[1:])
	case ':':
		return strconv.ParseInt(line[1:], 10, 64)
	case '$':
		n, err := strconv.Atoi(line[1:])
		if err != nil {
			return nil, err
		}
		if n == -1 {
			return nil, nil
		}
		buf := make([]byte, n+2) // +2 for \r\n
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		return string(buf[:n]), nil
	case '*':
		count, err := strconv.Atoi(line[1:])
		if err != nil {
			return nil, err
		}
		arr := make([]interface{}, count)
		for i := range arr {
			arr[i], err = readRESP(r)
			if err != nil {
				return nil, err
			}
		}
		return arr, nil
	default:
		return nil, fmt.Errorf("unknown RESP type %q", line[0])
	}
}

// ─── Command execution ────────────────────────────────────────────────────────

func redisCmd(args ...string) (interface{}, error) {
	conn, err := redisPool.get()
	if err != nil {
		return nil, fmt.Errorf("redis pool: %w", err)
	}

	conn.SetDeadline(time.Now().Add(3 * time.Second)) //nolint:errcheck
	if _, err := conn.Write([]byte(respCmd(args...))); err != nil {
		conn.Close()
		return nil, fmt.Errorf("redis write: %w", err)
	}

	result, err := readRESP(bufio.NewReader(conn))
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("redis read: %w", err)
	}

	conn.SetDeadline(time.Time{}) //nolint:errcheck
	redisPool.put(conn)
	return result, nil
}

// ─── Rate limiting ────────────────────────────────────────────────────────────

// checkRateLimitRedis uses a minute-bucket counter in Redis.
// Key format: rl:{sessionKey}:{unix_minute}
// Falls back to true (allow) if Redis errors — prefer availability over strictness.
func checkRateLimitRedis(sessionKey string, rpm int) bool {
	minute := time.Now().Unix() / 60
	key := fmt.Sprintf("rl:%s:%d", sessionKey, minute)

	result, err := redisCmd("INCR", key)
	if err != nil {
		log.Printf("⚠️  Redis rate-limit INCR failed (fail-open): %v", err)
		return true
	}

	count, ok := result.(int64)
	if !ok {
		return true
	}

	if count == 1 {
		// First hit this minute — set TTL (2 min window covers clock drift)
		if _, err := redisCmd("EXPIRE", key, "120"); err != nil {
			log.Printf("⚠️  Redis EXPIRE failed: %v", err)
		}
	}

	return count <= int64(rpm)
}
