package main

// Audit log export — streams audit_logs rows as CSV or NDJSON for compliance reporting.
//
// GET /armor/api/audit/export
//   ?format=csv|ndjson      (default: csv)
//   &limit=N                (default: 10000, max: 100000)
//   &from=RFC3339           (e.g. 2026-01-01T00:00:00Z)
//   &to=RFC3339
//   &action=BLOCKED|REDACTED|ALLOWED
//   &tenant=<id>            (filter by tenant, default: all)
//
// Admin only. Returns Content-Disposition: attachment so browsers download directly.

import (
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type auditEntry struct {
	ID             int    `json:"id"`
	Timestamp      string `json:"timestamp"`
	ClientIP       string `json:"client_ip"`
	SessionKey     string `json:"session_key"`
	Direction      string `json:"direction"`
	Action         string `json:"action"`
	RuleMatched    string `json:"rule_matched"`
	PayloadSnippet string `json:"payload_snippet"`
	TenantID       string `json:"tenant_id"`
}

func handleAuditExport(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	format := q.Get("format")
	if format == "" {
		format = "csv"
	}
	if format != "csv" && format != "ndjson" {
		http.Error(w, `{"error":"format must be csv or ndjson"}`, http.StatusBadRequest)
		return
	}

	limit := 10000
	if l, err := strconv.Atoi(q.Get("limit")); err == nil && l > 0 {
		if l > 100000 {
			l = 100000
		}
		limit = l
	}

	from := q.Get("from")
	to := q.Get("to")
	action := strings.ToUpper(q.Get("action"))
	tenant := q.Get("tenant")

	// Build parameterised query
	where := []string{}
	args := []interface{}{}
	i := 1

	if from != "" {
		where = append(where, "timestamp >= "+ph(i))
		args = append(args, from)
		i++
	}
	if to != "" {
		where = append(where, "timestamp <= "+ph(i))
		args = append(args, to)
		i++
	}
	if action != "" {
		where = append(where, "action = "+ph(i))
		args = append(args, action)
		i++
	}
	if tenant != "" {
		where = append(where, "tenant_id = "+ph(i))
		args = append(args, tenant)
		i++
	}

	query := `SELECT id, timestamp, COALESCE(client_ip,''), COALESCE(session_key,''),
		direction, action, COALESCE(rule_matched,''), COALESCE(payload_snippet,''),
		COALESCE(tenant_id,'default')
		FROM audit_logs`
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY id DESC LIMIT " + ph(i)
	args = append(args, limit)

	rows, err := db.Query(query, args...)
	if err != nil {
		http.Error(w, `{"error":"query failed: `+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	ts := time.Now().UTC().Format("2006-01-02T150405Z")
	filename := fmt.Sprintf("agentarmor-audit-%s.%s", ts, format)

	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.Header().Set("Cache-Control", "no-store")

	if format == "csv" {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		writeCSVExport(w, rows)
	} else {
		w.Header().Set("Content-Type", "application/x-ndjson")
		writeNDJSONExport(w, rows)
	}
}

func writeCSVExport(w http.ResponseWriter, rows *sql.Rows) {
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{
		"id", "timestamp", "client_ip", "session_key",
		"direction", "action", "rule_matched", "payload_snippet", "tenant_id",
	})
	for rows.Next() {
		var e auditEntry
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.ClientIP, &e.SessionKey,
			&e.Direction, &e.Action, &e.RuleMatched, &e.PayloadSnippet, &e.TenantID); err != nil {
			continue
		}
		_ = cw.Write([]string{
			strconv.Itoa(e.ID), e.Timestamp, e.ClientIP, e.SessionKey,
			e.Direction, e.Action, e.RuleMatched, e.PayloadSnippet, e.TenantID,
		})
	}
	cw.Flush()
}

func writeNDJSONExport(w http.ResponseWriter, rows *sql.Rows) {
	enc := json.NewEncoder(w)
	for rows.Next() {
		var e auditEntry
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.ClientIP, &e.SessionKey,
			&e.Direction, &e.Action, &e.RuleMatched, &e.PayloadSnippet, &e.TenantID); err != nil {
			continue
		}
		_ = enc.Encode(e) // writes JSON + newline
	}
}
