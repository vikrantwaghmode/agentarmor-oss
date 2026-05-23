package main

import (
	"log"
	"net"
	"os"
	"os/exec"

	"gopkg.in/yaml.v3"
)

type FirewallConfig struct {
	AllowedDomains []string `yaml:"allowed_domains"`
}

// Helper to run shell commands easily
func run(cmd string, args ...string) {
	err := exec.Command(cmd, args...).Run()
	if err != nil {
		log.Printf("⚠️ Firewall Warning: '%s %v' failed (may already exist)", cmd, args)
	}
}

func runCheck(cmd string, args ...string) error {
	return exec.Command(cmd, args...).Run()
}

func main() {
	log.Println("🧱 AgentArmor Layer 2: Initializing Network Kill Switch...")

	data, err := os.ReadFile("firewall.yaml")
	if err != nil {
		log.Fatal("Error reading firewall.yaml:", err)
	}

	var config FirewallConfig
	yaml.Unmarshal(data, &config) //nolint:errcheck

	// 1. Ensure our custom chain exists, creating it if it doesn't.
	run("iptables", "-N", "AI_EGRESS")

	// 2. Ensure we jump to it from the OUTPUT chain, but only add the rule once.
	if err := runCheck("iptables", "-C", "OUTPUT", "-j", "AI_EGRESS"); err != nil {
		run("iptables", "-A", "OUTPUT", "-j", "AI_EGRESS")
	}

	// 3. Flush any existing rules from our chain to ensure a clean slate.
	run("iptables", "-F", "AI_EGRESS")
	run("iptables", "-A", "AI_EGRESS", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT")

	// Allow loopback & Docker embedded DNS
	run("iptables", "-A", "AI_EGRESS", "-d", "127.0.0.0/8", "-j", "ACCEPT")

	// Allow outbound DNS
	run("iptables", "-A", "AI_EGRESS", "-p", "udp", "--dport", "53", "-j", "ACCEPT")
	run("iptables", "-A", "AI_EGRESS", "-p", "tcp", "--dport", "53", "-j", "ACCEPT")

	// Allow Docker internal networks for sidecars (Ollama, Presidio)
	run("iptables", "-A", "AI_EGRESS", "-d", "172.16.0.0/12", "-j", "ACCEPT")
	run("iptables", "-A", "AI_EGRESS", "-d", "192.168.0.0/16", "-j", "ACCEPT")

	// Resolve and allow external domains from firewall.yaml
	for _, domain := range config.AllowedDomains {
		ips, err := net.LookupIP(domain)
		if err != nil {
			log.Printf("⚠️ Could not resolve %s", domain)
			continue
		}
		for _, ip := range ips {
			if ip.To4() != nil {
				run("iptables", "-A", "AI_EGRESS", "-d", ip.String(), "-j", "ACCEPT")
				log.Printf("✅ Firewall: Allowed %s (%s)", domain, ip.String())
			}
		}
	}

	// Kill switch — block everything else
	run("iptables", "-A", "AI_EGRESS", "-j", "DROP")

	log.Println("🧱 Firewall Locked: All unauthorized outbound traffic will be dropped.")
}
