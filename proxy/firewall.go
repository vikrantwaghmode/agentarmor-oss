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
	// This helper does not ignore errors, unlike run().
	return exec.Command(cmd, args...).Run()
}

func main() {
	log.Println("🧱 AgentArmor Layer 2: Initializing Network Kill Switch...")

	data, err := os.ReadFile("firewall.yaml")
	if err != nil {
		log.Fatal("Error reading firewall.yaml:", err)
	}

	var config FirewallConfig
	yaml.Unmarshal(data, &config)

	// 1. Ensure our custom chain exists, creating it if it doesn't.
	run("iptables", "-N", "AI_EGRESS")

	// 2. Ensure we jump to it from the OUTPUT chain, but only add the rule once.
	if err := runCheck("iptables", "-C", "OUTPUT", "-j", "AI_EGRESS"); err != nil {
		run("iptables", "-A", "OUTPUT", "-j", "AI_EGRESS")
	}

	// 3. Flush any existing rules from our chain to ensure a clean slate.
	run("iptables", "-F", "AI_EGRESS")
	run("iptables", "-A", "AI_EGRESS", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT") // Must be first rule

	// 2. Allow ALL Loopback & Docker Embedded DNS
	// Docker DNS (127.0.0.11) uses DNAT to map port 53 to random high ports internally.
	// We must whitelist the entire 127.x.x.x block to catch those rerouted packets.
	run("iptables", "-A", "AI_EGRESS", "-d", "127.0.0.0/8", "-j", "ACCEPT")

	// ALLOW: Outbound DNS requests (so OpenClaw can resolve googleapis.com)
	// We allow port 53 globally here because DNS lookups are required for the API to function.
	run("iptables", "-A", "AI_EGRESS", "-p", "udp", "--dport", "53", "-j", "ACCEPT")
	run("iptables", "-A", "AI_EGRESS", "-p", "tcp", "--dport", "53", "-j", "ACCEPT")

	// 3. ALLOW: Docker Internal Networks for Sidecars
	// Ensures Ollama and Presidio are always reachable regardless of container startup order
	// (Layer 7 proxy still actively blocks SSRF to these subnets from user input)
	run("iptables", "-A", "AI_EGRESS", "-d", "172.16.0.0/12", "-j", "ACCEPT")
	run("iptables", "-A", "AI_EGRESS", "-d", "192.168.0.0/16", "-j", "ACCEPT")

	// 4. Resolve and Allow external domains from firewall.yaml
	for _, domain := range config.AllowedDomains {
		ips, err := net.LookupIP(domain)
		if err != nil {
			log.Printf("⚠️ Could not resolve %s", domain)
			continue
		}

		for _, ip := range ips {
			if ip.To4() != nil { // IPv4 only
				run("iptables", "-A", "AI_EGRESS", "-d", ip.String(), "-j", "ACCEPT")
				log.Printf("✅ Firewall: Allowed %s (%s)", domain, ip.String())
			}
		}
	}

	// 5. THE KILL SWITCH (Block everything else)
	run("iptables", "-A", "AI_EGRESS", "-j", "DROP")

	log.Println("🧱 Firewall Locked: All unauthorized outbound traffic will be dropped.")
}
