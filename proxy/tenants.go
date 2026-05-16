package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"gopkg.in/yaml.v3"
)

// generateToken produces a cryptographically random hex token.
func generateToken() string {
	b := make([]byte, 24)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// ──────────────────────────────────────────────
// Tenant types
// ──────────────────────────────────────────────

// TenantMeta is the on-disk format for tenants/<id>/tenant.yaml.
type TenantMeta struct {
	ID         string `yaml:"id"`
	Name       string `yaml:"name"`
	AdminToken string `yaml:"admin_token"`
	UserToken  string `yaml:"user_token"`
	CreatedAt  string `yaml:"created_at"`
}

// Tenant holds all isolated runtime state for one tenant.
// The zero value is NOT valid — use newTenant() or loadTenant().
type Tenant struct {
	Meta      TenantMeta
	IsDefault bool // true for the backward-compat default tenant

	// Policy (hot-reloadable per tenant)
	policyMu          sync.RWMutex
	policy            Config
	secretRegexes     []*regexp.Regexp
	piiRegexes        []*regexp.Regexp
	maliciousRegexes  []*regexp.Regexp
	internalIPRegexes []*regexp.Regexp
	canaryRegexes     []*regexp.Regexp
	canaryToken       string // per-tenant GoalLock anchor

	// Session state (intent scoring, anomaly, zero-trust, blast radius)
	sessions     map[string]*SessionState
	sessLock     sync.RWMutex

	// Rate limiting
	rateLimiters map[string]*RateLimiter
	rateLock     sync.RWMutex

	// Active WebSocket connections
	wsConns     map[string]*websocket.Conn
	wsConnsLock sync.Mutex

	// Tool approvals (zero-trust)
	approvals     map[string]*ToolApprovalRequest
	approvalsLock sync.RWMutex
	approvalsSeq  int

	// In-memory alerts
	alerts     []Alert
	alertsLock sync.Mutex
	alertsSeq  int

	// Auto-repave counter
	repaveEvents     []repaveEvent
	repaveEventLock  sync.Mutex
	repaveFired      bool
	repaveFiredAt    time.Time
}

func newTenant(meta TenantMeta) *Tenant {
	return &Tenant{
		Meta:         meta,
		canaryToken:  generateCanary(),
		sessions:     make(map[string]*SessionState),
		rateLimiters: make(map[string]*RateLimiter),
		wsConns:      make(map[string]*websocket.Conn),
		approvals:    make(map[string]*ToolApprovalRequest),
	}
}

// ── Policy accessors ──

func (t *Tenant) getPolicy() Config {
	if t.IsDefault {
		policyLock.RLock()
		defer policyLock.RUnlock()
		return policy
	}
	t.policyMu.RLock()
	defer t.policyMu.RUnlock()
	return t.policy
}

func (t *Tenant) secretRx() []*regexp.Regexp {
	if t.IsDefault {
		policyLock.RLock()
		defer policyLock.RUnlock()
		return compiledSecretRegexes
	}
	t.policyMu.RLock()
	defer t.policyMu.RUnlock()
	return t.secretRegexes
}
func (t *Tenant) piiRx() []*regexp.Regexp {
	if t.IsDefault {
		policyLock.RLock()
		defer policyLock.RUnlock()
		return compiledPIIRegexes
	}
	t.policyMu.RLock()
	defer t.policyMu.RUnlock()
	return t.piiRegexes
}
func (t *Tenant) maliciousRx() []*regexp.Regexp {
	if t.IsDefault {
		policyLock.RLock()
		defer policyLock.RUnlock()
		return compiledMaliciousRegexes
	}
	t.policyMu.RLock()
	defer t.policyMu.RUnlock()
	return t.maliciousRegexes
}
func (t *Tenant) internalIPRx() []*regexp.Regexp {
	if t.IsDefault {
		policyLock.RLock()
		defer policyLock.RUnlock()
		return compiledInternalIPRegexes
	}
	t.policyMu.RLock()
	defer t.policyMu.RUnlock()
	return t.internalIPRegexes
}
func (t *Tenant) canaryRx() []*regexp.Regexp {
	if t.IsDefault {
		policyLock.RLock()
		defer policyLock.RUnlock()
		return compiledCanaryRegexes
	}
	t.policyMu.RLock()
	defer t.policyMu.RUnlock()
	return t.canaryRegexes
}
func (t *Tenant) getCanary() string {
	if t.IsDefault {
		return runtimeCanary
	}
	t.policyMu.RLock()
	defer t.policyMu.RUnlock()
	return t.canaryToken
}

// ── Auth ──

func (t *Tenant) getRole(r *http.Request) string {
	// OIDC session (shared across tenants)
	if oidcEnabled {
		if sess := getSessionFromRequest(r); sess != nil {
			return sess.Role
		}
	}
	token := ""
	if h := r.Header.Get("Authorization"); len(h) > 7 && h[:7] == "Bearer " {
		token = h[7:]
	}
	if t.IsDefault {
		if token == adminToken {
			return "admin"
		}
		if token == userToken {
			return "user"
		}
		return "none"
	}
	if token == t.Meta.AdminToken {
		return "admin"
	}
	if token == t.Meta.UserToken {
		return "user"
	}
	return "none"
}

// ── Per-tenant alert helpers ──

func (t *Tenant) addAlert(alertType, message string) {
	if t.IsDefault {
		addAlert(alertType, message) // global
		return
	}
	t.alertsLock.Lock()
	defer t.alertsLock.Unlock()
	t.alertsSeq++
	t.alerts = append([]Alert{{
		ID:        t.alertsSeq,
		Timestamp: time.Now().Format(time.RFC3339),
		Type:      alertType,
		Message:   message,
	}}, t.alerts...)
	if len(t.alerts) > 50 {
		t.alerts = t.alerts[:50]
	}
	log.Printf("🚨 [%s] ALERT [%s]: %s", t.Meta.ID, alertType, message)
}

// ── Per-tenant session helpers ──

func (t *Tenant) sessGet(key string) (*SessionState, bool) {
	if t.IsDefault {
		sessionHistoryLock.RLock()
		s, ok := sessionHistory[key]
		sessionHistoryLock.RUnlock()
		return s, ok
	}
	t.sessLock.RLock()
	s, ok := t.sessions[key]
	t.sessLock.RUnlock()
	return s, ok
}
func (t *Tenant) sessSet(key string, s *SessionState) {
	if t.IsDefault {
		sessionHistoryLock.Lock()
		sessionHistory[key] = s
		sessionHistoryLock.Unlock()
		return
	}
	t.sessLock.Lock()
	t.sessions[key] = s
	t.sessLock.Unlock()
}
func (t *Tenant) sessDel(key string) {
	if t.IsDefault {
		sessionHistoryLock.Lock()
		delete(sessionHistory, key)
		sessionHistoryLock.Unlock()
		return
	}
	t.sessLock.Lock()
	delete(t.sessions, key)
	t.sessLock.Unlock()
}
func (t *Tenant) sessLockW() {
	if t.IsDefault {
		sessionHistoryLock.Lock()
	} else {
		t.sessLock.Lock()
	}
}
func (t *Tenant) sessUnlockW() {
	if t.IsDefault {
		sessionHistoryLock.Unlock()
	} else {
		t.sessLock.Unlock()
	}
}
func (t *Tenant) sessLockR() {
	if t.IsDefault {
		sessionHistoryLock.RLock()
	} else {
		t.sessLock.RLock()
	}
}
func (t *Tenant) sessUnlockR() {
	if t.IsDefault {
		sessionHistoryLock.RUnlock()
	} else {
		t.sessLock.RUnlock()
	}
}
func (t *Tenant) sessMap() map[string]*SessionState {
	if t.IsDefault {
		return sessionHistory
	}
	return t.sessions
}

// ── Per-tenant WS connection registry ──

func (t *Tenant) registerWS(key string, conn *websocket.Conn) {
	if t.IsDefault {
		registerWSConn(key, conn)
		return
	}
	t.wsConnsLock.Lock()
	t.wsConns[key] = conn
	t.wsConnsLock.Unlock()
}
func (t *Tenant) deregisterWS(key string) {
	if t.IsDefault {
		deregisterWSConn(key)
		return
	}
	t.wsConnsLock.Lock()
	delete(t.wsConns, key)
	t.wsConnsLock.Unlock()
}
func (t *Tenant) killAllWS() int {
	if t.IsDefault {
		return killAllSessions()
	}
	t.wsConnsLock.Lock()
	count := len(t.wsConns)
	for key, conn := range t.wsConns {
		conn.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseGoingAway, "Session terminated by admin"))
		conn.Close()
		delete(t.wsConns, key)
	}
	t.wsConnsLock.Unlock()
	t.sessLock.Lock()
	t.sessions = make(map[string]*SessionState)
	t.sessLock.Unlock()
	log.Printf("🛑 [%s] Kill switch: terminated %d session(s)", t.Meta.ID, count)
	return count
}
func (t *Tenant) killOneWS(key string) {
	if t.IsDefault {
		killSession(key)
		return
	}
	t.wsConnsLock.Lock()
	if conn, ok := t.wsConns[key]; ok {
		conn.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseGoingAway, "Blast radius exceeded"))
		conn.Close()
		delete(t.wsConns, key)
	}
	t.wsConnsLock.Unlock()
	t.sessLock.Lock()
	delete(t.sessions, key)
	t.sessLock.Unlock()
}

// ── Rate limiting ──

func (t *Tenant) checkRL(key string) bool {
	if t.IsDefault {
		return checkRateLimit(key)
	}
	policyLock.RLock()
	cfg := t.policy.Scanners.RateLimiting
	policyLock.RUnlock()
	if !cfg.Enabled {
		return true
	}
	t.rateLock.RLock()
	limiter, exists := t.rateLimiters[key]
	t.rateLock.RUnlock()
	if !exists {
		t.rateLock.Lock()
		if l, ok := t.rateLimiters[key]; ok {
			limiter = l
		} else {
			burst := cfg.Burst
			if burst <= 0 {
				burst = cfg.RequestsPerMinute * 2
			}
			limiter = NewRateLimiter(cfg.RequestsPerMinute, burst)
			t.rateLimiters[key] = limiter
		}
		t.rateLock.Unlock()
	}
	return limiter.Allow()
}

// ── Tool approvals ──

func (t *Tenant) requestApproval(sessionKey, tool string) string {
	if t.IsDefault {
		return requestToolApproval(sessionKey, tool)
	}
	t.approvalsLock.Lock()
	defer t.approvalsLock.Unlock()
	for id, req := range t.approvals {
		if req.SessionKey == sessionKey && req.Tool == tool && req.Status == "pending" {
			return id
		}
	}
	display := sessionKey
	if len(display) > 16 {
		display = display[:16] + "…"
	}
	t.approvalsSeq++
	id := fmt.Sprintf("%x", time.Now().UnixNano())[:12]
	t.approvals[id] = &ToolApprovalRequest{
		ID:          id,
		SessionKey:  sessionKey,
		DisplayKey:  display,
		Tool:        tool,
		RequestedAt: time.Now().Format(time.RFC3339),
		Status:      "pending",
	}
	go t.addAlert("TOOL_APPROVAL_REQUIRED",
		fmt.Sprintf("[%s] Session %s requests approval for '%s'", t.Meta.ID, display, tool))
	return id
}

// ──────────────────────────────────────────────
// Tenant registry
// ──────────────────────────────────────────────

var (
	tenantRegistry     = make(map[string]*Tenant) // id → tenant
	tenantTokenIndex   = make(map[string]string)  // token → tenantID
	tenantRegistryLock sync.RWMutex
	defaultTenant      *Tenant
	multiTenancyActive bool
)

// InitTenants loads tenant configs from ./tenants/ directory.
// If the directory does not exist, single-tenant mode is used.
func InitTenants() {
	// Create the default tenant backed by global state.
	defaultTenant = &Tenant{
		IsDefault:    true,
		sessions:     sessionHistory,
		rateLimiters: rateLimiters,
		wsConns:      activeWSConns,
		approvals:    toolApprovals,
	}
	defaultTenant.Meta = TenantMeta{ID: "default", Name: "Default"}

	if _, err := os.Stat("./tenants"); os.IsNotExist(err) {
		return // single-tenant mode
	}

	entries, err := os.ReadDir("./tenants")
	if err != nil {
		log.Printf("⚠️  Could not read tenants directory: %v", err)
		return
	}

	loaded := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if tnt, err := loadTenant(filepath.Join("./tenants", e.Name())); err == nil {
			tenantRegistryLock.Lock()
			tenantRegistry[tnt.Meta.ID] = tnt
			if tnt.Meta.AdminToken != "" {
				tenantTokenIndex[tnt.Meta.AdminToken] = tnt.Meta.ID
			}
			if tnt.Meta.UserToken != "" {
				tenantTokenIndex[tnt.Meta.UserToken] = tnt.Meta.ID
			}
			tenantRegistryLock.Unlock()
			loaded++
		} else {
			log.Printf("⚠️  Could not load tenant %s: %v", e.Name(), err)
		}
	}
	if loaded > 0 {
		multiTenancyActive = true
		log.Printf("✅ Multi-tenancy active: %d tenant(s) loaded", loaded)
	}
}

func loadTenant(dir string) (*Tenant, error) {
	metaData, err := os.ReadFile(filepath.Join(dir, "tenant.yaml"))
	if err != nil {
		return nil, fmt.Errorf("missing tenant.yaml: %w", err)
	}
	var meta TenantMeta
	if err := yaml.Unmarshal(metaData, &meta); err != nil {
		return nil, fmt.Errorf("bad tenant.yaml: %w", err)
	}
	if meta.ID == "" {
		meta.ID = filepath.Base(dir)
	}
	tnt := newTenant(meta)

	// Load tenant's own policy
	polData, err := os.ReadFile(filepath.Join(dir, "policy.yaml"))
	if err != nil {
		// Copy root policy as starting point
		polData, _ = os.ReadFile("policy.yaml")
	}
	if len(polData) > 0 {
		if err := tnt.loadPolicyBytes(polData); err != nil {
			log.Printf("⚠️  [%s] Policy load error: %v", meta.ID, err)
		}
	}
	return tnt, nil
}

func (t *Tenant) loadPolicyBytes(data []byte) error {
	var pol Config
	if err := yaml.Unmarshal(data, &pol); err != nil {
		return err
	}
	cr := compileRegexSet(pol)
	t.policyMu.Lock()
	t.policy = pol
	t.secretRegexes = cr.secret
	t.piiRegexes = cr.pii
	t.maliciousRegexes = cr.malicious
	t.internalIPRegexes = cr.internalIP
	t.canaryRegexes = cr.canary
	t.policyMu.Unlock()
	return nil
}

// compileRegexSet compiles all regex patterns from a Config.
type compiledRegexSet struct {
	secret, pii, malicious, internalIP, canary []*regexp.Regexp
}

func compileRegexSet(pol Config) compiledRegexSet {
	compile := func(rule string) *regexp.Regexp {
		rx, err := regexp.Compile(rule)
		if err != nil {
			log.Printf("⚠️  Invalid regex '%s': %v — skipped", rule, err)
			return nil
		}
		return rx
	}
	var cr compiledRegexSet
	for _, r := range pol.Scanners.Secrets.RedactPatterns {
		if rx := compile(r.Rule); rx != nil {
			cr.secret = append(cr.secret, rx)
		}
	}
	for _, r := range pol.Scanners.PII.BlockPatterns {
		if rx := compile(r.Rule); rx != nil {
			cr.pii = append(cr.pii, rx)
		}
	}
	for _, r := range pol.Scanners.MaliciousContent.BlockPatterns {
		if rx := compile(r.Rule); rx != nil {
			cr.malicious = append(cr.malicious, rx)
		}
	}
	for _, r := range pol.Scanners.InternalIPProtection.BlockPatterns {
		if rx := compile(r.Rule); rx != nil {
			cr.internalIP = append(cr.internalIP, rx)
		}
	}
	for _, r := range pol.Scanners.CanaryTokens.Tokens {
		if rx := compile("(?i)" + regexp.QuoteMeta(r.Rule)); rx != nil {
			cr.canary = append(cr.canary, rx)
		}
	}
	return cr
}

// ──────────────────────────────────────────────
// Tenant resolution
// ──────────────────────────────────────────────

func resolveTenant(r *http.Request) *Tenant {
	if !multiTenancyActive {
		return defaultTenant
	}
	// 1. Explicit header
	if id := r.Header.Get("X-Tenant-ID"); id != "" {
		tenantRegistryLock.RLock()
		tnt, ok := tenantRegistry[id]
		tenantRegistryLock.RUnlock()
		if ok {
			return tnt
		}
	}
	// 2. Token-based lookup
	if h := r.Header.Get("Authorization"); len(h) > 7 {
		token := h[7:]
		tenantRegistryLock.RLock()
		id, ok := tenantTokenIndex[token]
		tenantRegistryLock.RUnlock()
		if ok {
			tenantRegistryLock.RLock()
			tnt := tenantRegistry[id]
			tenantRegistryLock.RUnlock()
			if tnt != nil {
				return tnt
			}
		}
	}
	return defaultTenant
}

// ──────────────────────────────────────────────
// Tenant CRUD helpers (used by API handlers)
// ──────────────────────────────────────────────

type TenantSummary struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	AdminToken string `json:"admin_token,omitempty"`
	UserToken  string `json:"user_token,omitempty"`
	CreatedAt  string `json:"created_at"`
}

func ListTenants() []TenantSummary {
	tenantRegistryLock.RLock()
	defer tenantRegistryLock.RUnlock()
	var out []TenantSummary
	for _, t := range tenantRegistry {
		out = append(out, TenantSummary{
			ID:        t.Meta.ID,
			Name:      t.Meta.Name,
			CreatedAt: t.Meta.CreatedAt,
			// Never return tokens in list view
		})
	}
	return out
}

func CreateTenant(meta TenantMeta) (*Tenant, error) {
	if meta.ID == "" {
		return nil, fmt.Errorf("tenant ID is required")
	}
	tenantRegistryLock.RLock()
	_, exists := tenantRegistry[meta.ID]
	tenantRegistryLock.RUnlock()
	if exists {
		return nil, fmt.Errorf("tenant %q already exists", meta.ID)
	}
	if meta.CreatedAt == "" {
		meta.CreatedAt = time.Now().Format(time.RFC3339)
	}
	dir := filepath.Join("./tenants", meta.ID)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}
	data, _ := yaml.Marshal(meta)
	if err := os.WriteFile(filepath.Join(dir, "tenant.yaml"), data, 0600); err != nil {
		return nil, err
	}
	// Seed with root policy
	if root, err := os.ReadFile("policy.yaml"); err == nil {
		os.WriteFile(filepath.Join(dir, "policy.yaml"), root, 0644)
	}
	tnt := newTenant(meta)
	if pdata, err := os.ReadFile(filepath.Join(dir, "policy.yaml")); err == nil {
		tnt.loadPolicyBytes(pdata)
	}
	tenantRegistryLock.Lock()
	tenantRegistry[meta.ID] = tnt
	if meta.AdminToken != "" {
		tenantTokenIndex[meta.AdminToken] = meta.ID
	}
	if meta.UserToken != "" {
		tenantTokenIndex[meta.UserToken] = meta.ID
	}
	tenantRegistryLock.Unlock()
	if !multiTenancyActive {
		multiTenancyActive = true
		log.Printf("✅ Multi-tenancy activated")
	}
	log.Printf("✅ Tenant created: %s (%s)", meta.ID, meta.Name)
	return tnt, nil
}

func DeleteTenant(id string) error {
	tenantRegistryLock.Lock()
	tnt, ok := tenantRegistry[id]
	if !ok {
		tenantRegistryLock.Unlock()
		return fmt.Errorf("tenant %q not found", id)
	}
	delete(tenantRegistry, id)
	delete(tenantTokenIndex, tnt.Meta.AdminToken)
	delete(tenantTokenIndex, tnt.Meta.UserToken)
	tenantRegistryLock.Unlock()
	// Kill all tenant sessions
	tnt.killAllWS()
	// Remove directory
	os.RemoveAll(filepath.Join("./tenants", id))
	log.Printf("🗑  Tenant deleted: %s", id)
	return nil
}

func SaveTenantPolicy(id string, data []byte) error {
	tenantRegistryLock.RLock()
	tnt, ok := tenantRegistry[id]
	tenantRegistryLock.RUnlock()
	if !ok {
		return fmt.Errorf("tenant %q not found", id)
	}
	if err := tnt.loadPolicyBytes(data); err != nil {
		return err
	}
	path := filepath.Join("./tenants", id, "policy.yaml")
	return os.WriteFile(path, data, 0644)
}

func GetTenantPolicy(id string) ([]byte, error) {
	path := filepath.Join("./tenants", id, "policy.yaml")
	return os.ReadFile(path)
}
