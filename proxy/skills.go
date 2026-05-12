package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"gopkg.in/yaml.v3"
)

// ──────────────────────────────────────────────
// Skill Types
// ──────────────────────────────────────────────

type SkillConfig struct {
	ID           string   `yaml:"id"`
	Name         string   `yaml:"name"`
	Description  string   `yaml:"description"`
	SystemPrompt string   `yaml:"system_prompt"`
	Keywords     []string `yaml:"keywords"` // for auto-detection from content
}

type knowledgeDoc struct {
	title     string
	body      string
	tokens    map[string]int // precomputed for BM25 fallback
	embedding []float64      // semantic vector; nil until embedded
}

// embeddedDocCount tracks how many docs have been embedded (for dashboard status).
var embeddedDocCount atomic.Int64

type LoadedSkill struct {
	Config            SkillConfig
	Docs              []knowledgeDoc
	identityEmbedding []float64 // embedding of name+description+keywords for semantic routing
}

var (
	loadedSkills   = make(map[string]*LoadedSkill)
	skillsBasePath = "./skills"
	skillsMu       sync.RWMutex

	// Admin-activated skills — applied to all requests when no explicit
	// X-AgentArmor-Skill header or keyword match is present.
	adminActiveSkills   = make(map[string]bool)
	adminActiveSkillsMu sync.RWMutex
)

// ToggleSkill enables or disables a skill globally. Returns the new state.
func ToggleSkill(id string) (active bool, ok bool) {
	skillsMu.RLock()
	_, exists := loadedSkills[id]
	skillsMu.RUnlock()
	if !exists {
		return false, false
	}
	adminActiveSkillsMu.Lock()
	adminActiveSkills[id] = !adminActiveSkills[id]
	active = adminActiveSkills[id]
	adminActiveSkillsMu.Unlock()
	return active, true
}

// ActiveSkillIDs returns all admin-activated skill IDs in stable order.
func ActiveSkillIDs() []string {
	adminActiveSkillsMu.RLock()
	defer adminActiveSkillsMu.RUnlock()
	var ids []string
	for id, on := range adminActiveSkills {
		if on {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}

// BuildCombinedSkillContext merges system prompts and RAG from all
// admin-activated skills into a single context string.
func BuildCombinedSkillContext(query string) string {
	ids := ActiveSkillIDs()
	if len(ids) == 0 {
		return ""
	}
	var sb strings.Builder
	for i, id := range ids {
		ctx := BuildSkillContext(id, query)
		if ctx == "" {
			continue
		}
		if i > 0 {
			sb.WriteString("\n\n---\n\n")
		}
		sb.WriteString(ctx)
	}
	return sb.String()
}

// ──────────────────────────────────────────────
// Initialisation
// ──────────────────────────────────────────────

func initSkills() {
	entries, err := os.ReadDir(skillsBasePath)
	if err != nil {
		log.Printf("⚠️  Skills directory not found at %s — skills disabled", skillsBasePath)
		return
	}

	loaded := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if skill := loadSkill(filepath.Join(skillsBasePath, entry.Name())); skill != nil {
			skillsMu.Lock()
			loadedSkills[skill.Config.ID] = skill
			skillsMu.Unlock()
			log.Printf("🎓 Skill loaded: %s (%d knowledge docs)", skill.Config.Name, len(skill.Docs))
			loaded++
		}
	}
	log.Printf("✅ %d skill(s) ready", loaded)
}

// ──────────────────────────────────────────────
// Semantic RAG — Ollama Embeddings
// ──────────────────────────────────────────────

var embeddingInProgress atomic.Bool

// TriggerEmbeddingsIfNeeded starts the background Ollama embedding process
// if Semantic RAG is enabled and docs haven't been embedded yet.
func TriggerEmbeddingsIfNeeded(baseURL, model string) {
	if EmbeddedDocCount() > 0 || embeddingInProgress.Load() {
		return
	}
	embeddingInProgress.Store(true)
	go func() {
		defer embeddingInProgress.Store(false)
		embedAllDocs(baseURL, model)
	}()
}

// embedAllDocs runs in a background goroutine after skills load.
// Embeds every knowledge doc using Ollama; docs without embeddings
// automatically fall back to BM25 at query time.
func embedAllDocs(baseURL, model string) {
	skillsMu.Lock()
	// Collect all docs that need embedding
	type target struct {
		skill *LoadedSkill
		idx   int
	}
	var targets []target
	for _, skill := range loadedSkills {
		for i := range skill.Docs {
			targets = append(targets, target{skill, i})
		}
	}
	skillsMu.Unlock()

	// Also embed each skill's identity for semantic auto-routing.
	for _, skill := range loadedSkills {
		identityText := fmt.Sprintf("%s. %s. Topics: %s",
			skill.Config.Name,
			skill.Config.Description,
			strings.Join(skill.Config.Keywords, ", "))
		if emb, err := generateEmbedding(identityText, baseURL, model); err == nil {
			skillsMu.Lock()
			skill.identityEmbedding = emb
			skillsMu.Unlock()
		}
	}
	log.Printf("🔢 Semantic RAG: routing embeddings ready, embedding %d doc(s) with %s…", len(targets), model)

	for _, t := range targets {
		emb, err := generateEmbedding(t.skill.Docs[t.idx].body, baseURL, model)
		if err != nil {
			log.Printf("⚠️  Embedding failed (%s / %s): %v", t.skill.Config.ID, t.skill.Docs[t.idx].title, err)
			continue
		}
		skillsMu.Lock()
		t.skill.Docs[t.idx].embedding = emb
		skillsMu.Unlock()
		embeddedDocCount.Add(1)
	}
	log.Printf("✅ Semantic RAG: %d/%d document(s) embedded", embeddedDocCount.Load(), len(targets))
}

// generateEmbedding calls the Ollama /api/embeddings endpoint.
func generateEmbedding(text, baseURL, model string) ([]float64, error) {
	body, _ := json.Marshal(map[string]string{"model": model, "prompt": text})
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/api/embeddings", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("Ollama returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(bodyBytes)))
	}

	var result struct {
		Embedding []float64 `json:"embedding"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	if len(result.Embedding) == 0 {
		return nil, fmt.Errorf("empty embedding returned")
	}
	return result.Embedding, nil
}

// cosineSimilarity returns the cosine similarity between two vectors.
func cosineSimilarity(a, b []float64) float64 {
	if len(a) != len(b) || len(a) == 0 {
		return 0
	}
	var dot, normA, normB float64
	for i := range a {
		dot += a[i] * b[i]
		normA += a[i] * a[i]
		normB += b[i] * b[i]
	}
	if normA == 0 || normB == 0 {
		return 0
	}
	return dot / (math.Sqrt(normA) * math.Sqrt(normB))
}

// retrieveTopKSemantic finds the k most relevant docs by cosine similarity.
// Returns nil if no docs have embeddings yet (triggers BM25 fallback).
func retrieveTopKSemantic(docs []knowledgeDoc, queryEmb []float64, k int) []knowledgeDoc {
	if len(queryEmb) == 0 {
		return nil
	}
	type scored struct {
		doc   knowledgeDoc
		score float64
	}
	var results []scored
	for _, doc := range docs {
		if doc.embedding == nil {
			continue
		}
		results = append(results, scored{doc, cosineSimilarity(queryEmb, doc.embedding)})
	}
	if len(results) == 0 {
		return nil // no embeddings available yet
	}
	sort.Slice(results, func(i, j int) bool { return results[i].score > results[j].score })
	out := make([]knowledgeDoc, 0, k)
	for i := 0; i < k && i < len(results); i++ {
		out = append(out, results[i].doc)
	}
	return out
}

// detectSkillSemantic finds the best-matching skill for the query using cosine
// similarity against pre-computed skill identity embeddings. Returns "" if no
// skill exceeds the threshold or if embeddings are not yet ready.
func detectSkillSemantic(queryEmb []float64, threshold float64) string {
	if len(queryEmb) == 0 {
		return ""
	}
	skillsMu.RLock()
	defer skillsMu.RUnlock()

	best, bestScore := "", threshold
	for id, skill := range loadedSkills {
		if skill.identityEmbedding == nil {
			continue
		}
		if score := cosineSimilarity(queryEmb, skill.identityEmbedding); score > bestScore {
			bestScore = score
			best = id
		}
	}
	return best
}

// EmbeddedDocCount returns the number of embedded knowledge docs (for dashboard).
func EmbeddedDocCount() int64 { return embeddedDocCount.Load() }

func loadSkill(dir string) *LoadedSkill {
	cfgData, err := os.ReadFile(filepath.Join(dir, "skill.yaml"))
	if err != nil {
		return nil
	}

	var cfg SkillConfig
	if err := yaml.Unmarshal(cfgData, &cfg); err != nil {
		log.Printf("⚠️  Could not parse %s/skill.yaml: %v", dir, err)
		return nil
	}
	if cfg.ID == "" {
		cfg.ID = filepath.Base(dir)
	}

	skill := &LoadedSkill{Config: cfg}

	docEntries, _ := os.ReadDir(filepath.Join(dir, "knowledge"))
	for _, de := range docEntries {
		if de.IsDir() || !strings.HasSuffix(de.Name(), ".md") {
			continue
		}
		content, err := os.ReadFile(filepath.Join(dir, "knowledge", de.Name()))
		if err != nil {
			continue
		}
		title := strings.TrimSuffix(de.Name(), ".md")
		title = strings.ReplaceAll(title, "-", " ")
		skill.Docs = append(skill.Docs, knowledgeDoc{
			title:  title,
			body:   string(content),
			tokens: tokenise(string(content)),
		})
	}

	return skill
}

// ──────────────────────────────────────────────
// Skill Detection
// ──────────────────────────────────────────────

// armorSkillMarker is the tag embedded in OpenClaw SKILL.md files.
// When OpenClaw loads a skill, the marker appears in the conversation context,
// letting the proxy detect which skill is active without requiring a header.
const armorSkillMarkerPrefix = "[ARMOR-SKILL:"

// DetectSkill returns the skill ID from (in priority order):
//  1. The explicit X-AgentArmor-Skill header
//  2. The [ARMOR-SKILL:xxx] marker embedded in SKILL.md (injected by OpenClaw)
//  3. Keyword auto-detection from message content (≥2 hits required)
//
// Returns "" if no skill matches.
func DetectSkill(header, content string) string {
	skillsMu.RLock()
	defer skillsMu.RUnlock()

	// 1. Explicit header — highest priority.
	if header != "" {
		if _, ok := loadedSkills[header]; ok {
			return header
		}
	}

	// 2. ARMOR-SKILL marker injected by OpenClaw when a skill's SKILL.md is loaded.
	if idx := strings.Index(content, armorSkillMarkerPrefix); idx >= 0 {
		rest := content[idx+len(armorSkillMarkerPrefix):]
		if end := strings.Index(rest, "]"); end >= 0 {
			skillID := strings.TrimSpace(rest[:end])
			if _, ok := loadedSkills[skillID]; ok {
				return skillID
			}
		}
	}

	// 3. Keyword auto-detection — pick the skill with the most keyword hits.
	lower := strings.ToLower(content)
	type match struct {
		id    string
		score int
	}
	var best match
	for id, skill := range loadedSkills {
		score := 0
		for _, kw := range skill.Config.Keywords {
			if strings.Contains(lower, strings.ToLower(kw)) {
				score++
			}
		}
		if score > best.score {
			best = match{id, score}
		}
	}
	if best.score >= 1 {
		return best.id
	}

	// 4. Semantic auto-routing — embed the query and find the closest skill.
	// Only fires when semantic RAG is enabled and auto_route is true.
	policyLock.RLock()
	ragCfg := policy.SkillsRAG
	policyLock.RUnlock()

	if ragCfg.Enabled && ragCfg.AutoRoute && ragCfg.URL != "" && content != "" {
		threshold := ragCfg.AutoRouteThreshold
		if threshold == 0 {
			threshold = 0.70 // sensible default
		}
		if queryEmb, err := generateEmbedding(content, ragCfg.URL, ragCfg.Model); err == nil {
			if id := detectSkillSemantic(queryEmb, threshold); id != "" {
				log.Printf("🎓 Semantic auto-route → %s (threshold=%.2f)", id, threshold)
				return id
			}
		}
	}

	return ""
}

// ──────────────────────────────────────────────

// syncSkillsToOpenClaw writes each loaded skill into the two locations OpenClaw
// scans at startup:
//  1. codex-home/skills/<id>/ — the agent's skill context (used for RAG marker detection)
//  2. plugin-skills/<id>/     — OpenClaw's registered-skills registry (shown in the UI)
//
// Each skill directory must contain:
//   - SKILL.md               — description + [ARMOR-SKILL:id] marker
//   - agents/openai.yaml     — UI metadata (display_name, short_description, default_prompt)
//   - assets/icon-small.svg  — icon shown in the Skills tab
func syncSkillsToOpenClaw() {
	if _, err := os.Stat("/data/.openclaw"); os.IsNotExist(err) {
		return // not running in OpenClaw mode
	}

	codexBase := "/data/.openclaw/agents/main/agent/codex-home/skills"
	pluginBase := "/data/.openclaw/plugin-skills"
	os.MkdirAll(codexBase, 0755)
	os.MkdirAll(pluginBase, 0755)

	skillsMu.RLock()
	defer skillsMu.RUnlock()

	synced := 0
	for id, skill := range loadedSkills {
		for _, base := range []string{codexBase, pluginBase} {
			dir := filepath.Join(base, id)
			os.MkdirAll(filepath.Join(dir, "agents"), 0755)
			os.MkdirAll(filepath.Join(dir, "assets"), 0755)

			// SKILL.md — full system prompt + [ARMOR-SKILL:id] marker so the proxy
			// can detect which skill is active from the conversation context.
			skillMD := fmt.Sprintf("---\nname: \"%s\"\ndescription: \"%s\"\n---\n\n<!-- [ARMOR-SKILL:%s] -->\n\n# %s\n\n%s\n",
				id, skill.Config.Description, id, skill.Config.Name, skill.Config.SystemPrompt)
			os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte(skillMD), 0644)

			// agents/openai.yaml — controls what OpenClaw shows in the Skills / Agents tab
			agentYAML := fmt.Sprintf("interface:\n  display_name: %q\n  short_description: %q\n  default_prompt: \"Use $%s to help with this task.\"\n",
				skill.Config.Name, skill.Config.Description, id)
			os.WriteFile(filepath.Join(dir, "agents", "openai.yaml"), []byte(agentYAML), 0644)

			// assets/icon-small.svg — minimal coloured shield icon
			svg := fmt.Sprintf(
				`<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 16 16" fill="none">`+
					`<path fill="#a78bfa" d="M8 1L2 4v4c0 3.3 2.6 5.7 6 6.5C11.4 13.7 14 11.3 14 8V4L8 1z"/>`+
					`<text x="8" y="10.5" text-anchor="middle" font-size="7" fill="white" font-family="monospace">%s</text>`+
					`</svg>`, string([]rune(skill.Config.Name)[0:1]))
			os.WriteFile(filepath.Join(dir, "assets", "icon-small.svg"), []byte(svg), 0644)
		}
		synced++
	}
	log.Printf("🔄 Synced %d skill(s) to OpenClaw codex-home and plugin-skills", synced)
}

// ──────────────────────────────────────────────
// RAG Retrieval (TF-IDF)
// ──────────────────────────────────────────────

// BuildSkillContext returns the combined system prompt and top-K relevant
// knowledge chunks for the given skill and user query.
func BuildSkillContext(skillID, query string) string {
	skillsMu.RLock()
	skill, ok := loadedSkills[skillID]
	skillsMu.RUnlock()
	if !ok {
		return ""
	}

	var sb strings.Builder
	sb.WriteString(skill.Config.SystemPrompt)

	// Semantic retrieval — try first if enabled and embeddings are ready.
	var chunks []knowledgeDoc
	policyLock.RLock()
	ragCfg := policy.SkillsRAG
	policyLock.RUnlock()

	if ragCfg.Enabled && ragCfg.URL != "" && query != "" {
		if queryEmb, err := generateEmbedding(query, ragCfg.URL, ragCfg.Model); err == nil {
			chunks = retrieveTopKSemantic(skill.Docs, queryEmb, 3)
		}
	}

	// BM25 fallback — used when semantic is disabled, Ollama is down, or embeddings not yet ready.
	if len(chunks) == 0 {
		chunks = retrieveTopK(skill.Docs, query, 3)
	}

	if len(chunks) > 0 {
		sb.WriteString("\n\n---\nRelevant reference material:\n\n")
		for _, chunk := range chunks {
			body := chunk.body
			if len(body) > 600 {
				body = body[:600] + "…"
			}
			sb.WriteString(fmt.Sprintf("**%s**\n%s\n\n", chunk.title, body))
		}
	}

	return sb.String()
}

// ListSkills returns a summary of all loaded skills including their active state.
func ListSkills() []map[string]interface{} {
	skillsMu.RLock()
	defer skillsMu.RUnlock()
	adminActiveSkillsMu.RLock()
	defer adminActiveSkillsMu.RUnlock()
	var out []map[string]interface{}
	for _, s := range loadedSkills {
		embedded := 0
		for _, d := range s.Docs {
			if d.embedding != nil {
				embedded++
			}
		}
		out = append(out, map[string]interface{}{
			"id":            s.Config.ID,
			"name":          s.Config.Name,
			"description":   s.Config.Description,
			"docs":          len(s.Docs),
			"embedded_docs": embedded,
			"active":        adminActiveSkills[s.Config.ID],
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i]["id"].(string) < out[j]["id"].(string)
	})
	return out
}

// ──────────────────────────────────────────────
// BM25-style Scoring
// ──────────────────────────────────────────────

func retrieveTopK(docs []knowledgeDoc, query string, k int) []knowledgeDoc {
	if len(docs) == 0 {
		return nil
	}
	qt := tokenise(query)
	if len(qt) == 0 {
		return docs[:min(k, len(docs))]
	}

	N := float64(len(docs))
	type scored struct {
		doc   knowledgeDoc
		score float64
	}
	var results []scored

	for _, doc := range docs {
		score := 0.0
		for term := range qt {
			tf := float64(doc.tokens[term])
			if tf == 0 {
				continue
			}
			df := 0
			for _, d := range docs {
				if d.tokens[term] > 0 {
					df++
				}
			}
			idf := math.Log((N+1)/float64(df+1)) + 1
			score += math.Log(1+tf) * idf
		}
		if score > 0 {
			results = append(results, scored{doc, score})
		}
	}

	sort.Slice(results, func(i, j int) bool { return results[i].score > results[j].score })

	out := make([]knowledgeDoc, 0, k)
	for i := 0; i < k && i < len(results); i++ {
		out = append(out, results[i].doc)
	}
	return out
}

// ──────────────────────────────────────────────
// Tokeniser
// ──────────────────────────────────────────────

var stopWords = map[string]bool{
	"the": true, "and": true, "for": true, "are": true, "but": true,
	"not": true, "you": true, "all": true, "can": true, "had": true,
	"was": true, "one": true, "our": true, "out": true, "use": true,
	"how": true, "its": true, "they": true, "this": true, "with": true,
	"that": true, "from": true, "have": true, "will": true, "your": true,
	"what": true, "when": true, "each": true, "which": true, "been": true,
	"were": true, "more": true, "also": true, "into": true, "their": true,
	"than": true, "then": true, "some": true, "such": true, "only": true,
}

func tokenise(text string) map[string]int {
	counts := make(map[string]int)
	var word strings.Builder
	for _, r := range strings.ToLower(text) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			word.WriteRune(r)
		} else {
			if w := word.String(); len(w) > 2 && !stopWords[w] {
				counts[w]++
			}
			word.Reset()
		}
	}
	if w := word.String(); len(w) > 2 && !stopWords[w] {
		counts[w]++
	}
	return counts
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
