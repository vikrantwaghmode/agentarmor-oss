package main

import (
	"fmt"
	"log"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
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
	title  string
	body   string
	tokens map[string]int // precomputed token frequencies
}

type LoadedSkill struct {
	Config SkillConfig
	Docs   []knowledgeDoc
}

var (
	loadedSkills   = make(map[string]*LoadedSkill)
	skillsBasePath = "./skills"
	skillsMu       sync.RWMutex
)

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
	if best.score >= 2 { // require at least 2 keyword hits to avoid false positives
		return best.id
	}
	return ""
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

	chunks := retrieveTopK(skill.Docs, query, 3)
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

// ListSkills returns a summary of all loaded skills (for dashboard/API use).
func ListSkills() []map[string]string {
	skillsMu.RLock()
	defer skillsMu.RUnlock()
	var out []map[string]string
	for _, s := range loadedSkills {
		out = append(out, map[string]string{
			"id":          s.Config.ID,
			"name":        s.Config.Name,
			"description": s.Config.Description,
			"docs":        fmt.Sprintf("%d", len(s.Docs)),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i]["id"] < out[j]["id"] })
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
