// ODisasm — Multi-Arch Disassembler
// Part of the OWL security suite.  Author: khaled.s.haddad   Site: owlsec.org
// Language: Go (stdlib only, CGO disabled, static single-file build).
//
// ODisasm decodes x86, x64, ARM (A32) and AArch64 machine code from raw
// shellcode, hex strings, or ELF / PE / Mach-O executables (whose executable
// section, architecture, base and entry are detected automatically), using a
// linear sweep or recursive descent, and triages the result for shellcode
// traits (raw syscalls, GetPC, PEB walks, decoder loops, NOP sleds).
package main

import (
	"bufio"
	"bytes"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	APPNAME = "ODisasm"
	SUITE   = "Owl Disassembly Suite"
	TAGLINE = "Multi-Arch Disassembler"
	SUBLINE = "x86 · x64 · ARM · ARM64 · ELF/PE/Mach-O · Recursive · Triage · Grade"
	VERSION = "1.0"
	AUTHOR  = "khaled.s.haddad"
	WEBSITE = "owlsec.org"
)

const BANNER = `
 ██████╗ ██████╗ ██╗███████╗ █████╗ ███████╗███╗   ███╗
██╔═══██╗██╔══██╗██║██╔════╝██╔══██╗██╔════╝████╗ ████║
██║   ██║██║  ██║██║███████╗███████║███████╗██╔████╔██║
██║   ██║██║  ██║██║╚════██║██╔══██║╚════██║██║╚██╔╝██║
╚██████╔╝██████╔╝██║███████║██║  ██║███████║██║ ╚═╝ ██║
 ╚═════╝ ╚═════╝ ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝
`

// ---- OWL UI KIT (cyan "owl" house style) — stdlib only. Shared across the suite ----
// CYAN is the primary brand/frame colour; red is reserved for errors and
// CRITICAL/HIGH severities.
const (
	R   = "\033[91m"       // red     — errors / critical
	GRN = "\033[92m"       // green   — success / low
	YLW = "\033[93m"       // yellow  — prompts / warning text
	CY  = "\033[96m"       // cyan    — primary brand & frames
	W   = "\033[97m"       // white   — body text
	B   = "\033[1m"        // bold
	X   = "\033[0m"        // reset
	MG  = "\033[95m"       // magenta — suite name / accents
	BL  = "\033[94m"       // blue    — accents
	DIM = "\033[2m"        // dim     — secondary text
	OR  = "\033[38;5;208m" // orange  — warning markers
	GY  = "\033[90m"       // gray    — muted
	DR  = CY               // legacy alias: former frame colour → cyan
)

var noColor = os.Getenv("NO_COLOR") != "" || !isatty()

func isatty() bool { fi, _ := os.Stdout.Stat(); return (fi.Mode() & os.ModeCharDevice) != 0 }
func col(s string, c ...string) string {
	if noColor {
		return s
	}
	return strings.Join(c, "") + s + X
}
func clear()           { fmt.Print("\033[H\033[2J") }
func line(w int)       { fmt.Println(col(strings.Repeat("─", w), CY)) }
func okMsg(s string)   { fmt.Println("  " + col("[✔] ", GRN+B) + col(s, W)) }
func errMsg(s string)  { fmt.Println("  " + col("[✘] ", R+B) + col(s, R)) }
func warnMsg(s string) { fmt.Println("  " + col("[!] ", OR+B) + col(s, YLW)) }
func info(s string)    { fmt.Println("  " + col("[*] ", CY) + col(s, DIM+W)) }

// banner prints the cyan ANSI-Shadow wordmark and the suite identity block.
func banner() {
	fmt.Println(col(BANNER, CY))
	fmt.Println("  " + col(SUITE+"  ", B+MG) + col("v"+VERSION, YLW))
	fmt.Println("  " + col(SUBLINE, W))
	fmt.Println()
	fmt.Println("  " + col("Developer : ", DIM) + col(AUTHOR, CY) +
		col("   |   Website : ", DIM) + col(WEBSITE, CY))
	fmt.Println(col(strings.Repeat("─", 66), CY))
	fmt.Println()
}
func prompt(label string) string {
	fmt.Print("  " + col("[»] ", YLW) + col(label+": ", W))
	rd := bufio.NewReader(os.Stdin)
	s, err := rd.ReadString('\n')
	if err != nil && s == "" {
		fmt.Println()
		os.Exit(0) // stdin closed (Ctrl-D / end of piped input)
	}
	return strings.TrimSpace(s)
}
func pause() {
	fmt.Print(col("\n  [↩] Press Enter to continue...", YLW))
	bufio.NewReader(os.Stdin).ReadString('\n')
}

// sectionHeader prints a ⬡ heading between two cyan rules.
func sectionHeader(s string) {
	fmt.Println(col(strings.Repeat("─", 66), CY))
	fmt.Println("  " + col("⬡  "+s, B+CY))
	fmt.Println(col(strings.Repeat("─", 66), CY))
	fmt.Println()
}

type menuItem struct {
	key, name, desc, clr string
}

// menu renders the ONode-style main menu and returns the raw selection.
func menu(title string, items []menuItem) string {
	clear()
	banner()
	fmt.Println("  " + col("⬡  "+title, B+CY))
	fmt.Println()
	for _, it := range items {
		fmt.Println("  " + col(pad("["+it.key+"]", 4), it.clr) + "  " +
			col(pad(it.name, 32), W) + col("─ "+it.desc, DIM))
	}
	fmt.Println()
	fmt.Println("  " + col(pad("[H]", 4), YLW+B) + "  " + col(pad("Help & Usage", 32), W) + col("─ How to use, every option, CLI flags & examples", DIM))
	fmt.Println("  " + col(pad("[0]", 4), R) + "  " + col(pad("Exit", 32), W) + col("─ Quit "+APPNAME, DIM))
	fmt.Println()
	fmt.Println(col(strings.Repeat("─", 66), CY))
	return prompt("Select option")
}
func pad(s string, n int) string {
	if visw(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-visw(s))
}
func visw(s string) int { return len([]rune(s)) }
func table(headers []string, rows [][]string) {
	w := make([]int, len(headers))
	for i, h := range headers {
		w[i] = visw(h)
	}
	for _, r := range rows {
		for i, c := range r {
			if i < len(w) && visw(c) > w[i] {
				w[i] = visw(c)
			}
		}
	}
	var hb strings.Builder
	for i, h := range headers {
		hb.WriteString(col(pad(h, w[i]), CY+B))
		if i < len(headers)-1 {
			hb.WriteString(col(" \u2502 ", DR))
		}
	}
	fmt.Println("  " + hb.String())
	seg := make([]string, len(w))
	for i := range w {
		seg[i] = strings.Repeat("\u2500", w[i])
	}
	fmt.Println("  " + col(strings.Join(seg, "\u2500\u253c\u2500"), DR))
	for _, r := range rows {
		var rb strings.Builder
		for i := range headers {
			v := ""
			if i < len(r) {
				v = r[i]
			}
			rb.WriteString(col(pad(v, w[i]), W))
			if i < len(headers)-1 {
				rb.WriteString(col(" \u2502 ", DR))
			}
		}
		fmt.Println("  " + rb.String())
	}
}

// ---- shared finding model, grading, and 5-format export engine ----
type Finding struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	Category    string   `json:"category"`
	ATTCK       []string `json:"attck,omitempty"`
	CWE         string   `json:"cwe,omitempty"`
	Description string   `json:"description"`
	Evidence    string   `json:"evidence,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	Location    string   `json:"location,omitempty"`
	Score       float64  `json:"score"`
}

type KV struct {
	K string `json:"key"`
	V string `json:"value"`
}

type Report struct {
	Tool      string    `json:"tool"`
	Tagline   string    `json:"tagline"`
	Version   string    `json:"version"`
	Target    string    `json:"target"`
	Generated string    `json:"generated"`
	Findings  []Finding `json:"findings"`
	Stats     []KV      `json:"stats"`
	Notes     []string  `json:"notes,omitempty"`
	Listing   []string  `json:"listing,omitempty"`
	Grade     string    `json:"grade"`
	Score     float64   `json:"score"`
}

var sevOrder = map[string]int{"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}

func sevRank(s string) int {
	if v, ok := sevOrder[strings.ToUpper(s)]; ok {
		return v
	}
	return 0
}
func sevColor(s string) string {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return R + B
	case "HIGH":
		return R
	case "MEDIUM":
		return YLW
	case "LOW":
		return GRN
	default:
		return GY
	}
}
func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if sevRank(fs[i].Severity) != sevRank(fs[j].Severity) {
			return sevRank(fs[i].Severity) > sevRank(fs[j].Severity)
		}
		return fs[i].Score > fs[j].Score
	})
}
func gradeFromScore(f float64) string {
	switch {
	case f >= 97:
		return "A+"
	case f >= 93:
		return "A"
	case f >= 90:
		return "A-"
	case f >= 87:
		return "B+"
	case f >= 83:
		return "B"
	case f >= 80:
		return "B-"
	case f >= 77:
		return "C+"
	case f >= 73:
		return "C"
	case f >= 70:
		return "C-"
	case f >= 65:
		return "D+"
	case f >= 60:
		return "D"
	default:
		return "F"
	}
}
func computePosture(fs []Finding) (string, float64) {
	score := 100.0
	for _, f := range fs {
		switch strings.ToUpper(f.Severity) {
		case "CRITICAL":
			score -= 22
		case "HIGH":
			score -= 13
		case "MEDIUM":
			score -= 6
		case "LOW":
			score -= 2.5
		case "INFO":
			score -= 0.3
		}
	}
	if score < 0 {
		score = 0
	}
	return gradeFromScore(score), score
}
func sevCounts(fs []Finding) map[string]int {
	m := map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
	for _, f := range fs {
		m[strings.ToUpper(f.Severity)]++
	}
	return m
}
func newReport(target string) *Report {
	g, s := "", 0.0
	_ = g
	_ = s
	return &Report{
		Tool:      APPNAME,
		Tagline:   TAGLINE,
		Version:   VERSION,
		Target:    target,
		Generated: time.Now().Format("2006-01-02 15:04:05 -0700"),
		Findings:  []Finding{}, // JSON [] rather than null when clean
	}
}
func (r *Report) finalize() {
	sortFindings(r.Findings)
	r.Grade, r.Score = computePosture(r.Findings)
}

func jsonEscape(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func exportJSON(r *Report) string {
	r.finalize()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	_ = enc.Encode(r)
	return buf.String()
}

func exportCSV(r *Report) string {
	r.finalize()
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	w.Write([]string{"id", "severity", "score", "category", "title", "attck", "cwe", "location", "description", "remediation"})
	for _, f := range r.Findings {
		w.Write([]string{f.ID, f.Severity, strconv.FormatFloat(f.Score, 'f', 1, 64), f.Category, f.Title, strings.Join(f.ATTCK, " "), f.CWE, f.Location, oneLine(f.Description), oneLine(f.Remediation)})
	}
	w.Flush()
	return buf.String()
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return strings.TrimSpace(s)
}

func exportTXT(r *Report) string {
	r.finalize()
	var b strings.Builder
	bar := strings.Repeat("=", 72)
	b.WriteString(bar + "\n")
	b.WriteString("  " + r.Tool + " — " + r.Tagline + "\n")
	b.WriteString("  Author: khaled.s.haddad    Site: owlsec.org    Version: " + r.Version + "\n")
	b.WriteString(bar + "\n")
	b.WriteString("Target    : " + r.Target + "\n")
	b.WriteString("Generated : " + r.Generated + "\n")
	b.WriteString(fmt.Sprintf("Posture   : %s (%.1f/100)\n", r.Grade, r.Score))
	c := sevCounts(r.Findings)
	b.WriteString(fmt.Sprintf("Findings  : %d  [CRIT %d | HIGH %d | MED %d | LOW %d | INFO %d]\n",
		len(r.Findings), c["CRITICAL"], c["HIGH"], c["MEDIUM"], c["LOW"], c["INFO"]))
	if len(r.Stats) > 0 {
		b.WriteString("\n-- Statistics --\n")
		for _, kv := range r.Stats {
			b.WriteString(fmt.Sprintf("  %-28s : %s\n", kv.K, kv.V))
		}
	}
	if len(r.Findings) > 0 {
		b.WriteString("\n-- Findings --\n")
		for i, f := range r.Findings {
			b.WriteString(fmt.Sprintf("\n[%d] %s  (%s, score %.1f)\n", i+1, f.Title, f.Severity, f.Score))
			b.WriteString("    id         : " + f.ID + "\n")
			b.WriteString("    category   : " + f.Category + "\n")
			if len(f.ATTCK) > 0 {
				b.WriteString("    att&ck     : " + annotateATTCK(f.ATTCK) + "\n")
			}
			if f.CWE != "" {
				b.WriteString("    cwe        : " + f.CWE + "\n")
			}
			if f.Location != "" {
				b.WriteString("    location   : " + f.Location + "\n")
			}
			if f.Description != "" {
				b.WriteString("    detail     : " + f.Description + "\n")
			}
			if f.Evidence != "" {
				b.WriteString("    evidence   : " + oneLine(f.Evidence) + "\n")
			}
			if f.Remediation != "" {
				b.WriteString("    fix        : " + f.Remediation + "\n")
			}
		}
	}
	if len(r.Listing) > 0 {
		b.WriteString("\n-- Disassembly --\n")
		for _, l := range r.Listing {
			b.WriteString("  " + l + "\n")
		}
	}
	if len(r.Notes) > 0 {
		b.WriteString("\n-- Notes --\n")
		for _, n := range r.Notes {
			b.WriteString("  * " + n + "\n")
		}
	}
	b.WriteString("\n" + bar + "\n")
	return b.String()
}

func exportMD(r *Report) string {
	r.finalize()
	var b strings.Builder
	b.WriteString("# " + r.Tool + " Report\n\n")
	b.WriteString("*" + r.Tagline + "*\n\n")
	b.WriteString("| Field | Value |\n|---|---|\n")
	b.WriteString("| Target | " + mdEsc(r.Target) + " |\n")
	b.WriteString("| Generated | " + r.Generated + " |\n")
	b.WriteString("| Version | " + r.Version + " |\n")
	b.WriteString(fmt.Sprintf("| Posture | **%s** (%.1f/100) |\n", r.Grade, r.Score))
	c := sevCounts(r.Findings)
	b.WriteString(fmt.Sprintf("| Findings | %d (C%d/H%d/M%d/L%d/I%d) |\n\n",
		len(r.Findings), c["CRITICAL"], c["HIGH"], c["MEDIUM"], c["LOW"], c["INFO"]))
	if len(r.Stats) > 0 {
		b.WriteString("## Statistics\n\n| Metric | Value |\n|---|---|\n")
		for _, kv := range r.Stats {
			b.WriteString("| " + mdEsc(kv.K) + " | " + mdEsc(kv.V) + " |\n")
		}
		b.WriteString("\n")
	}
	if len(r.Findings) > 0 {
		b.WriteString("## Findings\n\n")
		for i, f := range r.Findings {
			b.WriteString(fmt.Sprintf("### %d. %s\n\n", i+1, mdEsc(f.Title)))
			b.WriteString("- **Severity:** " + f.Severity + fmt.Sprintf(" (score %.1f)\n", f.Score))
			b.WriteString("- **ID:** `" + f.ID + "`\n")
			b.WriteString("- **Category:** " + mdEsc(f.Category) + "\n")
			if len(f.ATTCK) > 0 {
				b.WriteString("- **ATT&CK:** " + annotateATTCK(f.ATTCK) + "\n")
			}
			if f.CWE != "" {
				b.WriteString("- **CWE:** " + f.CWE + "\n")
			}
			if f.Location != "" {
				b.WriteString("- **Location:** `" + f.Location + "`\n")
			}
			if f.Description != "" {
				b.WriteString("- **Detail:** " + mdEsc(f.Description) + "\n")
			}
			if f.Evidence != "" {
				b.WriteString("- **Evidence:** `" + oneLine(f.Evidence) + "`\n")
			}
			if f.Remediation != "" {
				b.WriteString("- **Fix:** " + mdEsc(f.Remediation) + "\n")
			}
			b.WriteString("\n")
		}
	}
	if len(r.Listing) > 0 {
		b.WriteString("## Disassembly\n\n```\n")
		for _, l := range r.Listing {
			b.WriteString(l + "\n")
		}
		b.WriteString("```\n\n")
	}
	if len(r.Notes) > 0 {
		b.WriteString("## Notes\n\n")
		for _, n := range r.Notes {
			b.WriteString("- " + mdEsc(n) + "\n")
		}
	}
	return b.String()
}

func mdEsc(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	return s
}

func sarifLevel(sev string) string {
	switch strings.ToUpper(sev) {
	case "CRITICAL", "HIGH":
		return "error"
	case "MEDIUM":
		return "warning"
	case "LOW", "INFO":
		return "note"
	default:
		return "none"
	}
}

func exportSARIF(r *Report) string {
	r.finalize()
	type sarifMsg struct {
		Text string `json:"text"`
	}
	type sarifRule struct {
		ID               string            `json:"id"`
		Name             string            `json:"name"`
		ShortDescription sarifMsg          `json:"shortDescription"`
		FullDescription  sarifMsg          `json:"fullDescription"`
		HelpURI          string            `json:"helpUri,omitempty"`
		Properties       map[string]any    `json:"properties,omitempty"`
		DefaultConfig    map[string]string `json:"defaultConfiguration,omitempty"`
	}
	type sarifArtifact struct {
		URI string `json:"uri"`
	}
	type sarifRegion struct {
		StartLine int `json:"startLine,omitempty"`
	}
	type sarifPhys struct {
		ArtifactLocation sarifArtifact `json:"artifactLocation"`
		Region           *sarifRegion  `json:"region,omitempty"`
	}
	type sarifLoc struct {
		PhysicalLocation sarifPhys `json:"physicalLocation"`
	}
	type sarifResult struct {
		RuleID    string         `json:"ruleId"`
		Level     string         `json:"level"`
		Message   sarifMsg       `json:"message"`
		Locations []sarifLoc     `json:"locations,omitempty"`
		Props     map[string]any `json:"properties,omitempty"`
	}
	type sarifDriver struct {
		Name           string      `json:"name"`
		Version        string      `json:"version"`
		InformationURI string      `json:"informationUri"`
		Rules          []sarifRule `json:"rules"`
	}
	type sarifTool struct {
		Driver sarifDriver `json:"driver"`
	}
	type sarifRun struct {
		Tool    sarifTool     `json:"tool"`
		Results []sarifResult `json:"results"`
	}
	type sarifDoc struct {
		Schema  string     `json:"$schema"`
		Version string     `json:"version"`
		Runs    []sarifRun `json:"runs"`
	}
	ruleSeen := map[string]bool{}
	var rules []sarifRule
	var results []sarifResult
	for _, f := range r.Findings {
		if !ruleSeen[f.ID] {
			ruleSeen[f.ID] = true
			props := map[string]any{"severity": f.Severity, "category": f.Category}
			if len(f.ATTCK) > 0 {
				props["attck"] = f.ATTCK
			}
			if f.CWE != "" {
				props["cwe"] = f.CWE
			}
			rules = append(rules, sarifRule{
				ID:               f.ID,
				Name:             f.Title,
				ShortDescription: sarifMsg{Text: f.Title},
				FullDescription:  sarifMsg{Text: nonEmpty(f.Description, f.Title)},
				HelpURI:          "https://owlsec.org",
				Properties:       props,
				DefaultConfig:    map[string]string{"level": sarifLevel(f.Severity)},
			})
		}
		loc := nonEmpty(f.Location, r.Target)
		res := sarifResult{
			RuleID:  f.ID,
			Level:   sarifLevel(f.Severity),
			Message: sarifMsg{Text: nonEmpty(f.Description, f.Title)},
			Props:   map[string]any{"score": f.Score, "severity": f.Severity},
			Locations: []sarifLoc{{PhysicalLocation: sarifPhys{
				ArtifactLocation: sarifArtifact{URI: loc},
			}}},
		}
		results = append(results, res)
	}
	doc := sarifDoc{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           r.Tool,
				Version:        r.Version,
				InformationURI: "https://owlsec.org",
				Rules:          rules,
			}},
			Results: results,
		}},
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	_ = enc.Encode(doc)
	return buf.String()
}

func nonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

func renderReport(r *Report, format string) string {
	switch strings.ToLower(format) {
	case "json":
		return exportJSON(r)
	case "csv":
		return exportCSV(r)
	case "md", "markdown":
		return exportMD(r)
	case "sarif":
		return exportSARIF(r)
	default:
		return exportTXT(r)
	}
}

func emit(r *Report, format, output string) error {
	content := renderReport(r, format)
	if output == "" || output == "-" {
		fmt.Print(content)
		if !strings.HasSuffix(content, "\n") {
			fmt.Println()
		}
		return nil
	}
	if err := os.WriteFile(output, []byte(content), 0644); err != nil {
		return err
	}
	okMsg("wrote " + format + " report to " + output)
	return nil
}

func showFindingsTUI(r *Report) {
	r.finalize()
	if len(r.Findings) == 0 {
		okMsg("no findings")
		return
	}
	rows := [][]string{}
	for _, f := range r.Findings {
		at := strings.Join(f.ATTCK, ",")
		if at == "" {
			at = "-"
		}
		rows = append(rows, []string{f.ID, f.Severity, fmt.Sprintf("%.1f", f.Score), f.Title, at})
	}
	table([]string{"ID", "SEV", "SCORE", "TITLE", "ATT&CK"}, rows)
	fmt.Println()
	info(fmt.Sprintf("posture grade %s (%.1f/100)", r.Grade, r.Score))
}

// ---- shared utility helpers (hexdump, entropy, histograms, formatting) ----
func hexDump(b []byte) string {
	var sb strings.Builder
	for i := 0; i < len(b); i += 16 {
		sb.WriteString(fmt.Sprintf("%08x  ", i))
		for j := 0; j < 16; j++ {
			if i+j < len(b) {
				sb.WriteString(fmt.Sprintf("%02x ", b[i+j]))
			} else {
				sb.WriteString("   ")
			}
			if j == 7 {
				sb.WriteString(" ")
			}
		}
		sb.WriteString(" |")
		for j := 0; j < 16 && i+j < len(b); j++ {
			c := b[i+j]
			if c >= 32 && c < 127 {
				sb.WriteByte(c)
			} else {
				sb.WriteByte('.')
			}
		}
		sb.WriteString("|\n")
	}
	return sb.String()
}

func entropyOf(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var freq [256]int
	for _, c := range b {
		freq[c]++
	}
	var h float64
	n := float64(len(b))
	for _, f := range freq {
		if f == 0 {
			continue
		}
		p := float64(f) / n
		h -= p * mathLog2(p)
	}
	return h
}

func mathLog2(x float64) float64 { return lnApprox(x) / 0.6931471805599453 }

func lnApprox(x float64) float64 {
	if x <= 0 {
		return 0
	}
	k := 0
	for x > 2 {
		x /= 2
		k++
	}
	for x < 0.5 {
		x *= 2
		k--
	}
	y := (x - 1) / (x + 1)
	y2 := y * y
	sum := 0.0
	term := y
	for i := 1; i <= 19; i += 2 {
		sum += term / float64(i)
		term *= y2
	}
	return 2*sum + float64(k)*0.6931471805599453
}

func humanBytes(n int64) string {
	const u = 1024
	if n < u {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(u), 0
	for x := n / u; x >= u; x /= u {
		div *= u
		exp++
	}
	units := []string{"KB", "MB", "GB", "TB", "PB", "EB"}
	return fmt.Sprintf("%.2f %s", float64(n)/float64(div), units[exp])
}

func commaInt(n int64) string {
	s := strconv.FormatInt(n, 10)
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	var out []byte
	for i, c := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, c)
	}
	if neg {
		return "-" + string(out)
	}
	return string(out)
}

func asciiBar(frac float64, width int) string {
	if frac < 0 {
		frac = 0
	}
	if frac > 1 {
		frac = 1
	}
	fill := int(frac * float64(width))
	if fill > width {
		fill = width
	}
	return strings.Repeat("\u2588", fill) + strings.Repeat("\u2591", width-fill)
}

func byteHistogram(b []byte) [256]int {
	var h [256]int
	for _, c := range b {
		h[c]++
	}
	return h
}

func truncStr(s string, n int) string {
	if len([]rune(s)) <= n {
		return s
	}
	r := []rune(s)
	if n < 1 {
		return ""
	}
	return string(r[:n-1]) + "\u2026"
}

func minI(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func maxI(a, b int) int {
	if a > b {
		return a
	}
	return b
}
func absI(a int) int {
	if a < 0 {
		return -a
	}
	return a
}
func clampF(x, lo, hi float64) float64 {
	if x < lo {
		return lo
	}
	if x > hi {
		return hi
	}
	return x
}

func kvTable(pairs []KV) {
	rows := [][]string{}
	for _, kv := range pairs {
		rows = append(rows, []string{kv.K, kv.V})
	}
	table([]string{"METRIC", "VALUE"}, rows)
}

func printHelpSection(title string, lines []string) {
	fmt.Println(col("  "+title, CY+B))
	for _, l := range lines {
		fmt.Println("    " + l)
	}
	fmt.Println()
}

func readLines(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, l := range strings.Split(string(data), "\n") {
		out = append(out, l)
	}
	return out, nil
}

func wrapText(s string, width int) []string {
	words := strings.Fields(s)
	var lines []string
	cur := ""
	for _, w := range words {
		if len(cur)+len(w)+1 > width {
			lines = append(lines, cur)
			cur = w
		} else if cur == "" {
			cur = w
		} else {
			cur += " " + w
		}
	}
	if cur != "" {
		lines = append(lines, cur)
	}
	return lines
}

// atoiSafe parses an int, returning def on error.
func atoiSafe(s string, def int) int {
	s = strings.TrimSpace(s)
	if v, err := strconv.Atoi(s); err == nil {
		return v
	}
	return def
}

// splitCSVLine does minimal CSV field splitting on a single line.
func splitCSVLine(s string) []string {
	var out []string
	var cur strings.Builder
	inq := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			inq = !inq
		case c == ',' && !inq:
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	out = append(out, cur.String())
	return out
}

// ---- shared MITRE ATT&CK + CWE reference (used by finding renderers) ----
var attckNames = map[string]string{
	"T1003":     "OS Credential Dumping",
	"T1003.001": "LSASS Memory",
	"T1005":     "Data from Local System",
	"T1016":     "System Network Configuration Discovery",
	"T1018":     "Remote System Discovery",
	"T1021":     "Remote Services",
	"T1021.001": "Remote Desktop Protocol",
	"T1021.002": "SMB/Windows Admin Shares",
	"T1033":     "System Owner/User Discovery",
	"T1036":     "Masquerading",
	"T1040":     "Network Sniffing",
	"T1046":     "Network Service Discovery",
	"T1048":     "Exfiltration Over Alternative Protocol",
	"T1055":     "Process Injection",
	"T1057":     "Process Discovery",
	"T1059":     "Command and Scripting Interpreter",
	"T1068":     "Exploitation for Privilege Escalation",
	"T1070":     "Indicator Removal",
	"T1070.002": "Clear Linux or Mac System Logs",
	"T1071":     "Application Layer Protocol",
	"T1071.001": "Web Protocols",
	"T1071.004": "DNS",
	"T1078":     "Valid Accounts",
	"T1082":     "System Information Discovery",
	"T1083":     "File and Directory Discovery",
	"T1090":     "Proxy",
	"T1095":     "Non-Application Layer Protocol",
	"T1098":     "Account Manipulation",
	"T1110":     "Brute Force",
	"T1110.001": "Password Guessing",
	"T1110.003": "Password Spraying",
	"T1133":     "External Remote Services",
	"T1135":     "Network Share Discovery",
	"T1136":     "Create Account",
	"T1190":     "Exploit Public-Facing Application",
	"T1203":     "Exploitation for Client Execution",
	"T1210":     "Exploitation of Remote Services",
	"T1211":     "Exploitation for Defense Evasion",
	"T1217":     "Browser Information Discovery",
	"T1222":     "File and Directory Permissions Modification",
	"T1222.001": "Windows File and Directory Permissions Modification",
	"T1222.002": "Linux and Mac File and Directory Permissions Modification",
	"T1480":     "Execution Guardrails",
	"T1485":     "Data Destruction",
	"T1486":     "Data Encrypted for Impact",
	"T1489":     "Service Stop",
	"T1498":     "Network Denial of Service",
	"T1499":     "Endpoint Denial of Service",
	"T1518":     "Software Discovery",
	"T1543":     "Create or Modify System Process",
	"T1543.002": "Systemd Service",
	"T1547":     "Boot or Logon Autostart Execution",
	"T1548":     "Abuse Elevation Control Mechanism",
	"T1548.001": "Setuid and Setgid",
	"T1552":     "Unsecured Credentials",
	"T1552.001": "Credentials In Files",
	"T1552.004": "Private Keys",
	"T1553":     "Subvert Trust Controls",
	"T1557":     "Adversary-in-the-Middle",
	"T1557.001": "LLMNR/NBT-NS Poisoning and SMB Relay",
	"T1562":     "Impair Defenses",
	"T1562.001": "Disable or Modify Tools",
	"T1565":     "Data Manipulation",
	"T1565.001": "Stored Data Manipulation",
	"T1570":     "Lateral Tool Transfer",
	"T1571":     "Non-Standard Port",
	"T1572":     "Protocol Tunneling",
	"T1573":     "Encrypted Channel",
	"T1573.001": "Symmetric Cryptography",
	"T1574":     "Hijack Execution Flow",
	"T1589":     "Gather Victim Identity Information",
	"T1590":     "Gather Victim Network Information",
	"T1595":     "Active Scanning",
	"T1599":     "Network Boundary Bridging",
	"T1600":     "Weaken Encryption",
	"T1602":     "Data from Configuration Repository",
	"T1610":     "Deploy Container",
	"T1611":     "Escape to Host",
}

var cweNames = map[string]string{
	"CWE-22":   "Path Traversal",
	"CWE-78":   "OS Command Injection",
	"CWE-79":   "Cross-site Scripting",
	"CWE-89":   "SQL Injection",
	"CWE-200":  "Exposure of Sensitive Information",
	"CWE-209":  "Information Exposure Through an Error Message",
	"CWE-250":  "Execution with Unnecessary Privileges",
	"CWE-269":  "Improper Privilege Management",
	"CWE-276":  "Incorrect Default Permissions",
	"CWE-295":  "Improper Certificate Validation",
	"CWE-306":  "Missing Authentication for Critical Function",
	"CWE-307":  "Improper Restriction of Excessive Authentication Attempts",
	"CWE-311":  "Missing Encryption of Sensitive Data",
	"CWE-312":  "Cleartext Storage of Sensitive Information",
	"CWE-319":  "Cleartext Transmission of Sensitive Information",
	"CWE-326":  "Inadequate Encryption Strength",
	"CWE-327":  "Use of a Broken or Risky Cryptographic Algorithm",
	"CWE-328":  "Use of Weak Hash",
	"CWE-330":  "Use of Insufficiently Random Values",
	"CWE-338":  "Use of Cryptographically Weak PRNG",
	"CWE-521":  "Weak Password Requirements",
	"CWE-522":  "Insufficiently Protected Credentials",
	"CWE-532":  "Insertion of Sensitive Information into Log File",
	"CWE-601":  "Open Redirect",
	"CWE-732":  "Incorrect Permission Assignment for Critical Resource",
	"CWE-798":  "Use of Hard-coded Credentials",
	"CWE-918":  "Server-Side Request Forgery",
	"CWE-1104": "Use of Unmaintained Third Party Components",
}

func attckName(id string) string {
	if n, ok := attckNames[id]; ok {
		return n
	}
	return id
}

func cweName(id string) string {
	if !strings.HasPrefix(id, "CWE-") {
		id = "CWE-" + id
	}
	if n, ok := cweNames[id]; ok {
		return id + " (" + n + ")"
	}
	return id
}

func annotateATTCK(ids []string) string {
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		if n := attckName(id); n != id {
			parts = append(parts, id+" "+n)
		} else {
			parts = append(parts, id)
		}
	}
	return strings.Join(parts, ", ")
}

// printTechniqueCatalog lists all known ATT&CK techniques referenced by the suite.
func printTechniqueCatalog() {
	var ids []string
	for id := range attckNames {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	rows := [][]string{}
	for _, id := range ids {
		rows = append(rows, []string{id, attckNames[id]})
	}
	table([]string{"TECHNIQUE", "NAME"}, rows)
}

var x86OneByteOps = map[byte]string{
	0x00: "ADD r/m8,r8",
	0x01: "ADD r/m,r",
	0x02: "ADD r8,r/m8",
	0x03: "ADD r,r/m",
	0x04: "ADD AL,imm8",
	0x05: "ADD rAX,imm",
	0x06: "PUSH ES",
	0x07: "POP ES",
	0x08: "OR r/m8,r8",
	0x09: "OR r/m,r",
	0x0a: "OR r8,r/m8",
	0x0b: "OR r,r/m",
	0x0c: "OR AL,imm8",
	0x0d: "OR rAX,imm",
	0x0e: "PUSH CS",
	0x0f: "2-byte escape",
	0x10: "ADC r/m8,r8",
	0x11: "ADC r/m,r",
	0x12: "ADC r8,r/m8",
	0x13: "ADC r,r/m",
	0x14: "ADC AL,imm8",
	0x15: "ADC rAX,imm",
	0x16: "PUSH SS",
	0x17: "POP SS",
	0x18: "SBB r/m8,r8",
	0x19: "SBB r/m,r",
	0x1a: "SBB r8,r/m8",
	0x1b: "SBB r,r/m",
	0x1c: "SBB AL,imm8",
	0x1d: "SBB rAX,imm",
	0x1e: "PUSH DS",
	0x1f: "POP DS",
	0x20: "AND r/m8,r8",
	0x21: "AND r/m,r",
	0x22: "AND r8,r/m8",
	0x23: "AND r,r/m",
	0x24: "AND AL,imm8",
	0x25: "AND rAX,imm",
	0x26: "ES:",
	0x27: "DAA",
	0x28: "SUB r/m8,r8",
	0x29: "SUB r/m,r",
	0x2a: "SUB r8,r/m8",
	0x2b: "SUB r,r/m",
	0x2c: "SUB AL,imm8",
	0x2d: "SUB rAX,imm",
	0x2e: "CS:",
	0x2f: "DAS",
	0x30: "XOR r/m8,r8",
	0x31: "XOR r/m,r",
	0x32: "XOR r8,r/m8",
	0x33: "XOR r,r/m",
	0x34: "XOR AL,imm8",
	0x35: "XOR rAX,imm",
	0x36: "SS:",
	0x37: "AAA",
	0x38: "CMP r/m8,r8",
	0x39: "CMP r/m,r",
	0x3a: "CMP r8,r/m8",
	0x3b: "CMP r,r/m",
	0x3c: "CMP AL,imm8",
	0x3d: "CMP rAX,imm",
	0x3e: "DS:",
	0x3f: "AAS",
	0x40: "INC AX/REX",
	0x41: "INC CX/REX",
	0x42: "INC DX/REX",
	0x43: "INC BX/REX",
	0x44: "INC SP/REX",
	0x45: "INC BP/REX",
	0x46: "INC SI/REX",
	0x47: "INC DI/REX",
	0x48: "DEC AX/REX",
	0x49: "DEC CX/REX",
	0x4a: "DEC DX/REX",
	0x4b: "DEC BX/REX",
	0x4c: "DEC SP/REX",
	0x4d: "DEC BP/REX",
	0x4e: "DEC SI/REX",
	0x4f: "DEC DI/REX",
	0x50: "PUSH rAX",
	0x51: "PUSH rCX",
	0x52: "PUSH rDX",
	0x53: "PUSH rBX",
	0x54: "PUSH rSP",
	0x55: "PUSH rBP",
	0x56: "PUSH rSI",
	0x57: "PUSH rDI",
	0x58: "POP rAX",
	0x59: "POP rCX",
	0x5a: "POP rDX",
	0x5b: "POP rBX",
	0x5c: "POP rSP",
	0x5d: "POP rBP",
	0x5e: "POP rSI",
	0x5f: "POP rDI",
	0x60: "PUSHA",
	0x61: "POPA",
	0x62: "BOUND",
	0x63: "MOVSXD/ARPL",
	0x64: "FS:",
	0x65: "GS:",
	0x66: "OPSIZE",
	0x67: "ADSIZE",
	0x68: "PUSH imm",
	0x69: "IMUL r,r/m,imm",
	0x6a: "PUSH imm8",
	0x6b: "IMUL r,r/m,imm8",
	0x6c: "INSB",
	0x6d: "INS",
	0x6e: "OUTSB",
	0x6f: "OUTS",
	0x70: "JO",
	0x71: "JNO",
	0x72: "JB",
	0x73: "JAE",
	0x74: "JE",
	0x75: "JNE",
	0x76: "JBE",
	0x77: "JA",
	0x78: "JS",
	0x79: "JNS",
	0x7a: "JP",
	0x7b: "JNP",
	0x7c: "JL",
	0x7d: "JGE",
	0x7e: "JLE",
	0x7f: "JG",
	0x80: "ALU r/m8,imm8",
	0x81: "ALU r/m,imm",
	0x82: "ALU r/m8,imm8",
	0x83: "ALU r/m,imm8",
	0x84: "TEST r/m8,r8",
	0x85: "TEST r/m,r",
	0x86: "XCHG r8,r/m8",
	0x87: "XCHG r,r/m",
	0x88: "MOV r/m8,r8",
	0x89: "MOV r/m,r",
	0x8a: "MOV r8,r/m8",
	0x8b: "MOV r,r/m",
	0x8c: "MOV r/m,sreg",
	0x8d: "LEA r,m",
	0x8e: "MOV sreg,r/m",
	0x8f: "POP r/m",
	0x90: "NOP/XCHG",
	0x91: "XCHG rCX,rAX",
	0x92: "XCHG rDX,rAX",
	0x93: "XCHG rBX,rAX",
	0x94: "XCHG rSP,rAX",
	0x95: "XCHG rBP,rAX",
	0x96: "XCHG rSI,rAX",
	0x97: "XCHG rDI,rAX",
	0x98: "CBW/CWDE/CDQE",
	0x99: "CWD/CDQ/CQO",
	0x9a: "CALLF",
	0x9b: "FWAIT",
	0x9c: "PUSHF",
	0x9d: "POPF",
	0x9e: "SAHF",
	0x9f: "LAHF",
	0xa0: "MOV AL,moffs",
	0xa1: "MOV rAX,moffs",
	0xa2: "MOV moffs,AL",
	0xa3: "MOV moffs,rAX",
	0xa4: "MOVSB",
	0xa5: "MOVS",
	0xa6: "CMPSB",
	0xa7: "CMPS",
	0xa8: "TEST AL,imm8",
	0xa9: "TEST rAX,imm",
	0xaa: "STOSB",
	0xab: "STOS",
	0xac: "LODSB",
	0xad: "LODS",
	0xae: "SCASB",
	0xaf: "SCAS",
	0xb0: "MOV AL,imm8",
	0xb1: "MOV CL,imm8",
	0xb2: "MOV DL,imm8",
	0xb3: "MOV BL,imm8",
	0xb4: "MOV AH,imm8",
	0xb5: "MOV CH,imm8",
	0xb6: "MOV DH,imm8",
	0xb7: "MOV BH,imm8",
	0xb8: "MOV rAX,imm",
	0xb9: "MOV rCX,imm",
	0xba: "MOV rDX,imm",
	0xbb: "MOV rBX,imm",
	0xbc: "MOV rSP,imm",
	0xbd: "MOV rBP,imm",
	0xbe: "MOV rSI,imm",
	0xbf: "MOV rDI,imm",
	0xc0: "shift r/m8,imm8",
	0xc1: "shift r/m,imm8",
	0xc2: "RET imm16",
	0xc3: "RET",
	0xc4: "LES",
	0xc5: "LDS",
	0xc6: "MOV r/m8,imm8",
	0xc7: "MOV r/m,imm",
	0xc8: "ENTER",
	0xc9: "LEAVE",
	0xca: "RETF imm16",
	0xcb: "RETF",
	0xcc: "INT3",
	0xcd: "INT imm8",
	0xce: "INTO",
	0xcf: "IRET",
	0xd0: "shift r/m8,1",
	0xd1: "shift r/m,1",
	0xd2: "shift r/m8,CL",
	0xd3: "shift r/m,CL",
	0xd4: "AAM",
	0xd5: "AAD",
	0xd6: "SALC",
	0xd7: "XLAT",
	0xd8: "x87-D8",
	0xd9: "x87-D9",
	0xda: "x87-DA",
	0xdb: "x87-DB",
	0xdc: "x87-DC",
	0xdd: "x87-DD",
	0xde: "x87-DE",
	0xdf: "x87-DF",
	0xe0: "LOOPNE",
	0xe1: "LOOPE",
	0xe2: "LOOP",
	0xe3: "JCXZ",
	0xe4: "IN AL,imm8",
	0xe5: "IN rAX,imm8",
	0xe6: "OUT imm8,AL",
	0xe7: "OUT imm8,rAX",
	0xe8: "CALL rel",
	0xe9: "JMP rel",
	0xea: "JMPF",
	0xeb: "JMP rel8",
	0xec: "IN AL,DX",
	0xed: "IN rAX,DX",
	0xee: "OUT DX,AL",
	0xef: "OUT DX,rAX",
	0xf0: "LOCK",
	0xf1: "INT1",
	0xf2: "REPNE",
	0xf3: "REP",
	0xf4: "HLT",
	0xf5: "CMC",
	0xf6: "unary r/m8",
	0xf7: "unary r/m",
	0xf8: "CLC",
	0xf9: "STC",
	0xfa: "CLI",
	0xfb: "STI",
	0xfc: "CLD",
	0xfd: "STD",
	0xfe: "INC/DEC r/m8",
	0xff: "INC/DEC/CALL/JMP/PUSH",
}
var armCond = []string{"EQ", "NE", "CS", "CC", "MI", "PL", "VS", "VC", "HI", "LS", "GE", "LT", "GT", "LE", "AL", "NV"}
var armDataProc = []string{"AND", "EOR", "SUB", "RSB", "ADD", "ADC", "SBC", "RSC", "TST", "TEQ", "CMP", "CMN", "ORR", "MOV", "BIC", "MVN"}

type Arch int

const (
	ArchX86 Arch = iota
	ArchX64
	ArchARM
	ArchARM64
)

func (a Arch) String() string {
	switch a {
	case ArchX86:
		return "x86"
	case ArchX64:
		return "x64"
	case ArchARM:
		return "arm"
	case ArchARM64:
		return "arm64"
	default:
		return "?"
	}
}

// parseArch maps a --arch value to an Arch and its default operand width.
func parseArch(s string) (Arch, int, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "x86", "i386", "32", "ia32":
		return ArchX86, 32, true
	case "x64", "amd64", "x86_64", "x86-64", "64", "":
		return ArchX64, 64, true
	case "arm", "arm32", "a32":
		return ArchARM, 32, true
	case "arm64", "aarch64", "a64":
		return ArchARM64, 64, true
	}
	return ArchX64, 64, false
}

// Insn is one decoded instruction. Flow is one of:
// next | branch (unconditional) | cbranch (conditional) | call | ret |
// syscall | stop (hlt/ud2) | invalid.
type Insn struct {
	Offset    uint64
	Size      int
	Bytes     []byte
	Mnemonic  string
	Operands  string
	Flow      string
	Target    uint64 // direct branch/call target
	HasTarget bool
	MemRef    uint64 // RIP/PC-relative data address (lea, mov [rip+x], ldr =lit)
	HasMemRef bool
	Leader    bool   // first instruction of a basic block
	Comment   string // decoder annotation (resolved address, syscall name, …)
}

// ============================================================================
//  x86 / x64 decoder — table driven, Intel syntax.
//  Covers legacy prefixes, REX, ModRM/SIB (16/32/64-bit addressing, RIP-rel),
//  every one-byte opcode, the 0F / 0F38 / 0F3A maps, x87, and VEX/EVEX
//  lengths. Lengths are exact, so a linear sweep stays in sync.
// ============================================================================

type x86Op struct {
	mn    string // mnemonic; "" = invalid
	ops   string // operand template, comma separated
	modrm bool
	grp   int  // 1..5 = arithmetic/shift/unary/incdec/ff groups, 11 = mov-imm
	inv64 bool // invalid in 64-bit mode
	d64   bool // defaults to 64-bit operand size in 64-bit mode
}

var x86Map1 [256]x86Op
var x86Map2 [256]x86Op

var aluNames = []string{"add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"}
var grp2Names = []string{"rol", "ror", "rcl", "rcr", "shl", "shr", "sal", "sar"}
var grp3Names = []string{"test", "test", "not", "neg", "mul", "imul", "div", "idiv"}
var ccNames = []string{"o", "no", "b", "ae", "e", "ne", "be", "a", "s", "ns", "p", "np", "l", "ge", "le", "g"}

func init() {
	m := &x86Map1
	set := func(op int, mn, ops string, modrm bool) { m[op] = x86Op{mn: mn, ops: ops, modrm: modrm} }
	for k := 0; k < 8; k++ {
		b := k * 8
		set(b+0, aluNames[k], "Eb,Gb", true)
		set(b+1, aluNames[k], "Ev,Gv", true)
		set(b+2, aluNames[k], "Gb,Eb", true)
		set(b+3, aluNames[k], "Gv,Ev", true)
		set(b+4, aluNames[k], "AL,Ib", false)
		set(b+5, aluNames[k], "eAX,Iz", false)
	}
	seg := []string{"es", "cs", "ss", "ds"}
	for k := 0; k < 4; k++ {
		m[k*8+6] = x86Op{mn: "push", ops: seg[k], inv64: true}
		if k != 1 {
			m[k*8+7] = x86Op{mn: "pop", ops: seg[k], inv64: true}
		}
	}
	m[0x27] = x86Op{mn: "daa", inv64: true}
	m[0x2f] = x86Op{mn: "das", inv64: true}
	m[0x37] = x86Op{mn: "aaa", inv64: true}
	m[0x3f] = x86Op{mn: "aas", inv64: true}
	for r := 0; r < 8; r++ {
		m[0x40+r] = x86Op{mn: "inc", ops: "Zv"}
		m[0x48+r] = x86Op{mn: "dec", ops: "Zv"}
		m[0x50+r] = x86Op{mn: "push", ops: "Zv", d64: true}
		m[0x58+r] = x86Op{mn: "pop", ops: "Zv", d64: true}
		m[0x70+r] = x86Op{mn: "j" + ccNames[r], ops: "Jb"}
		m[0x78+r] = x86Op{mn: "j" + ccNames[8+r], ops: "Jb"}
		m[0xb0+r] = x86Op{mn: "mov", ops: "Zb,Ib"}
		m[0xb8+r] = x86Op{mn: "mov", ops: "Zv,Iv"}
		if r > 0 {
			m[0x90+r] = x86Op{mn: "xchg", ops: "Zv,eAX"}
		}
	}
	m[0x60] = x86Op{mn: "pushad", inv64: true}
	m[0x61] = x86Op{mn: "popad", inv64: true}
	m[0x62] = x86Op{mn: "bound", ops: "Gv,M", modrm: true, inv64: true}
	m[0x63] = x86Op{mn: "arpl", ops: "Ew,Gw", modrm: true}
	m[0x68] = x86Op{mn: "push", ops: "Iz", d64: true}
	m[0x69] = x86Op{mn: "imul", ops: "Gv,Ev,Iz", modrm: true}
	m[0x6a] = x86Op{mn: "push", ops: "Ibs", d64: true}
	m[0x6b] = x86Op{mn: "imul", ops: "Gv,Ev,Ibs", modrm: true}
	m[0x6c] = x86Op{mn: "insb"}
	m[0x6d] = x86Op{mn: "insd"}
	m[0x6e] = x86Op{mn: "outsb"}
	m[0x6f] = x86Op{mn: "outsd"}
	m[0x80] = x86Op{grp: 1, ops: "Eb,Ib", modrm: true}
	m[0x81] = x86Op{grp: 1, ops: "Ev,Iz", modrm: true}
	m[0x82] = x86Op{grp: 1, ops: "Eb,Ib", modrm: true, inv64: true}
	m[0x83] = x86Op{grp: 1, ops: "Ev,Ibs", modrm: true}
	set(0x84, "test", "Eb,Gb", true)
	set(0x85, "test", "Ev,Gv", true)
	set(0x86, "xchg", "Eb,Gb", true)
	set(0x87, "xchg", "Ev,Gv", true)
	set(0x88, "mov", "Eb,Gb", true)
	set(0x89, "mov", "Ev,Gv", true)
	set(0x8a, "mov", "Gb,Eb", true)
	set(0x8b, "mov", "Gv,Ev", true)
	set(0x8c, "mov", "Ev,Sw", true)
	set(0x8d, "lea", "Gv,M", true)
	set(0x8e, "mov", "Sw,Ew", true)
	m[0x8f] = x86Op{mn: "pop", ops: "Ev", modrm: true, d64: true}
	m[0x90] = x86Op{mn: "nop"}
	m[0x98] = x86Op{mn: "cwde"}
	m[0x99] = x86Op{mn: "cdq"}
	m[0x9a] = x86Op{mn: "call", ops: "Ap", inv64: true}
	m[0x9b] = x86Op{mn: "fwait"}
	m[0x9c] = x86Op{mn: "pushfd", d64: true}
	m[0x9d] = x86Op{mn: "popfd", d64: true}
	m[0x9e] = x86Op{mn: "sahf"}
	m[0x9f] = x86Op{mn: "lahf"}
	m[0xa0] = x86Op{mn: "mov", ops: "AL,Ob"}
	m[0xa1] = x86Op{mn: "mov", ops: "eAX,Ov"}
	m[0xa2] = x86Op{mn: "mov", ops: "Ob,AL"}
	m[0xa3] = x86Op{mn: "mov", ops: "Ov,eAX"}
	for i, s := range []string{"movsb", "movsd", "cmpsb", "cmpsd"} {
		m[0xa4+i] = x86Op{mn: s}
	}
	m[0xa8] = x86Op{mn: "test", ops: "AL,Ib"}
	m[0xa9] = x86Op{mn: "test", ops: "eAX,Iz"}
	for i, s := range []string{"stosb", "stosd", "lodsb", "lodsd", "scasb", "scasd"} {
		m[0xaa+i] = x86Op{mn: s}
	}
	m[0xc0] = x86Op{grp: 2, ops: "Eb,Ib", modrm: true}
	m[0xc1] = x86Op{grp: 2, ops: "Ev,Ib", modrm: true}
	m[0xc2] = x86Op{mn: "ret", ops: "Iw"}
	m[0xc3] = x86Op{mn: "ret"}
	m[0xc4] = x86Op{mn: "les", ops: "Gv,M", modrm: true, inv64: true}
	m[0xc5] = x86Op{mn: "lds", ops: "Gv,M", modrm: true, inv64: true}
	m[0xc6] = x86Op{grp: 11, mn: "mov", ops: "Eb,Ib", modrm: true}
	m[0xc7] = x86Op{grp: 11, mn: "mov", ops: "Ev,Iz", modrm: true}
	m[0xc8] = x86Op{mn: "enter", ops: "Iw,Ib"}
	m[0xc9] = x86Op{mn: "leave", d64: true}
	m[0xca] = x86Op{mn: "retf", ops: "Iw"}
	m[0xcb] = x86Op{mn: "retf"}
	m[0xcc] = x86Op{mn: "int3"}
	m[0xcd] = x86Op{mn: "int", ops: "Ib"}
	m[0xce] = x86Op{mn: "into", inv64: true}
	m[0xcf] = x86Op{mn: "iretd"}
	m[0xd0] = x86Op{grp: 2, ops: "Eb,1", modrm: true}
	m[0xd1] = x86Op{grp: 2, ops: "Ev,1", modrm: true}
	m[0xd2] = x86Op{grp: 2, ops: "Eb,CL", modrm: true}
	m[0xd3] = x86Op{grp: 2, ops: "Ev,CL", modrm: true}
	m[0xd4] = x86Op{mn: "aam", ops: "Ib", inv64: true}
	m[0xd5] = x86Op{mn: "aad", ops: "Ib", inv64: true}
	m[0xd6] = x86Op{mn: "salc", inv64: true}
	m[0xd7] = x86Op{mn: "xlatb"}
	for i := 0xd8; i <= 0xdf; i++ {
		m[i] = x86Op{mn: "fpu", modrm: true}
	}
	m[0xe0] = x86Op{mn: "loopne", ops: "Jb"}
	m[0xe1] = x86Op{mn: "loope", ops: "Jb"}
	m[0xe2] = x86Op{mn: "loop", ops: "Jb"}
	m[0xe3] = x86Op{mn: "jecxz", ops: "Jb"}
	m[0xe4] = x86Op{mn: "in", ops: "AL,Ib"}
	m[0xe5] = x86Op{mn: "in", ops: "eAX,Ib"}
	m[0xe6] = x86Op{mn: "out", ops: "Ib,AL"}
	m[0xe7] = x86Op{mn: "out", ops: "Ib,eAX"}
	m[0xe8] = x86Op{mn: "call", ops: "Jz", d64: true}
	m[0xe9] = x86Op{mn: "jmp", ops: "Jz", d64: true}
	m[0xea] = x86Op{mn: "jmp", ops: "Ap", inv64: true}
	m[0xeb] = x86Op{mn: "jmp", ops: "Jb"}
	m[0xec] = x86Op{mn: "in", ops: "AL,DX"}
	m[0xed] = x86Op{mn: "in", ops: "eAX,DX"}
	m[0xee] = x86Op{mn: "out", ops: "DX,AL"}
	m[0xef] = x86Op{mn: "out", ops: "DX,eAX"}
	m[0xf1] = x86Op{mn: "int1"}
	m[0xf4] = x86Op{mn: "hlt"}
	m[0xf5] = x86Op{mn: "cmc"}
	m[0xf6] = x86Op{grp: 3, ops: "Eb", modrm: true}
	m[0xf7] = x86Op{grp: 3, ops: "Ev", modrm: true}
	for i, s := range []string{"clc", "stc", "cli", "sti", "cld", "std"} {
		m[0xf8+i] = x86Op{mn: s}
	}
	m[0xfe] = x86Op{grp: 4, ops: "Eb", modrm: true}
	m[0xff] = x86Op{grp: 5, ops: "Ev", modrm: true}

	// ---- 0F two-byte map: modrm by default, then the exceptions ----
	t := &x86Map2
	for i := range t {
		t[i] = x86Op{mn: "", modrm: true}
	}
	noModrm := map[int]string{0x05: "syscall", 0x06: "clts", 0x07: "sysret", 0x08: "invd", 0x09: "wbinvd",
		0x0b: "ud2", 0x0e: "femms", 0x30: "wrmsr", 0x31: "rdtsc", 0x32: "rdmsr", 0x33: "rdpmc", 0x34: "sysenter",
		0x35: "sysexit", 0x37: "getsec", 0x77: "emms", 0xa2: "cpuid", 0xaa: "rsm"}
	for op, mn := range noModrm {
		t[op] = x86Op{mn: mn}
	}
	t[0xa0] = x86Op{mn: "push", ops: "fs", d64: true}
	t[0xa1] = x86Op{mn: "pop", ops: "fs", d64: true}
	t[0xa8] = x86Op{mn: "push", ops: "gs", d64: true}
	t[0xa9] = x86Op{mn: "pop", ops: "gs", d64: true}
	for r := 0; r < 16; r++ {
		t[0x80+r] = x86Op{mn: "j" + ccNames[r], ops: "Jz", d64: true}
		t[0x90+r] = x86Op{mn: "set" + ccNames[r], ops: "Eb", modrm: true}
		t[0x40+r] = x86Op{mn: "cmov" + ccNames[r], ops: "Gv,Ev", modrm: true}
	}
	for r := 0; r < 8; r++ {
		t[0xc8+r] = x86Op{mn: "bswap", ops: "Zv"}
	}
	named := map[int][2]string{
		0x00: {"grp6", "Ew"}, 0x01: {"grp7", "M"}, 0x02: {"lar", "Gv,Ew"}, 0x03: {"lsl", "Gv,Ew"},
		0x0d: {"prefetch", "M"}, 0x18: {"prefetch", "M"}, 0x1f: {"nop", "Ev"},
		0x10: {"movups", "V,W"}, 0x11: {"movups", "W,V"}, 0x12: {"movlps", "V,W"}, 0x13: {"movlps", "W,V"},
		0x14: {"unpcklps", "V,W"}, 0x15: {"unpckhps", "V,W"}, 0x16: {"movhps", "V,W"}, 0x17: {"movhps", "W,V"},
		0x20: {"mov", "Rd,Cd"}, 0x21: {"mov", "Rd,Dd"}, 0x22: {"mov", "Cd,Rd"}, 0x23: {"mov", "Dd,Rd"},
		0x28: {"movaps", "V,W"}, 0x29: {"movaps", "W,V"}, 0x2a: {"cvtpi2ps", "V,W"}, 0x2b: {"movntps", "W,V"},
		0x2c: {"cvttps2pi", "V,W"}, 0x2d: {"cvtps2pi", "V,W"}, 0x2e: {"ucomiss", "V,W"}, 0x2f: {"comiss", "V,W"},
		0x50: {"movmskps", "Gv,W"}, 0x51: {"sqrtps", "V,W"}, 0x52: {"rsqrtps", "V,W"}, 0x53: {"rcpps", "V,W"},
		0x54: {"andps", "V,W"}, 0x55: {"andnps", "V,W"}, 0x56: {"orps", "V,W"}, 0x57: {"xorps", "V,W"},
		0x58: {"addps", "V,W"}, 0x59: {"mulps", "V,W"}, 0x5a: {"cvtps2pd", "V,W"}, 0x5b: {"cvtdq2ps", "V,W"},
		0x5c: {"subps", "V,W"}, 0x5d: {"minps", "V,W"}, 0x5e: {"divps", "V,W"}, 0x5f: {"maxps", "V,W"},
		0x60: {"punpcklbw", "V,W"}, 0x61: {"punpcklwd", "V,W"}, 0x62: {"punpckldq", "V,W"}, 0x63: {"packsswb", "V,W"},
		0x64: {"pcmpgtb", "V,W"}, 0x65: {"pcmpgtw", "V,W"}, 0x66: {"pcmpgtd", "V,W"}, 0x67: {"packuswb", "V,W"},
		0x68: {"punpckhbw", "V,W"}, 0x69: {"punpckhwd", "V,W"}, 0x6a: {"punpckhdq", "V,W"}, 0x6b: {"packssdw", "V,W"},
		0x6c: {"punpcklqdq", "V,W"}, 0x6d: {"punpckhqdq", "V,W"}, 0x6e: {"movd", "V,Ev"}, 0x6f: {"movq", "V,W"},
		0x74: {"pcmpeqb", "V,W"}, 0x75: {"pcmpeqw", "V,W"}, 0x76: {"pcmpeqd", "V,W"},
		0x7e: {"movd", "Ev,V"}, 0x7f: {"movq", "W,V"},
		0xa3: {"bt", "Ev,Gv"}, 0xa5: {"shld", "Ev,Gv,CL"}, 0xab: {"bts", "Ev,Gv"}, 0xad: {"shrd", "Ev,Gv,CL"},
		0xae: {"grp15", "M"}, 0xaf: {"imul", "Gv,Ev"}, 0xb0: {"cmpxchg", "Eb,Gb"}, 0xb1: {"cmpxchg", "Ev,Gv"},
		0xb2: {"lss", "Gv,M"}, 0xb3: {"btr", "Ev,Gv"}, 0xb4: {"lfs", "Gv,M"}, 0xb5: {"lgs", "Gv,M"},
		0xb6: {"movzx", "Gv,Eb"}, 0xb7: {"movzx", "Gv,Ew"}, 0xb8: {"jmpe", ""}, 0xb9: {"ud1", "Gv,Ev"},
		0xbb: {"btc", "Ev,Gv"}, 0xbc: {"bsf", "Gv,Ev"}, 0xbd: {"bsr", "Gv,Ev"}, 0xbe: {"movsx", "Gv,Eb"},
		0xbf: {"movsx", "Gv,Ew"}, 0xc0: {"xadd", "Eb,Gb"}, 0xc1: {"xadd", "Ev,Gv"}, 0xc3: {"movnti", "M,Gv"},
		0xc7: {"grp9", "M"}, 0xd4: {"paddq", "V,W"}, 0xd5: {"pmullw", "V,W"}, 0xd7: {"pmovmskb", "Gv,W"},
		0xdb: {"pand", "V,W"}, 0xdf: {"pandn", "V,W"}, 0xe7: {"movntq", "W,V"}, 0xeb: {"por", "V,W"},
		0xef: {"pxor", "V,W"}, 0xfa: {"psubd", "V,W"}, 0xfb: {"psubq", "V,W"}, 0xfc: {"paddb", "V,W"},
		0xfd: {"paddw", "V,W"}, 0xfe: {"paddd", "V,W"},
	}
	for op, v := range named {
		t[op] = x86Op{mn: v[0], ops: v[1], modrm: true}
	}
	// opcodes that carry an imm8 after ModRM
	for _, op := range []int{0x70, 0x71, 0x72, 0x73, 0xa4, 0xac, 0xba, 0xc2, 0xc4, 0xc5, 0xc6} {
		t[op].ops += ",Ib"
		if strings.HasPrefix(t[op].ops, ",") {
			t[op].ops = "V,W,Ib"
		}
	}
	t[0x70].mn, t[0xa4].mn, t[0xac].mn, t[0xba].mn = "pshufw", "shld", "shrd", "grp8"
	t[0xa4].ops, t[0xac].ops, t[0xba].ops = "Ev,Gv,Ib", "Ev,Gv,Ib", "Ev,Ib"
	t[0xc2].mn, t[0xc4].mn, t[0xc5].mn, t[0xc6].mn = "cmpps", "pinsrw", "pextrw", "shufps"
	t[0x71].mn, t[0x72].mn, t[0x73].mn = "psxw", "psxd", "psxq"
	t[0x71].ops, t[0x72].ops, t[0x73].ops = "W,Ib", "W,Ib", "W,Ib"
}

type x86Dec struct {
	code             []byte
	pos              int
	bits             int
	base             uint64
	start            int
	opsz, adsz       int
	rex              byte
	seg              string
	rep, repne, lock bool
	opPfx, adPfx     bool
	modrm            byte
	haveModRM        bool
	mod, reg, rm     int
	memStr           string // rendered r/m memory operand (without size)
	ripTarget        uint64
	hasRip           bool
	ripDispOff       int // offset of disp32 within instruction (for RIP fix-up after imm)
	truncated        bool
}

func (d *x86Dec) u8() byte {
	if d.pos >= len(d.code) {
		d.truncated = true
		d.pos++
		return 0
	}
	b := d.code[d.pos]
	d.pos++
	return b
}
func (d *x86Dec) imm(n int) int64 {
	var v uint64
	for i := 0; i < n; i++ {
		v |= uint64(d.u8()) << (8 * i)
	}
	switch n { // sign-extend
	case 1:
		return int64(int8(v))
	case 2:
		return int64(int16(v))
	case 4:
		return int64(int32(v))
	}
	return int64(v)
}

var x86RegsByte = []string{"al", "cl", "dl", "bl", "ah", "ch", "dh", "bh"}
var x86RegsByteRex = []string{"al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil"}
var x86Seg = []string{"es", "cs", "ss", "ds", "fs", "gs", "?", "?"}

func (d *x86Dec) gpr(n, size int) string {
	switch size {
	case 8:
		if n >= 8 {
			return fmt.Sprintf("r%db", n)
		}
		if d.rex != 0 {
			return x86RegsByteRex[n]
		}
		return x86RegsByte[n]
	case 16:
		if n >= 8 {
			return fmt.Sprintf("r%dw", n)
		}
		return x86Reg16[n]
	case 32:
		if n >= 8 {
			return fmt.Sprintf("r%dd", n)
		}
		return x86Reg32[n]
	}
	return x86Reg64[n&15]
}

func hexs(v int64) string {
	if v < 0 {
		return fmt.Sprintf("-0x%x", uint64(-v))
	}
	return fmt.Sprintf("0x%x", v)
}

// readModRM consumes ModRM (+SIB, +displacement) and renders the r/m operand.
func (d *x86Dec) readModRM() {
	d.modrm = d.u8()
	d.haveModRM = true
	d.mod = int(d.modrm >> 6)
	d.reg = int((d.modrm>>3)&7) | int(d.rex>>2&1)<<3
	d.rm = int(d.modrm & 7)
	if d.mod == 3 {
		d.rm |= int(d.rex&1) << 3
		return
	}
	var parts []string
	var disp int64
	if d.adsz == 16 {
		tbl := []string{"bx+si", "bx+di", "bp+si", "bp+di", "si", "di", "bp", "bx"}
		switch {
		case d.mod == 0 && d.rm == 6:
			disp = d.imm(2)
		default:
			parts = append(parts, tbl[d.rm])
			if d.mod == 1 {
				disp = d.imm(1)
			} else if d.mod == 2 {
				disp = d.imm(2)
			}
		}
	} else {
		areg := func(n int) string {
			if d.adsz == 32 {
				return d.gpr(n, 32)
			}
			return d.gpr(n, 64)
		}
		rm := d.rm
		if rm == 4 { // SIB
			sib := d.u8()
			scale := 1 << (sib >> 6)
			idx := int((sib>>3)&7) | int(d.rex>>1&1)<<3
			base := int(sib&7) | int(d.rex&1)<<3
			if (sib&7) == 5 && d.mod == 0 {
				disp = d.imm(4)
			} else {
				parts = append(parts, areg(base))
			}
			if idx != 4 {
				s := areg(idx)
				if scale > 1 {
					s += fmt.Sprintf("*%d", scale)
				}
				parts = append(parts, s)
			}
		} else if rm == 5 && d.mod == 0 {
			d.ripDispOff = d.pos - d.start
			disp = d.imm(4)
			if d.bits == 64 {
				parts = append(parts, map[bool]string{true: "eip", false: "rip"}[d.adsz == 32])
				d.hasRip = true
				d.ripTarget = uint64(disp) // fixed up once the full length is known
			}
		} else {
			parts = append(parts, areg(rm|int(d.rex&1)<<3))
		}
		if d.mod == 1 {
			disp = d.imm(1)
		} else if d.mod == 2 {
			disp = d.imm(4)
		}
	}
	s := strings.Join(parts, "+")
	switch {
	case s == "":
		s = fmt.Sprintf("0x%x", uint64(disp)&0xffffffff)
	case disp != 0:
		if disp < 0 {
			s += "-" + hexs(-disp)
		} else {
			s += "+" + hexs(disp)
		}
	}
	seg := ""
	if d.seg != "" {
		seg = d.seg + ":"
	}
	d.memStr = seg + "[" + s + "]"
}

func ptrName(size int) string {
	switch size {
	case 8:
		return "byte ptr "
	case 16:
		return "word ptr "
	case 32:
		return "dword ptr "
	case 64:
		return "qword ptr "
	}
	return ""
}

// rmOperand renders the ModRM r/m operand at the given size (0 = no size).
func (d *x86Dec) rmOperand(size int, xmm bool) string {
	if d.mod == 3 {
		if xmm {
			return fmt.Sprintf("xmm%d", d.rm)
		}
		if size == 0 {
			size = d.opsz
		}
		return d.gpr(d.rm, size)
	}
	return ptrName(size) + d.memStr
}

// decodeX86 decodes one instruction at code[off:].
func decodeX86(code []byte, off int, base uint64, bits int) Insn {
	d := &x86Dec{code: code, pos: off, start: off, bits: bits, base: base}
	d.opsz, d.adsz = 32, bits
	if bits == 16 {
		d.opsz = 16
	}
	// ---- prefixes (max 14 + opcode = 15 bytes) ----
	for d.pos < len(code) && d.pos-off < 14 {
		b := code[d.pos]
		switch b {
		case 0xf0:
			d.lock = true
		case 0xf2:
			d.repne = true
		case 0xf3:
			d.rep = true
		case 0x2e, 0x36, 0x3e, 0x26, 0x64, 0x65:
			d.seg = map[byte]string{0x26: "es", 0x2e: "cs", 0x36: "ss", 0x3e: "ds", 0x64: "fs", 0x65: "gs"}[b]
		case 0x66:
			d.opPfx = true
		case 0x67:
			d.adPfx = true
		default:
			goto prefixDone
		}
		d.rex = 0 // a legacy prefix after REX cancels the REX
		d.pos++
	}
prefixDone:
	if bits == 64 && d.pos < len(code) && code[d.pos]&0xf0 == 0x40 {
		d.rex = code[d.pos]
		d.pos++
	}
	rexW := d.rex&8 != 0
	if d.opPfx {
		d.opsz = 16
	}
	if rexW {
		d.opsz = 64
	}
	if d.adPfx {
		if bits == 64 {
			d.adsz = 32
		} else {
			d.adsz = 16
		}
	}
	in := Insn{Offset: base + uint64(off), Flow: "next"}
	finish := func(mn, ops string) Insn {
		if d.truncated || d.pos-off > 15 {
			return x86Invalid(code, off, base, "truncated")
		}
		if d.hasRip {
			d.ripTarget = base + uint64(d.pos) + d.ripTarget
			in.MemRef, in.HasMemRef = d.ripTarget, true
			if in.Comment == "" {
				in.Comment = fmt.Sprintf("0x%x", d.ripTarget)
			}
		}
		pfx := ""
		if d.lock {
			pfx = "lock "
		}
		if d.rep && (strings.HasPrefix(mn, "movs") || strings.HasPrefix(mn, "stos") || strings.HasPrefix(mn, "lods") || strings.HasPrefix(mn, "ins") || strings.HasPrefix(mn, "outs")) {
			pfx += "rep "
		} else if (d.rep || d.repne) && (strings.HasPrefix(mn, "cmps") || strings.HasPrefix(mn, "scas")) {
			pfx += map[bool]string{true: "repne ", false: "repe "}[d.repne]
		}
		in.Mnemonic = pfx + mn
		in.Operands = ops
		in.Size = d.pos - off
		in.Bytes = append([]byte{}, code[off:d.pos]...)
		return in
	}
	if d.pos >= len(code) {
		return x86Invalid(code, off, base, "prefix only")
	}
	op := d.u8()
	var e x86Op
	twoByte := false
	lo := op // opcode byte whose low 3 bits encode a register (Zb/Zv forms)
	switch {
	case op == 0x0f:
		twoByte = true
		op2 := d.u8()
		lo = op2
		switch op2 {
		case 0x38: // three-byte map 0F 38: ModRM, no imm
			op3 := d.u8()
			d.readModRM()
			return finish(fmt.Sprintf("0f38.%02x", op3), fmt.Sprintf("xmm%d, %s", d.reg, d.rmOperand(0, true)))
		case 0x3a: // 0F 3A: ModRM + imm8
			op3 := d.u8()
			d.readModRM()
			ib := d.imm(1)
			return finish(fmt.Sprintf("0f3a.%02x", op3), fmt.Sprintf("xmm%d, %s, %s", d.reg, d.rmOperand(0, true), hexs(ib&0xff)))
		case 0x0f: // 3DNow!: ModRM + suffix opcode byte
			d.readModRM()
			d.u8()
			return finish("3dnow", fmt.Sprintf("mm%d, %s", d.reg&7, d.rmOperand(0, false)))
		case 0x1e:
			if d.rep && d.pos < len(code) && (code[d.pos] == 0xfa || code[d.pos] == 0xfb) {
				m := map[byte]string{0xfa: "endbr64", 0xfb: "endbr32"}[code[d.pos]]
				d.pos++
				d.rep = false
				return finish(m, "")
			}
		}
		e = x86Map2[op2]
		// mandatory-prefix variants of the commonest SSE / bit-count opcodes
		switch {
		case d.rep && op2 == 0xb8:
			e.mn, d.rep = "popcnt", false
		case d.rep && op2 == 0xbc:
			e.mn, d.rep = "tzcnt", false
		case d.rep && op2 == 0xbd:
			e.mn, d.rep = "lzcnt", false
		case d.rep && (op2 == 0x10 || op2 == 0x11):
			e.mn, d.rep = "movss", false
		case d.repne && (op2 == 0x10 || op2 == 0x11):
			e.mn, d.repne = "movsd", false
		case d.opPfx && op2 == 0x6f, d.opPfx && op2 == 0x7f:
			e.mn = "movdqa"
		case d.rep && (op2 == 0x6f || op2 == 0x7f):
			e.mn, d.rep = "movdqu", false
		}
		if op2 >= 0x10 && op2 <= 0x17 || op2 >= 0x28 && op2 <= 0x2f || op2 >= 0x50 && op2 <= 0x7f || op2 >= 0xc2 && op2 <= 0xc6 || op2 >= 0xd0 {
			if d.opPfx {
				d.opsz = 32 // 66 selects the SSE form, not a 16-bit operand
			}
		}
		if e.mn == "" {
			e.mn = fmt.Sprintf("0f.%02x", op2)
			if !e.modrm {
				e.modrm = true
			}
		}
	case (op == 0xc4 || op == 0xc5) && (bits == 64 || (d.pos < len(code) && code[d.pos]>>6 == 3)):
		return decodeVEX(d, op, finish)
	case op == 0x62 && (bits == 64 || (d.pos < len(code) && code[d.pos]>>6 == 3)):
		return decodeEVEX(d, finish)
	default:
		e = x86Map1[op]
		if bits == 64 && e.inv64 {
			return x86Invalid(code, off, base, "invalid in 64-bit mode")
		}
		if bits == 64 && op == 0x63 {
			e = x86Op{mn: "movsxd", ops: "Gv,Ed", modrm: true}
		}
		if op == 0x90 && d.rex&1 != 0 {
			e = x86Op{mn: "xchg", ops: "Zv,eAX"}
		} else if op == 0x90 && d.rep {
			e.mn, d.rep = "pause", false
		}
		if op == 0x98 || op == 0x99 {
			e.mn = map[int][2]string{16: {"cbw", "cwd"}, 32: {"cwde", "cdq"}, 64: {"cdqe", "cqo"}}[d.opsz][op-0x98]
		}
	}
	if bits == 64 && e.d64 && !d.opPfx {
		d.opsz = 64
	}
	if e.mn == "" && e.grp == 0 {
		return x86Invalid(code, off, base, "undefined opcode")
	}
	if e.modrm {
		d.readModRM()
	}
	mn := e.mn
	ops := e.ops
	switch e.grp {
	case 1:
		mn = aluNames[d.reg&7]
	case 2:
		mn = grp2Names[d.reg&7]
	case 3:
		mn = grp3Names[d.reg&7]
		if d.reg&7 < 2 {
			if op == 0xf6 {
				ops += ",Ib"
			} else {
				ops += ",Iz"
			}
		}
	case 4:
		if d.reg&7 > 1 {
			return x86Invalid(code, off, base, "invalid FE group")
		}
		mn = []string{"inc", "dec"}[d.reg&7]
	case 5:
		r := d.reg & 7
		mn = []string{"inc", "dec", "call", "call far", "jmp", "jmp far", "push", ""}[r]
		if mn == "" {
			return x86Invalid(code, off, base, "invalid FF group")
		}
		if bits == 64 && (r == 2 || r == 4 || r == 6) && !d.opPfx {
			d.opsz = 64
		}
		if r == 3 || r == 5 {
			ops = "M"
		}
	case 11:
		switch {
		case d.reg&7 == 0:
		case d.reg&7 == 7 && d.modrm == 0xf8: // TSX: C6 F8 ib xabort / C7 F8 cd xbegin
			if op == 0xc6 {
				mn, ops = "xabort", "Ib"
			} else {
				mn, ops = "xbegin", "Jz"
			}
		default:
			return x86Invalid(code, off, base, "invalid mov group")
		}
	}
	if twoByte && op == 0x0f {
		// keep group names readable for the 0F groups
		switch e.mn {
		case "grp6":
			mn = []string{"sldt", "str", "lldt", "ltr", "verr", "verw", "0f00", "0f00"}[d.reg&7]
		case "grp7":
			if d.mod == 3 {
				mn = fmt.Sprintf("0f01.%02x", d.modrm)
				switch d.modrm {
				case 0xd0:
					mn = "xgetbv"
				case 0xf8:
					mn = "swapgs"
				case 0xf9:
					mn = "rdtscp"
				case 0xc1:
					mn = "vmcall"
				}
				ops = ""
			} else {
				mn = []string{"sgdt", "sidt", "lgdt", "lidt", "smsw", "0f01", "lmsw", "invlpg"}[d.reg&7]
			}
		case "grp8":
			mn = []string{"0fba", "0fba", "0fba", "0fba", "bt", "bts", "btr", "btc"}[d.reg&7]
		case "grp9":
			mn = "cmpxchg8b"
			if rexW {
				mn = "cmpxchg16b"
			}
			if d.mod == 3 {
				mn = map[int]string{6: "rdrand", 7: "rdseed"}[d.reg&7]
				if mn == "" {
					mn = "0fc7"
				}
				ops = "Ev"
			}
		case "grp15":
			if d.mod == 3 {
				mn = map[int]string{5: "lfence", 6: "mfence", 7: "sfence"}[d.reg&7]
				ops = ""
				if mn == "" {
					mn = "0fae"
				}
			} else {
				mn = []string{"fxsave", "fxrstor", "ldmxcsr", "stmxcsr", "xsave", "xrstor", "xsaveopt", "clflush"}[d.reg&7]
			}
		}
	}
	if op >= 0xd8 && op <= 0xdf && !twoByte {
		mn, ops = x87Name(op, d)
	}
	// ---- operands ----
	var out []string
	for _, tok := range strings.Split(ops, ",") {
		if tok == "" {
			continue
		}
		s := ""
		switch tok {
		case "Eb":
			s = d.rmOperand(8, false)
		case "Ew":
			s = d.rmOperand(16, false)
		case "Ed":
			s = d.rmOperand(32, false)
		case "Ev":
			s = d.rmOperand(d.opsz, false)
		case "M":
			s = d.rmOperand(0, false)
			if mn != "lea" && d.mod != 3 {
				s = d.memStr
			}
		case "Gb":
			s = d.gpr(d.reg, 8)
		case "Gw":
			s = d.gpr(d.reg, 16)
		case "Gv", "Gz":
			s = d.gpr(d.reg, d.opsz)
		case "V":
			s = fmt.Sprintf("xmm%d", d.reg)
		case "W":
			s = d.rmOperand(0, true)
		case "Rd":
			s = d.gpr(d.rm, map[bool]int{true: 64, false: 32}[bits == 64])
		case "Cd":
			s = fmt.Sprintf("cr%d", d.reg)
		case "Dd":
			s = fmt.Sprintf("dr%d", d.reg)
		case "Sw":
			s = x86Seg[d.reg&7]
		case "AL":
			s = "al"
		case "CL":
			s = "cl"
		case "DX":
			s = "dx"
		case "1":
			s = "1"
		case "eAX":
			s = d.gpr(0, d.opsz)
		case "Zb":
			s = d.gpr(int(lo&7)|int(d.rex&1)<<3, 8)
		case "Zv":
			s = d.gpr(int(lo&7)|int(d.rex&1)<<3, d.opsz)
		case "Ib":
			s = hexs(d.imm(1) & 0xff)
		case "Ibs":
			s = hexs(d.imm(1))
		case "Iw":
			s = hexs(d.imm(2) & 0xffff)
		case "Iz":
			if d.opsz == 16 {
				s = hexs(d.imm(2))
			} else {
				s = hexs(d.imm(4))
			}
		case "Iv":
			switch d.opsz {
			case 16:
				s = hexs(d.imm(2) & 0xffff)
			case 64:
				s = fmt.Sprintf("0x%x", uint64(d.imm(8)))
			default:
				s = hexs(d.imm(4) & 0xffffffff)
			}
		case "Jb", "Jz":
			var rel int64
			if tok == "Jb" {
				rel = d.imm(1)
			} else if d.opsz == 16 && bits != 64 {
				rel = d.imm(2)
			} else {
				rel = d.imm(4)
			}
			tgt := uint64(int64(base) + int64(d.pos) + rel)
			if bits == 32 {
				tgt &= 0xffffffff
			}
			in.Target, in.HasTarget = tgt, true
			s = fmt.Sprintf("0x%x", tgt)
		case "Ob", "Ov":
			n := d.adsz / 8
			a := uint64(d.imm(n))
			if n < 8 {
				a &= (1 << (8 * uint(n))) - 1
			}
			sz := 8
			if tok == "Ov" {
				sz = d.opsz
			}
			seg := ""
			if d.seg != "" {
				seg = d.seg + ":"
			}
			s = fmt.Sprintf("%s%s[0x%x]", ptrName(sz), seg, a)
		case "Ap":
			var o int64
			if d.opsz == 16 {
				o = d.imm(2) & 0xffff
			} else {
				o = d.imm(4) & 0xffffffff
			}
			sel := d.imm(2) & 0xffff
			s = fmt.Sprintf("0x%x:0x%x", sel, o)
		default:
			s = tok // literal register such as es / fs
		}
		out = append(out, s)
	}
	// ---- control flow ----
	switch {
	case mn == "ret" || mn == "retf" || mn == "iretd":
		in.Flow = "ret"
	case mn == "call" || mn == "call far":
		in.Flow = "call"
	case mn == "jmp" || mn == "jmp far":
		in.Flow = "branch"
	case strings.HasPrefix(mn, "loop") || mn == "jecxz" || (len(mn) <= 3 && mn[0] == 'j' && in.HasTarget):
		in.Flow = "cbranch"
	case mn == "xbegin":
		in.Flow = "cbranch" // falls through, or resumes at the abort handler
	case mn == "syscall" || mn == "sysenter" || mn == "int":
		in.Flow = "syscall"
	case mn == "hlt" || mn == "ud2":
		in.Flow = "stop"
	}
	if mn == "jecxz" && bits == 64 {
		mn = "jrcxz"
	}
	if (mn == "pushfd" || mn == "popfd") && d.opsz == 64 {
		mn = strings.TrimSuffix(mn, "d") + "q"
	}
	if (in.Flow == "call" || in.Flow == "branch") && !in.HasTarget {
		in.Comment = "indirect"
	}
	return finish(mn, strings.Join(out, ", "))
}

func x86Invalid(code []byte, off int, base uint64, why string) Insn {
	return Insn{Offset: base + uint64(off), Size: 1, Bytes: []byte{code[off]}, Mnemonic: "(bad)",
		Operands: fmt.Sprintf("0x%02x", code[off]), Flow: "invalid", Comment: why}
}

// decodeVEX handles C4/C5 VEX prefixes: exact length, generic v-mnemonic.
func decodeVEX(d *x86Dec, op byte, finish func(string, string) Insn) Insn {
	mapSel := 1
	var vvvv int
	l := 0
	if op == 0xc5 {
		p := d.u8()
		d.rex = 0x40 | (^p>>5)&4
		vvvv = int(^p>>3) & 15
		l = int(p>>2) & 1
	} else {
		p1, p2 := d.u8(), d.u8()
		d.rex = 0x40 | (^p1>>5)&7 | (p2>>4)&8
		mapSel = int(p1 & 31)
		vvvv = int(^p2>>3) & 15
		l = int(p2>>2) & 1
	}
	opc := d.u8()
	if op == 0xc5 && opc == 0x77 {
		return finish(map[int]string{0: "vzeroupper", 1: "vzeroall"}[l], "")
	}
	d.readModRM()
	if mapSel == 3 || (mapSel == 1 && (opc >= 0x70 && opc <= 0x73 || opc >= 0xc2 && opc <= 0xc6)) {
		d.u8()
	}
	reg := "xmm"
	if l == 1 {
		reg = "ymm"
	}
	mn := fmt.Sprintf("vex.%s.%02x", []string{"?", "0f", "0f38", "0f3a"}[mapSel&3], opc)
	if mapSel == 1 && x86Map2[opc].mn != "" && !strings.HasPrefix(x86Map2[opc].mn, "grp") {
		mn = "v" + x86Map2[opc].mn
	}
	rmS := d.memStr
	if d.mod == 3 {
		rmS = fmt.Sprintf("%s%d", reg, d.rm)
	}
	return finish(mn, fmt.Sprintf("%s%d, %s%d, %s", reg, d.reg, reg, vvvv, rmS))
}

// decodeEVEX handles 62 (AVX-512) prefixes: exact length, generic mnemonic.
func decodeEVEX(d *x86Dec, finish func(string, string) Insn) Insn {
	p0 := d.u8()
	d.u8()
	d.u8()
	mapSel := int(p0 & 7)
	d.rex = 0x40 | (^p0>>5)&7
	opc := d.u8()
	d.readModRM()
	if mapSel == 3 || (mapSel == 1 && (opc >= 0x70 && opc <= 0x73 || opc >= 0xc2 && opc <= 0xc6)) {
		d.u8()
	}
	return finish(fmt.Sprintf("evex.m%d.%02x", mapSel, opc), "zmm, "+d.rmOperand(0, true))
}

var x87Mem = [8][8]string{
	{"fadd", "fmul", "fcom", "fcomp", "fsub", "fsubr", "fdiv", "fdivr"},
	{"fld", "(bad)", "fst", "fstp", "fldenv", "fldcw", "fnstenv", "fnstcw"},
	{"fiadd", "fimul", "ficom", "ficomp", "fisub", "fisubr", "fidiv", "fidivr"},
	{"fild", "fisttp", "fist", "fistp", "(bad)", "fld", "(bad)", "fstp"},
	{"fadd", "fmul", "fcom", "fcomp", "fsub", "fsubr", "fdiv", "fdivr"},
	{"fld", "fisttp", "fst", "fstp", "frstor", "(bad)", "fnsave", "fnstsw"},
	{"fiadd", "fimul", "ficom", "ficomp", "fisub", "fisubr", "fidiv", "fidivr"},
	{"fild", "fisttp", "fist", "fistp", "fbld", "fild", "fbstp", "fistp"},
}
var x87MemSize = [8]int{32, 32, 32, 32, 64, 64, 16, 16}

func x87Name(op byte, d *x86Dec) (string, string) {
	e := int(op - 0xd8)
	r := d.reg & 7
	if d.mod != 3 {
		sz := x87MemSize[e]
		if (e == 1 && r >= 4) || (e == 5 && r >= 4) {
			sz = 0 // environment / state / control-word forms
		}
		if (e == 3 && (r == 5 || r == 7)) || (e == 7 && (r == 5 || r == 7)) {
			sz = 80
		}
		ps := ptrName(sz)
		if sz == 80 {
			ps = "tbyte ptr "
		}
		return x87Mem[e][r], ps + d.memStr
	}
	i := d.rm & 7
	st := fmt.Sprintf("st(%d)", i)
	switch op {
	case 0xd8, 0xdc:
		return x87Mem[0][r], "st, " + st
	case 0xd9:
		switch r {
		case 0:
			return "fld", st
		case 1:
			return "fxch", st
		}
		names := map[byte]string{0xd0: "fnop", 0xe0: "fchs", 0xe1: "fabs", 0xe4: "ftst", 0xe5: "fxam",
			0xe8: "fld1", 0xe9: "fldl2t", 0xea: "fldl2e", 0xeb: "fldpi", 0xec: "fldlg2", 0xed: "fldln2", 0xee: "fldz",
			0xf0: "f2xm1", 0xf1: "fyl2x", 0xf2: "fptan", 0xf3: "fpatan", 0xfa: "fsqrt", 0xfc: "frndint", 0xfe: "fsin", 0xff: "fcos"}
		if n, ok := names[d.modrm]; ok {
			return n, ""
		}
	case 0xdb:
		switch d.modrm {
		case 0xe2:
			return "fnclex", ""
		case 0xe3:
			return "fninit", ""
		}
	case 0xdd:
		return []string{"ffree", "(bad)", "fst", "fstp", "fucom", "fucomp", "(bad)", "(bad)"}[r], st
	case 0xde:
		if d.modrm == 0xd9 {
			return "fcompp", ""
		}
		return []string{"faddp", "fmulp", "(bad)", "(bad)", "fsubrp", "fsubp", "fdivrp", "fdivp"}[r], st + ", st"
	case 0xdf:
		if d.modrm == 0xe0 {
			return "fnstsw", "ax"
		}
	}
	return "fpu", fmt.Sprintf("0x%02x 0x%02x", op, d.modrm)
}

func disasmX86Linear(code []byte, base uint64, bits int) []Insn {
	var out []Insn
	for i := 0; i < len(code); {
		in := decodeX86(code, i, base, bits)
		out = append(out, in)
		i += in.Size
	}
	markLeaders(out, base)
	return out
}

// ============================================================================
//  ARM (A32) decoder
// ============================================================================

func armCondStr(c uint32) string {
	if c == 14 {
		return ""
	}
	return strings.ToLower(armCond[c])
}

func armRegList(mask uint32) string {
	var parts []string
	for i := 0; i < 16; {
		if mask&(1<<uint(i)) == 0 {
			i++
			continue
		}
		j := i
		for j+1 < 16 && mask&(1<<uint(j+1)) != 0 {
			j++
		}
		if j-i >= 2 {
			parts = append(parts, armRegs[i]+"-"+armRegs[j])
		} else {
			for k := i; k <= j; k++ {
				parts = append(parts, armRegs[k])
			}
		}
		i = j + 1
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

// armOperand2 renders the shifter operand of a data-processing instruction.
func armOperand2(w uint32) string {
	if w&(1<<25) != 0 {
		rot := (w >> 8) & 0xf * 2
		v := (w&0xff)>>rot | (w&0xff)<<((32-rot)&31)
		if rot == 0 {
			v = w & 0xff
		}
		return fmt.Sprintf("#0x%x", v)
	}
	rm := armRegs[w&0xf]
	typ := (w >> 5) & 3
	if w&(1<<4) != 0 {
		return fmt.Sprintf("%s, %s %s", rm, strings.ToLower(armShifts[typ]), armRegs[(w>>8)&0xf])
	}
	amt := (w >> 7) & 0x1f
	switch {
	case amt == 0 && typ == 0:
		return rm
	case amt == 0 && typ == 3:
		return rm + ", rrx"
	case amt == 0:
		amt = 32
	}
	return fmt.Sprintf("%s, %s #%d", rm, strings.ToLower(armShifts[typ]), amt)
}

func decodeARM(w uint32, addr uint64) Insn {
	in := Insn{Offset: addr, Size: 4, Flow: "next"}
	cond := w >> 28
	cs := armCondStr(cond)
	set := func(mn, ops string) { in.Mnemonic, in.Operands = mn, ops }
	switch {
	case w == 0xe1a00000 || w == 0xe320f000:
		set("nop", "")
	case cond == 15:
		if (w>>25)&7 == 5 { // BLX imm (switches to Thumb)
			off := int64(int32(w<<8)>>6) | int64((w>>24)&1)<<1
			in.Target, in.HasTarget = uint64(int64(addr)+8+off), true
			in.Flow = "call"
			set("blx", fmt.Sprintf("0x%x", in.Target))
		} else {
			set(".inst", fmt.Sprintf("0x%08x", w))
		}
	case w&0x0ffffff0 == 0x012fff10:
		rm := w & 0xf
		set("bx"+cs, armRegs[rm])
		if rm == 14 {
			in.Flow = "ret"
		} else {
			in.Flow, in.Comment = "branch", "indirect"
		}
		if cond != 14 && in.Flow == "branch" {
			in.Flow = "cbranch"
		}
	case w&0x0ffffff0 == 0x012fff30:
		set("blx"+cs, armRegs[w&0xf])
		in.Flow, in.Comment = "call", "indirect"
	case w&0x0fc000f0 == 0x00000090:
		rd, rn, rs, rm := armRegs[(w>>16)&0xf], armRegs[(w>>12)&0xf], armRegs[(w>>8)&0xf], armRegs[w&0xf]
		if w&(1<<21) != 0 {
			set("mla"+cs, fmt.Sprintf("%s, %s, %s, %s", rd, rm, rs, rn))
		} else {
			set("mul"+cs, fmt.Sprintf("%s, %s, %s", rd, rm, rs))
		}
	case w&0x0f8000f0 == 0x00800090:
		names := []string{"umull", "umlal", "smull", "smlal"}
		set(names[(w>>21)&3]+cs, fmt.Sprintf("%s, %s, %s, %s", armRegs[(w>>12)&0xf], armRegs[(w>>16)&0xf], armRegs[w&0xf], armRegs[(w>>8)&0xf]))
	case w&0x0ff00ff0 == 0x01000090 || w&0x0ff00ff0 == 0x01400090:
		set("swp"+map[bool]string{true: "b", false: ""}[w&(1<<22) != 0]+cs, fmt.Sprintf("%s, %s, [%s]", armRegs[(w>>12)&0xf], armRegs[w&0xf], armRegs[(w>>16)&0xf]))
	case w&0x0e000090 == 0x00000090 && w&0x60 != 0: // halfword / signed transfers
		l := w&(1<<20) != 0
		sh := (w >> 5) & 3
		mn := map[bool][]string{true: {"", "ldrh", "ldrsb", "ldrsh"}, false: {"", "strh", "ldrd", "strd"}}[l][sh]
		off := ""
		if w&(1<<22) != 0 {
			imm := (w>>4)&0xf0 | w&0xf
			if imm != 0 {
				off = fmt.Sprintf(", #%s0x%x", map[bool]string{true: "", false: "-"}[w&(1<<23) != 0], imm)
			}
		} else {
			off = ", " + map[bool]string{true: "", false: "-"}[w&(1<<23) != 0] + armRegs[w&0xf]
		}
		set(mn+cs, fmt.Sprintf("%s, [%s%s]", armRegs[(w>>12)&0xf], armRegs[(w>>16)&0xf], off))
	case w&0x0fbf0fff == 0x010f0000:
		set("mrs"+cs, armRegs[(w>>12)&0xf]+", "+map[bool]string{true: "spsr", false: "cpsr"}[w&(1<<22) != 0])
	case w&0x0db0f000 == 0x0120f000:
		set("msr"+cs, map[bool]string{true: "spsr", false: "cpsr"}[w&(1<<22) != 0]+"_fc, "+armOperand2(w))
	case w&0x0fff0ff0 == 0x016f0f10:
		set("clz"+cs, armRegs[(w>>12)&0xf]+", "+armRegs[w&0xf])
	case w&0x0ff00000 == 0x03000000 || w&0x0ff00000 == 0x03400000:
		imm := (w>>4)&0xf000 | w&0xfff
		set(map[bool]string{true: "movt", false: "movw"}[w&(1<<22) != 0]+cs, fmt.Sprintf("%s, #0x%x", armRegs[(w>>12)&0xf], imm))
	case (w>>26)&3 == 0: // data processing
		opc := (w >> 21) & 0xf
		s := w&(1<<20) != 0
		rn, rd := (w>>16)&0xf, (w>>12)&0xf
		mn := strings.ToLower(armDataProc[opc])
		op2 := armOperand2(w)
		switch {
		case opc >= 8 && opc <= 11:
			set(mn+cs, armRegs[rn]+", "+op2)
		case opc == 13 || opc == 15:
			// mov with an immediate shift is the canonical lsl/lsr/asr/ror alias
			if opc == 13 && w&(1<<25) == 0 && op2 != armRegs[w&0xf] && !strings.HasSuffix(op2, "rrx") {
				parts := strings.SplitN(op2, ", ", 2)
				sh := strings.SplitN(parts[1], " ", 2)
				set(sh[0]+map[bool]string{true: "s", false: ""}[s]+cs, fmt.Sprintf("%s, %s, %s", armRegs[rd], parts[0], sh[1]))
			} else {
				set(mn+map[bool]string{true: "s", false: ""}[s]+cs, armRegs[rd]+", "+op2)
			}
		default:
			set(mn+map[bool]string{true: "s", false: ""}[s]+cs, fmt.Sprintf("%s, %s, %s", armRegs[rd], armRegs[rn], op2))
		}
		if rd == 15 && !(opc >= 8 && opc <= 11) {
			if (opc == 13 && w&0x0200000f == 14) || (s && rn == 14) {
				in.Flow = "ret"
			} else {
				in.Flow, in.Comment = "branch", "indirect (writes pc)"
			}
		}
	case (w>>26)&3 == 1: // single data transfer
		if w&(1<<25) != 0 && w&(1<<4) != 0 {
			set("udf", fmt.Sprintf("0x%08x", w))
			in.Flow = "invalid"
			break
		}
		l, b := w&(1<<20) != 0, w&(1<<22) != 0
		p, u, wb := w&(1<<24) != 0, w&(1<<23) != 0, w&(1<<21) != 0
		rn, rd := (w>>16)&0xf, (w>>12)&0xf
		mn := map[bool]string{true: "ldr", false: "str"}[l] + map[bool]string{true: "b", false: ""}[b] + cs
		sign := map[bool]string{true: "", false: "-"}[u]
		off := ""
		if w&(1<<25) == 0 {
			if imm := w & 0xfff; imm != 0 {
				off = fmt.Sprintf("#%s0x%x", sign, imm)
			}
		} else {
			off = sign + armOperand2(w&^(1<<25)&^(1<<4))
		}
		var ops string
		switch {
		case p && off == "":
			ops = fmt.Sprintf("%s, [%s]", armRegs[rd], armRegs[rn])
		case p:
			ops = fmt.Sprintf("%s, [%s, %s]%s", armRegs[rd], armRegs[rn], off, map[bool]string{true: "!", false: ""}[wb])
		default:
			ops = fmt.Sprintf("%s, [%s], %s", armRegs[rd], armRegs[rn], off)
		}
		if l && rn == 13 && !p && u && w&0xfff == 4 && w&(1<<25) == 0 {
			mn, ops = "pop"+cs, "{"+armRegs[rd]+"}"
		} else if !l && rn == 13 && p && !u && wb && w&0xfff == 4 && w&(1<<25) == 0 {
			mn, ops = "push"+cs, "{"+armRegs[rd]+"}"
		}
		if rn == 15 && p && w&(1<<25) == 0 {
			imm := int64(w & 0xfff)
			if !u {
				imm = -imm
			}
			in.MemRef, in.HasMemRef = uint64(int64(addr)+8+imm), true
			in.Comment = fmt.Sprintf("=[0x%x]", in.MemRef)
		}
		set(mn, ops)
		if l && rd == 15 {
			if rn == 13 {
				in.Flow = "ret"
			} else {
				in.Flow, in.Comment = "branch", "indirect (loads pc)"
			}
		}
	case (w>>25)&7 == 4: // block transfer
		l := w&(1<<20) != 0
		rn := (w >> 16) & 0xf
		wb := w&(1<<21) != 0
		mode := []string{"da", "ia", "db", "ib"}[(w>>23)&3]
		regs := armRegList(w & 0xffff)
		switch {
		case rn == 13 && wb && l && mode == "ia":
			set("pop"+cs, regs)
		case rn == 13 && wb && !l && mode == "db":
			set("push"+cs, regs)
		default:
			set(map[bool]string{true: "ldm", false: "stm"}[l]+mode+cs, armRegs[rn]+map[bool]string{true: "!", false: ""}[wb]+", "+regs)
		}
		if l && w&(1<<15) != 0 {
			in.Flow = "ret"
		}
	case (w>>25)&7 == 5: // B / BL
		off := int64(int32(w<<8) >> 6)
		in.Target, in.HasTarget = uint64(int64(addr)+8+off), true
		if w&(1<<24) != 0 {
			set("bl"+cs, fmt.Sprintf("0x%x", in.Target))
			in.Flow = "call"
		} else {
			set("b"+cs, fmt.Sprintf("0x%x", in.Target))
			in.Flow = "branch"
			if cond != 14 {
				in.Flow = "cbranch"
			}
		}
	case (w>>24)&0xf == 0xf:
		set("svc"+cs, fmt.Sprintf("#0x%x", w&0xffffff))
		in.Flow = "syscall"
	case (w>>24)&0xf == 0xe && w&(1<<4) != 0:
		set(map[bool]string{true: "mrc", false: "mcr"}[w&(1<<20) != 0]+cs,
			fmt.Sprintf("p%d, %d, %s, c%d, c%d, %d", (w>>8)&0xf, (w>>21)&7, armRegs[(w>>12)&0xf], (w>>16)&0xf, w&0xf, (w>>5)&7))
	case (w>>24)&0xf == 0xe:
		set("cdp"+cs, fmt.Sprintf("p%d", (w>>8)&0xf))
	case (w>>25)&7 == 6:
		set(map[bool]string{true: "ldc", false: "stc"}[w&(1<<20) != 0]+cs, fmt.Sprintf("p%d", (w>>8)&0xf))
	default:
		set("udf", fmt.Sprintf("0x%08x", w))
		in.Flow = "invalid"
	}
	return in
}

func disasmARMLinear(code []byte, base uint64) []Insn {
	var out []Insn
	for i := 0; i+3 < len(code); i += 4 {
		in := decodeARM(binary.LittleEndian.Uint32(code[i:]), base+uint64(i))
		in.Bytes = append([]byte{}, code[i:i+4]...)
		out = append(out, in)
	}
	markLeaders(out, base)
	return out
}

// ============================================================================
//  AArch64 (A64) decoder — the integer/control-flow core used by real code.
//  Anything outside the subset decodes as ".inst" (length is always 4).
// ============================================================================

var a64Cond = []string{"eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"}

func a64Reg(n uint32, sf bool, sp bool) string {
	if n == 31 {
		if sp {
			return map[bool]string{true: "sp", false: "wsp"}[sf]
		}
		return map[bool]string{true: "xzr", false: "wzr"}[sf]
	}
	return fmt.Sprintf("%s%d", map[bool]string{true: "x", false: "w"}[sf], n)
}

func sext(v uint32, bits uint) int64 { return int64(int32(v<<(32-bits)) >> (32 - bits)) }

func decodeA64(w uint32, addr uint64) Insn {
	in := Insn{Offset: addr, Size: 4, Flow: "next"}
	set := func(mn, ops string) { in.Mnemonic, in.Operands = mn, ops }
	rd, rn := w&31, (w>>5)&31
	sf := w&(1<<31) != 0
	switch {
	case w == 0xd503201f:
		set("nop", "")
	case w&0xfffffc1f == 0xd65f0000:
		set("ret", map[bool]string{true: "", false: a64Reg(rn, true, false)}[rn == 30])
		in.Flow = "ret"
	case w&0xfffffc1f == 0xd61f0000:
		set("br", a64Reg(rn, true, false))
		in.Flow, in.Comment = "branch", "indirect"
	case w&0xfffffc1f == 0xd63f0000:
		set("blr", a64Reg(rn, true, false))
		in.Flow, in.Comment = "call", "indirect"
	case w&0x7c000000 == 0x14000000:
		in.Target, in.HasTarget = uint64(int64(addr)+sext(w&0x3ffffff, 26)*4), true
		if w&(1<<31) != 0 {
			set("bl", fmt.Sprintf("0x%x", in.Target))
			in.Flow = "call"
		} else {
			set("b", fmt.Sprintf("0x%x", in.Target))
			in.Flow = "branch"
		}
	case w&0xff000010 == 0x54000000:
		in.Target, in.HasTarget = uint64(int64(addr)+sext((w>>5)&0x7ffff, 19)*4), true
		set("b."+a64Cond[w&0xf], fmt.Sprintf("0x%x", in.Target))
		in.Flow = "cbranch"
	case w&0x7e000000 == 0x34000000:
		in.Target, in.HasTarget = uint64(int64(addr)+sext((w>>5)&0x7ffff, 19)*4), true
		set(map[bool]string{true: "cbnz", false: "cbz"}[w&(1<<24) != 0], fmt.Sprintf("%s, 0x%x", a64Reg(rd, sf, false), in.Target))
		in.Flow = "cbranch"
	case w&0x7e000000 == 0x36000000:
		bit := (w>>31)<<5 | (w>>19)&31
		in.Target, in.HasTarget = uint64(int64(addr)+sext((w>>5)&0x3fff, 14)*4), true
		set(map[bool]string{true: "tbnz", false: "tbz"}[w&(1<<24) != 0], fmt.Sprintf("%s, #%d, 0x%x", a64Reg(rd, bit >= 32, false), bit, in.Target))
		in.Flow = "cbranch"
	case w&0xffe0001f == 0xd4000001:
		set("svc", fmt.Sprintf("#0x%x", (w>>5)&0xffff))
		in.Flow = "syscall"
	case w&0xffe0001f == 0xd4200000:
		set("brk", fmt.Sprintf("#0x%x", (w>>5)&0xffff))
	case w&0x1f000000 == 0x10000000:
		imm := sext((w>>5)&0x7ffff<<2|(w>>29)&3, 21)
		if w&(1<<31) != 0 {
			in.MemRef, in.HasMemRef = uint64(int64(addr&^0xfff)+imm<<12), true
			set("adrp", fmt.Sprintf("%s, 0x%x", a64Reg(rd, true, false), in.MemRef))
		} else {
			in.MemRef, in.HasMemRef = uint64(int64(addr)+imm), true
			set("adr", fmt.Sprintf("%s, 0x%x", a64Reg(rd, true, false), in.MemRef))
		}
	case w&0x1f800000 == 0x12800000:
		opc := (w >> 29) & 3
		hw := (w >> 21) & 3
		imm := (w >> 5) & 0xffff
		mn := []string{"movn", "", "movz", "movk"}[opc]
		if mn == "" {
			set(".inst", fmt.Sprintf("0x%08x", w))
			break
		}
		if mn == "movz" && (hw == 0 || imm != 0) {
			mn = "mov"
			set(mn, fmt.Sprintf("%s, #0x%x", a64Reg(rd, sf, false), uint64(imm)<<(16*hw)))
			break
		}
		sh := ""
		if hw != 0 {
			sh = fmt.Sprintf(", lsl #%d", 16*hw)
		}
		set(mn, fmt.Sprintf("%s, #0x%x%s", a64Reg(rd, sf, false), imm, sh))
	case w&0x1f000000 == 0x11000000:
		sub, s := w&(1<<30) != 0, w&(1<<29) != 0
		imm := uint64((w >> 10) & 0xfff)
		if w&(1<<22) != 0 {
			imm <<= 12
		}
		mn := map[bool]string{true: "sub", false: "add"}[sub] + map[bool]string{true: "s", false: ""}[s]
		switch {
		case !sub && !s && imm == 0 && (rd == 31 || rn == 31):
			set("mov", a64Reg(rd, sf, true)+", "+a64Reg(rn, sf, true))
		case s && rd == 31:
			set(map[bool]string{true: "cmp", false: "cmn"}[sub], fmt.Sprintf("%s, #0x%x", a64Reg(rn, sf, true), imm))
		default:
			set(mn, fmt.Sprintf("%s, %s, #0x%x", a64Reg(rd, sf, !s), a64Reg(rn, sf, true), imm))
		}
	case w&0x7fe0ffe0 == 0x2a0003e0:
		set("mov", a64Reg(rd, sf, false)+", "+a64Reg((w>>16)&31, sf, false))
	case w&0x1f000000 == 0x0a000000:
		opc := (w >> 29) & 3
		n := (w >> 21) & 1
		mn := [][]string{{"and", "orr", "eor", "ands"}, {"bic", "orn", "eon", "bics"}}[n][opc]
		set(mn, fmt.Sprintf("%s, %s, %s", a64Reg(rd, sf, false), a64Reg(rn, sf, false), a64Reg((w>>16)&31, sf, false)))
	case w&0x1f200000 == 0x0b000000:
		sub, s := w&(1<<30) != 0, w&(1<<29) != 0
		mn := map[bool]string{true: "sub", false: "add"}[sub] + map[bool]string{true: "s", false: ""}[s]
		if s && rd == 31 {
			set(map[bool]string{true: "cmp", false: "cmn"}[sub], a64Reg(rn, sf, false)+", "+a64Reg((w>>16)&31, sf, false))
		} else {
			set(mn, fmt.Sprintf("%s, %s, %s", a64Reg(rd, sf, false), a64Reg(rn, sf, false), a64Reg((w>>16)&31, sf, false)))
		}
	case w&0x3b000000 == 0x39000000 && w&(1<<26) == 0:
		size := (w >> 30) & 3
		opc := (w >> 22) & 3
		off := uint64((w>>10)&0xfff) << size
		suffix := []string{"b", "h", "", ""}[size]
		x := size == 3
		mn := ""
		switch opc {
		case 0:
			mn = "str" + suffix
		case 1:
			mn = "ldr" + suffix
		case 2:
			mn, x = "ldrs"+suffix, true
			if size == 2 {
				mn = "ldrsw"
			}
		case 3:
			mn, x = "ldrs"+suffix, false
		}
		mem := "[" + a64Reg(rn, true, true)
		if off != 0 {
			mem += fmt.Sprintf(", #0x%x", off)
		}
		set(mn, a64Reg(rd, x, false)+", "+mem+"]")
	case w&0x3a000000 == 0x28000000 && w&(1<<26) == 0:
		x := w&(1<<31) != 0
		scale := map[bool]int64{true: 8, false: 4}[x]
		imm := sext((w>>15)&0x7f, 7) * scale
		l := w&(1<<22) != 0
		idx := (w >> 23) & 3
		mn := map[bool]string{true: "ldp", false: "stp"}[l]
		rt, rt2 := a64Reg(rd, x, false), a64Reg((w>>10)&31, x, false)
		b := a64Reg(rn, true, true)
		var mem string
		switch idx {
		case 1:
			mem = fmt.Sprintf("[%s], #%d", b, imm)
		case 3:
			mem = fmt.Sprintf("[%s, #%d]!", b, imm)
		default:
			mem = fmt.Sprintf("[%s, #%d]", b, imm)
		}
		set(mn, rt+", "+rt2+", "+mem)
	case w&0x3b000000 == 0x18000000:
		in.MemRef, in.HasMemRef = uint64(int64(addr)+sext((w>>5)&0x7ffff, 19)*4), true
		set("ldr", fmt.Sprintf("%s, 0x%x", a64Reg(rd, w&(1<<30) != 0, false), in.MemRef))
	default:
		set(".inst", fmt.Sprintf("0x%08x", w))
	}
	return in
}

func disasmA64Linear(code []byte, base uint64) []Insn {
	var out []Insn
	for i := 0; i+3 < len(code); i += 4 {
		in := decodeA64(binary.LittleEndian.Uint32(code[i:]), base+uint64(i))
		in.Bytes = append([]byte{}, code[i:i+4]...)
		out = append(out, in)
	}
	markLeaders(out, base)
	return out
}

// ============================================================================
//  Linear sweep, recursive descent, basic-block leaders
// ============================================================================

// decodeAt decodes one instruction for arch at code[off:].
func decodeAt(code []byte, off int, base uint64, arch Arch, bits int) (Insn, bool) {
	switch arch {
	case ArchARM, ArchARM64:
		if off+4 > len(code) {
			return Insn{}, false
		}
		w := binary.LittleEndian.Uint32(code[off:])
		var in Insn
		if arch == ArchARM {
			in = decodeARM(w, base+uint64(off))
		} else {
			in = decodeA64(w, base+uint64(off))
		}
		in.Bytes = append([]byte{}, code[off:off+4]...)
		return in, true
	}
	if off >= len(code) {
		return Insn{}, false
	}
	return decodeX86(code, off, base, bits), true
}

func linearDisasm(code []byte, base uint64, arch Arch, bits int) []Insn {
	switch arch {
	case ArchARM:
		return disasmARMLinear(code, base)
	case ArchARM64:
		return disasmA64Linear(code, base)
	}
	return disasmX86Linear(code, base, bits)
}

// markLeaders flags basic-block leaders: the entry points, every in-range
// direct branch/call target, and the instruction after any control transfer.
func markLeaders(insns []Insn, entries ...uint64) {
	lead := map[uint64]bool{}
	for _, e := range entries {
		lead[e] = true
	}
	for _, in := range insns {
		switch in.Flow {
		case "branch", "cbranch", "call", "ret", "stop", "syscall":
			lead[in.Offset+uint64(in.Size)] = true
			if in.HasTarget && in.Flow != "syscall" {
				lead[in.Target] = true
			}
		}
	}
	for i := range insns {
		insns[i].Leader = lead[insns[i].Offset]
	}
}

// recursiveDisasm follows control flow from the entry points instead of
// sweeping every byte, so data embedded between functions (jump tables,
// strings, padding) is not decoded as code. Returns instructions sorted by
// address plus the number of code bytes reached.
func recursiveDisasm(code []byte, base uint64, arch Arch, bits int, entries ...uint64) []Insn {
	if len(entries) == 0 {
		entries = []uint64{base}
	}
	seen := map[uint64]Insn{}
	work := append([]uint64{}, entries...)
	end := base + uint64(len(code))
	const maxInsns = 2000000
	for len(work) > 0 && len(seen) < maxInsns {
		a := work[len(work)-1]
		work = work[:len(work)-1]
		for a >= base && a < end && len(seen) < maxInsns {
			if _, ok := seen[a]; ok {
				break
			}
			in, ok := decodeAt(code, int(a-base), base, arch, bits)
			if !ok {
				break
			}
			seen[a] = in
			if in.HasTarget && (in.Flow == "branch" || in.Flow == "cbranch" || in.Flow == "call") {
				work = append(work, in.Target)
			}
			// A code address materialised with lea/adr is almost always a
			// function pointer (main handed to __libc_start_main, callbacks,
			// thread entry points): follow it as another root.
			if in.HasMemRef && (in.Mnemonic == "lea" || in.Mnemonic == "adr") && in.MemRef >= base && in.MemRef < end {
				work = append(work, in.MemRef)
			}
			if in.Flow == "branch" || in.Flow == "ret" || in.Flow == "stop" || in.Flow == "invalid" {
				break
			}
			a += uint64(in.Size)
		}
	}
	out := make([]Insn, 0, len(seen))
	for _, in := range seen {
		out = append(out, in)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Offset < out[j].Offset })
	markLeaders(out, entries...)
	return out
}

// coverage returns the fraction of code bytes covered by decoded instructions.
func coverage(insns []Insn, n int) float64 {
	if n == 0 {
		return 0
	}
	c := 0
	for _, in := range insns {
		c += in.Size
	}
	if c > n {
		c = n
	}
	return float64(c) / float64(n)
}

// ============================================================================
//  Executable containers: ELF / PE / Mach-O via the Go standard library
// ============================================================================

type binImage struct {
	Format  string
	Arch    Arch
	Bits    int
	Section string
	Base    uint64
	Code    []byte
	Entry   uint64
	HasEnt  bool
	Funcs   []uint64 // function symbols inside the section (extra recursive-descent roots)
}

// inSection keeps the addresses that fall inside [base, base+n).
func inSection(addrs []uint64, base uint64, n int) []uint64 {
	var out []uint64
	for _, a := range addrs {
		if a >= base && a < base+uint64(n) {
			out = append(out, a)
		}
	}
	return out
}

// loadImage recognises ELF, PE and Mach-O files and returns their executable
// section. It returns (nil, nil) for anything else (treated as raw bytes).
func loadImage(data []byte, want string) (*binImage, error) {
	r := bytes.NewReader(data)
	switch {
	case bytes.HasPrefix(data, []byte("\x7fELF")):
		f, err := elf.NewFile(r)
		if err != nil {
			return nil, fmt.Errorf("ELF: %v", err)
		}
		img := &binImage{Format: "ELF", Entry: f.Entry, HasEnt: f.Entry != 0}
		switch f.Machine {
		case elf.EM_386:
			img.Arch, img.Bits = ArchX86, 32
		case elf.EM_X86_64:
			img.Arch, img.Bits = ArchX64, 64
		case elf.EM_ARM:
			img.Arch, img.Bits = ArchARM, 32
		case elf.EM_AARCH64:
			img.Arch, img.Bits = ArchARM64, 64
		default:
			return nil, fmt.Errorf("ELF machine %v is not supported", f.Machine)
		}
		var sec *elf.Section
		for _, s := range f.Sections {
			if (want != "" && s.Name == want) || (want == "" && s.Name == ".text") {
				sec = s
				break
			}
		}
		if sec == nil && want == "" {
			for _, s := range f.Sections {
				if s.Flags&elf.SHF_EXECINSTR != 0 && s.Type == elf.SHT_PROGBITS {
					sec = s
					break
				}
			}
		}
		if sec == nil {
			return nil, fmt.Errorf("ELF: no executable section %q", want)
		}
		b, err := sec.Data()
		if err != nil {
			return nil, err
		}
		img.Section, img.Base, img.Code = sec.Name, sec.Addr, b
		var fn []uint64
		syms, _ := f.Symbols()
		dyn, _ := f.DynamicSymbols()
		for _, sy := range append(syms, dyn...) {
			if elf.ST_TYPE(sy.Info) == elf.STT_FUNC && sy.Value != 0 {
				fn = append(fn, sy.Value)
			}
		}
		img.Funcs = inSection(fn, img.Base, len(b))
		return img, nil
	case bytes.HasPrefix(data, []byte("MZ")):
		f, err := pe.NewFile(r)
		if err != nil {
			return nil, fmt.Errorf("PE: %v", err)
		}
		img := &binImage{Format: "PE"}
		var imageBase uint64
		var entry uint32
		switch oh := f.OptionalHeader.(type) {
		case *pe.OptionalHeader32:
			imageBase, entry = uint64(oh.ImageBase), oh.AddressOfEntryPoint
		case *pe.OptionalHeader64:
			imageBase, entry = oh.ImageBase, oh.AddressOfEntryPoint
		}
		switch f.Machine {
		case pe.IMAGE_FILE_MACHINE_I386:
			img.Arch, img.Bits = ArchX86, 32
		case pe.IMAGE_FILE_MACHINE_AMD64:
			img.Arch, img.Bits = ArchX64, 64
		case pe.IMAGE_FILE_MACHINE_ARM64:
			img.Arch, img.Bits = ArchARM64, 64
		case pe.IMAGE_FILE_MACHINE_ARM:
			img.Arch, img.Bits = ArchARM, 32
		default:
			return nil, fmt.Errorf("PE machine 0x%x is not supported", f.Machine)
		}
		var sec *pe.Section
		for _, s := range f.Sections {
			if (want != "" && s.Name == want) || (want == "" && s.Name == ".text") {
				sec = s
				break
			}
		}
		if sec == nil && want == "" {
			for _, s := range f.Sections {
				if s.Characteristics&0x20000000 != 0 { // IMAGE_SCN_MEM_EXECUTE
					sec = s
					break
				}
			}
		}
		if sec == nil {
			return nil, fmt.Errorf("PE: no executable section %q", want)
		}
		b, err := sec.Data()
		if err != nil {
			return nil, err
		}
		if sec.VirtualSize != 0 && int(sec.VirtualSize) < len(b) {
			b = b[:sec.VirtualSize] // drop file-alignment padding
		}
		img.Section, img.Base, img.Code = sec.Name, imageBase+uint64(sec.VirtualAddress), b
		if entry != 0 {
			img.Entry, img.HasEnt = imageBase+uint64(entry), true
		}
		return img, nil
	}
	if len(data) >= 4 {
		magic := binary.LittleEndian.Uint32(data)
		if magic == macho.Magic32 || magic == macho.Magic64 {
			f, err := macho.NewFile(r)
			if err != nil {
				return nil, fmt.Errorf("Mach-O: %v", err)
			}
			img := &binImage{Format: "Mach-O"}
			switch f.Cpu {
			case macho.Cpu386:
				img.Arch, img.Bits = ArchX86, 32
			case macho.CpuAmd64:
				img.Arch, img.Bits = ArchX64, 64
			case macho.CpuArm:
				img.Arch, img.Bits = ArchARM, 32
			case macho.CpuArm64:
				img.Arch, img.Bits = ArchARM64, 64
			default:
				return nil, fmt.Errorf("Mach-O cpu %v is not supported", f.Cpu)
			}
			name := want
			if name == "" {
				name = "__text"
			}
			sec := f.Section(name)
			if sec == nil {
				return nil, fmt.Errorf("Mach-O: no section %q", name)
			}
			b, err := sec.Data()
			if err != nil {
				return nil, err
			}
			img.Section, img.Base, img.Code = sec.Name, sec.Addr, b
			if f.Symtab != nil {
				var fn []uint64
				for _, sy := range f.Symtab.Syms {
					fn = append(fn, sy.Value)
				}
				img.Funcs = inSection(fn, img.Base, len(b))
			}
			return img, nil
		}
	}
	return nil, nil
}

// ============================================================================
//  Triage analysis → findings
// ============================================================================

var linuxX64Sys = map[int64]string{0: "read", 1: "write", 2: "open", 3: "close", 9: "mmap", 10: "mprotect",
	21: "access", 32: "dup", 33: "dup2", 41: "socket", 42: "connect", 43: "accept", 44: "sendto", 45: "recvfrom",
	49: "bind", 50: "listen", 56: "clone", 57: "fork", 59: "execve", 60: "exit", 62: "kill", 101: "ptrace",
	105: "setuid", 231: "exit_group", 257: "openat", 292: "dup3", 319: "memfd_create", 322: "execveat"}
var linuxX86Sys = map[int64]string{1: "exit", 2: "fork", 3: "read", 4: "write", 5: "open", 6: "close", 11: "execve",
	23: "setuid", 26: "ptrace", 37: "kill", 41: "dup", 63: "dup2", 102: "socketcall", 125: "mprotect",
	190: "vfork", 192: "mmap2", 252: "exit_group", 359: "socket", 362: "connect", 358: "execveat"}
var linuxARMSys = map[int64]string{1: "exit", 2: "fork", 3: "read", 4: "write", 5: "open", 6: "close", 11: "execve",
	26: "ptrace", 37: "kill", 63: "dup2", 125: "mprotect", 192: "mmap2", 248: "exit_group", 281: "socket",
	282: "bind", 283: "connect", 284: "listen", 285: "accept"}
var linuxA64Sys = map[int64]string{23: "dup", 24: "dup3", 56: "openat", 57: "close", 63: "read", 64: "write",
	93: "exit", 94: "exit_group", 117: "ptrace", 129: "kill", 198: "socket", 200: "bind", 201: "listen",
	202: "accept", 203: "connect", 220: "clone", 221: "execve", 222: "mmap", 226: "mprotect", 281: "execveat"}

// movImm parses "mov <reg>, <imm>" style instructions (x86 and ARM forms)
// and returns the destination register and immediate value.
func movImm(in Insn) (string, int64, bool) {
	if in.Mnemonic != "mov" && in.Mnemonic != "movw" {
		return "", 0, false
	}
	parts := strings.SplitN(in.Operands, ", ", 2)
	if len(parts) != 2 {
		return "", 0, false
	}
	v := strings.TrimPrefix(parts[1], "#")
	neg := strings.HasPrefix(v, "-")
	v = strings.TrimPrefix(v, "-")
	if !strings.HasPrefix(v, "0x") {
		return "", 0, false
	}
	n, err := strconv.ParseUint(v[2:], 16, 64)
	if err != nil {
		return "", 0, false
	}
	if neg {
		return parts[0], -int64(n), true
	}
	return parts[0], int64(n), true
}

// syscallNumber looks back from a syscall instruction for the value loaded
// into the syscall-number register (eax/rax/al, r7, x8/w8).
func syscallNumber(insns []Insn, i int, arch Arch) (int64, bool) {
	regs := map[Arch][]string{ArchX64: {"eax", "rax", "al", "ax"}, ArchX86: {"eax", "al", "ax"},
		ArchARM: {"r7"}, ArchARM64: {"x8", "w8"}}[arch]
	var al int64
	haveAL := false
	for j := i - 1; j >= 0 && j >= i-12; j-- {
		in := insns[j]
		if in.Flow != "next" {
			break
		}
		if reg, v, ok := movImm(in); ok {
			for _, r := range regs {
				if reg == r {
					if r == "al" || r == "ax" {
						al, haveAL = v, true
						break
					}
					return v, true
				}
			}
		}
		// push imm ; pop rax  — a common shellcode idiom
		if (in.Mnemonic == "pop") && (in.Operands == "rax" || in.Operands == "eax") && j > 0 && insns[j-1].Mnemonic == "push" {
			if v, err := strconv.ParseInt(strings.TrimPrefix(insns[j-1].Operands, "0x"), 16, 64); err == nil {
				return v, true
			}
		}
	}
	if haveAL {
		return al, true // "xor eax,eax ; mov al,N" leaves N in eax
	}
	return 0, false
}

func syscallTable(arch Arch, in Insn) map[int64]string {
	switch arch {
	case ArchX64:
		if in.Mnemonic == "int" {
			return linuxX86Sys // int 0x80 in 64-bit code uses the 32-bit ABI
		}
		return linuxX64Sys
	case ArchX86:
		return linuxX86Sys
	case ArchARM:
		return linuxARMSys
	}
	return linuxA64Sys
}

type sysRisk struct {
	sev   string
	score float64
	attck []string
	why   string
}

var sysRisks = map[string]sysRisk{
	"execve":       {"HIGH", 8.0, []string{"T1059.004", "T1106"}, "spawns a program (typically /bin/sh) — classic shellcode payload"},
	"execveat":     {"HIGH", 8.0, []string{"T1059.004", "T1106"}, "spawns a program via execveat (fileless execution)"},
	"socket":       {"HIGH", 7.0, []string{"T1095"}, "creates a raw network socket — bind/reverse shell building block"},
	"connect":      {"HIGH", 7.5, []string{"T1095", "T1571"}, "connects out — reverse-shell / C2 callback"},
	"bind":         {"HIGH", 7.0, []string{"T1095"}, "binds a listening port — bind shell"},
	"listen":       {"HIGH", 7.0, []string{"T1095"}, "listens for inbound connections — bind shell"},
	"accept":       {"HIGH", 7.0, []string{"T1095"}, "accepts inbound connections — bind shell"},
	"socketcall":   {"HIGH", 7.0, []string{"T1095"}, "x86 socketcall multiplexer — network shellcode"},
	"dup2":         {"HIGH", 7.0, []string{"T1059.004"}, "redirects stdin/stdout/stderr — shell over a socket"},
	"dup3":         {"HIGH", 7.0, []string{"T1059.004"}, "redirects file descriptors — shell over a socket"},
	"mprotect":     {"MEDIUM", 5.5, []string{"T1055"}, "changes memory protection — staging executable payloads"},
	"mmap":         {"MEDIUM", 5.0, []string{"T1055"}, "maps memory — possible RWX payload staging"},
	"mmap2":        {"MEDIUM", 5.0, []string{"T1055"}, "maps memory — possible RWX payload staging"},
	"memfd_create": {"HIGH", 7.0, []string{"T1620"}, "anonymous in-memory file — fileless execution"},
	"ptrace":       {"MEDIUM", 5.0, []string{"T1622", "T1055.008"}, "ptrace — anti-debugging or process injection"},
	"setuid":       {"MEDIUM", 5.5, []string{"T1548"}, "changes user id — privilege manipulation"},
	"kill":         {"LOW", 3.0, []string{"T1489"}, "signals another process"},
	"fork":         {"LOW", 2.5, []string{"T1106"}, "forks the process"},
	"clone":        {"LOW", 2.5, []string{"T1106"}, "creates a thread/process"},
}

// analyzeInsns runs the triage heuristics over a decoded listing. container
// is "" for raw bytes (shellcode, dumps) or ELF / PE / Mach-O: inside a normal
// executable raw syscalls (libc wrappers), XOR-over-buffer loops (crypto) and
// the like are routine, so they are summarised at INFO instead of alerting.
func analyzeInsns(r *Report, insns []Insn, arch Arch, container string) {
	raw := container == ""
	add := func(f Finding) {
		if !raw && f.Category != "evasion" && f.Category != "coverage" {
			f.Severity, f.Score = "INFO", 0.5
			f.Description += " (Inside a compiled " + container + " this is often legitimate; it is a strong signal only in raw shellcode.)"
		}
		r.Findings = append(r.Findings, f)
	}
	sysCount, resolved := 0, 0
	inventory := map[string]int{}
	for i, in := range insns {
		if in.Flow != "syscall" || (arch != ArchARM && arch != ArchARM64 && in.Mnemonic == "int" && in.Operands != "0x80") {
			continue
		}
		sysCount++
		n, ok := syscallNumber(insns, i, arch)
		if !ok {
			continue
		}
		name, known := syscallTable(arch, in)[n]
		if !known {
			name = fmt.Sprintf("#%d", n)
		}
		insns[i].Comment = "sys_" + name
		resolved++
		inventory[name]++
		risk, risky := sysRisks[name]
		if !risky || !raw {
			continue
		}
		add(Finding{ID: "ODISASM-SYS-" + strings.ToUpper(name), Title: "Raw syscall: " + name,
			Severity: risk.sev, Category: "syscall", Score: risk.score, ATTCK: risk.attck,
			Location: fmt.Sprintf("0x%x", in.Offset), Evidence: in.Mnemonic + " " + in.Operands + "  (nr " + strconv.FormatInt(n, 10) + ")",
			Description: "Direct " + name + " system call without libc — " + risk.why + ".",
			Remediation: "Treat as shellcode-like behaviour; detonate only in an isolated sandbox."})
	}
	r.Stats = append(r.Stats, KV{"syscall_sites", strconv.Itoa(sysCount)}, KV{"syscalls_resolved", strconv.Itoa(resolved)})
	if !raw && len(inventory) > 0 {
		names := make([]string, 0, len(inventory))
		for n := range inventory {
			names = append(names, n)
		}
		sort.Strings(names)
		var risky []string
		for _, n := range names {
			if _, ok := sysRisks[n]; ok {
				risky = append(risky, fmt.Sprintf("%s×%d", n, inventory[n]))
			}
		}
		if len(risky) > 0 {
			r.Findings = append(r.Findings, Finding{ID: "ODISASM-SYSCALL-INVENTORY", Title: "Direct syscall sites (inventory)", Severity: "INFO",
				Category: "syscall", Score: 0.5, ATTCK: []string{"T1106"}, Evidence: strings.Join(risky, ", "),
				Description: "Security-relevant system calls issued directly from this " + container + ". Normal for libc and statically linked programs; review if the binary is not expected to make them.",
				Remediation: "Compare against the program's expected capabilities."})
		}
	}

	// GetPC: call $+5 ; pop reg   or   fnstenv [esp-0xc]
	for i, in := range insns {
		getpc := false
		if in.Flow == "call" && in.HasTarget && in.Target == in.Offset+uint64(in.Size) && i+1 < len(insns) && insns[i+1].Mnemonic == "pop" {
			getpc = true
		}
		if in.Mnemonic == "fnstenv" && strings.Contains(in.Operands, "sp-0xc]") {
			getpc = true
		}
		if getpc {
			add(Finding{ID: "ODISASM-GETPC", Title: "GetPC idiom (position-independent shellcode)", Severity: "HIGH",
				Category: "shellcode", Score: 7.5, ATTCK: []string{"T1027", "T1620"}, Location: fmt.Sprintf("0x%x", in.Offset),
				Evidence:    in.Mnemonic + " " + in.Operands,
				Description: "Code discovers its own address at run time (call/pop or fnstenv). Compiled programs rarely do this; injected shellcode and decoders do.",
				Remediation: "Inspect the bytes that follow — usually a decoder stub or payload."})
			break
		}
	}
	// PEB access: manual API resolution on Windows. On Linux fs/gs hold the
	// TLS base, so only raw blobs and PE files are checked, per architecture.
	peb := map[Arch]string{ArchX86: "fs:[0x30]", ArchX64: "gs:[0x60]"}[arch]
	for _, in := range insns {
		if peb == "" || !(raw || container == "PE") {
			break
		}
		if strings.Contains(in.Operands, peb) {
			add(Finding{ID: "ODISASM-PEB", Title: "Process Environment Block access", Severity: "HIGH", Category: "shellcode",
				Score: 7.0, ATTCK: []string{"T1106", "T1027.007"}, Location: fmt.Sprintf("0x%x", in.Offset),
				Evidence:    in.Mnemonic + " " + in.Operands,
				Description: "Reads the PEB (fs:[0x30] / gs:[0x60]) — the first step of walking the loader list to resolve APIs without an import table.",
				Remediation: "Typical of Windows shellcode and packers; trace the subsequent module-list walk."})
			break
		}
	}
	// NOP sled
	run, best, at := 0, 0, uint64(0)
	for _, in := range insns {
		if in.Mnemonic == "nop" && in.Size == 1 {
			run++
			if run > best {
				best, at = run, in.Offset-uint64(run-1)
			}
		} else {
			run = 0
		}
	}
	if best >= 16 {
		add(Finding{ID: "ODISASM-NOPSLED", Title: "NOP sled", Severity: "MEDIUM", Category: "shellcode", Score: 5.0,
			ATTCK: []string{"T1203"}, Location: fmt.Sprintf("0x%x", at), Evidence: fmt.Sprintf("%d consecutive 0x90", best),
			Description: "A long run of single-byte NOPs is used to absorb imprecise jumps into exploit payloads.",
			Remediation: "Look for the payload immediately after the sled."})
	}
	// XOR/ADD/SUB decoder loop: memory transformed through a pointer that the
	// loop itself advances, closed by a backward branch. Requiring the pointer
	// walk keeps ordinary counters (add dword ptr [rsp+0x44], 1) out.
	for i, in := range insns {
		if !(in.Mnemonic == "xor" || in.Mnemonic == "add" || in.Mnemonic == "sub" || in.Mnemonic == "rol" || in.Mnemonic == "ror") ||
			!(strings.HasPrefix(in.Operands, "byte ptr [") || strings.HasPrefix(in.Operands, "dword ptr [")) {
			continue
		}
		ptr := memBaseReg(in.Operands)
		if ptr == "" || ptr == "rsp" || ptr == "esp" || ptr == "rbp" || ptr == "ebp" || ptr == "rip" {
			continue
		}
		// a buffer walk addresses [ptr] or [ptr+index]; [ptr+0x20] is a struct field
		if !strings.Contains(in.Operands, "["+ptr+"]") && !(strings.Contains(in.Operands, "["+ptr+"+") && !strings.Contains(in.Operands, "["+ptr+"+0x")) {
			continue
		}
		advanced := false
		for j := i + 1; j < len(insns) && j <= i+8; j++ {
			b := insns[j]
			if (b.Mnemonic == "inc" || b.Mnemonic == "add" || b.Mnemonic == "sub" || b.Mnemonic == "lea" || b.Mnemonic == "dec") && strings.HasPrefix(b.Operands, ptr+",") || b.Operands == ptr {
				advanced = true
			}
			if (b.Flow == "cbranch" || b.Flow == "branch") && b.HasTarget && b.Target <= in.Offset {
				if advanced {
					add(Finding{ID: "ODISASM-DECODER", Title: "Self-decoding loop", Severity: "MEDIUM", Category: "obfuscation", Score: 6.0,
						ATTCK: []string{"T1140", "T1027"}, Location: fmt.Sprintf("0x%x", in.Offset),
						Evidence:    fmt.Sprintf("%s %s … %s 0x%x", in.Mnemonic, in.Operands, b.Mnemonic, b.Target),
						Description: "Memory is transformed byte/dword-wise through a pointer the loop advances, closed by a backward branch — the shape of an XOR/ADD decoder unpacking an encoded payload.",
						Remediation: "Emulate the loop (or set a breakpoint after it) to recover the decoded payload."})
				}
				break
			}
		}
		if hasFinding(r, "ODISASM-DECODER") {
			break
		}
	}
	// Anti-analysis primitives
	var anti []string
	for _, in := range insns {
		switch {
		case in.Mnemonic == "rdtsc" || in.Mnemonic == "rdtscp":
			anti = append(anti, fmt.Sprintf("0x%x rdtsc (timing check)", in.Offset))
		case in.Mnemonic == "cpuid":
			anti = append(anti, fmt.Sprintf("0x%x cpuid (VM detection)", in.Offset))
		case in.Mnemonic == "int" && in.Operands == "0x2d":
			anti = append(anti, fmt.Sprintf("0x%x int 0x2d (debugger trap)", in.Offset))
		case in.Mnemonic == "int1":
			anti = append(anti, fmt.Sprintf("0x%x icebp", in.Offset))
		}
	}
	if len(anti) > 0 {
		if len(anti) > 6 {
			anti = append(anti[:6], fmt.Sprintf("… %d more", len(anti)-6))
		}
		add(Finding{ID: "ODISASM-ANTIANALYSIS", Title: "Anti-analysis instructions", Severity: "LOW", Category: "evasion", Score: 3.0,
			ATTCK: []string{"T1497", "T1622"}, Evidence: strings.Join(anti, "; "),
			Description: "Timing, CPU-identification or debugger-trap instructions are present; common in sandbox/debugger evasion (and in benign runtime feature detection).",
			Remediation: "Check whether results feed a branch that changes behaviour under analysis."})
	}
	// Invalid-opcode ratio: data, packed code, or the wrong --arch
	invalid := 0
	for _, in := range insns {
		if in.Flow == "invalid" {
			invalid++
		}
	}
	if len(insns) > 0 {
		ratio := float64(invalid) / float64(len(insns))
		r.Stats = append(r.Stats, KV{"invalid_opcodes", fmt.Sprintf("%d (%.1f%%)", invalid, ratio*100)})
		if ratio > 0.10 && len(insns) >= 20 {
			add(Finding{ID: "ODISASM-INVALID", Title: "High invalid-opcode ratio", Severity: "LOW", Category: "coverage", Score: 2.5,
				ATTCK: []string{"T1027.002"}, Evidence: fmt.Sprintf("%d of %d instructions invalid", invalid, len(insns)),
				Description: "Many bytes do not decode: the region is data, packed/encrypted code, or --arch is wrong.",
				Remediation: "Try another --arch, use --recursive to follow real control flow, or unpack first."})
		}
	}
}

// memBaseReg returns the base register of a "size ptr [reg+...]" operand.
func memBaseReg(ops string) string {
	i := strings.IndexByte(ops, '[')
	if i < 0 {
		return ""
	}
	rest := ops[i+1:]
	if j := strings.IndexAny(rest, "+-*]"); j > 0 {
		return rest[:j]
	}
	return ""
}

func hasFinding(r *Report, id string) bool {
	for _, f := range r.Findings {
		if f.ID == id {
			return true
		}
	}
	return false
}

type disasmOpts struct {
	target    string
	format    string // raw / ELF / PE / Mach-O
	section   string
	entry     uint64
	hasEntry  bool
	recursive bool
	limit     int // listing lines in the report
	codeLen   int
	symbols   int // function symbols used as extra roots
}

func insnsToReport(o disasmOpts, arch Arch, insns []Insn) *Report {
	r := newReport(o.target)
	r.Stats = []KV{{"arch", arch.String()}, {"container", nonEmpty(o.format, "raw")}}
	if o.section != "" {
		r.Stats = append(r.Stats, KV{"section", o.section})
	}
	if len(insns) > 0 {
		r.Stats = append(r.Stats, KV{"base", fmt.Sprintf("0x%x", insns[0].Offset)})
	}
	if o.hasEntry {
		r.Stats = append(r.Stats, KV{"entry", fmt.Sprintf("0x%x", o.entry)})
	}
	if o.symbols > 0 {
		r.Stats = append(r.Stats, KV{"function_symbols", strconv.Itoa(o.symbols)})
	}
	mode := "linear sweep"
	if o.recursive {
		mode = "recursive descent"
	}
	r.Stats = append(r.Stats, KV{"mode", mode}, KV{"code_bytes", strconv.Itoa(o.codeLen)}, KV{"instructions", strconv.Itoa(len(insns))})
	if o.recursive {
		r.Stats = append(r.Stats, KV{"coverage", fmt.Sprintf("%.1f%%", coverage(insns, o.codeLen)*100)})
	}
	flows := map[string]int{}
	for _, in := range insns {
		flows[in.Flow]++
	}
	keys := make([]string, 0, len(flows))
	for k := range flows {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		r.Stats = append(r.Stats, KV{"flow_" + k, strconv.Itoa(flows[k])})
	}
	r.Stats = append(r.Stats, KV{"basic_blocks", strconv.Itoa(len(basicBlocks(insns)))},
		KV{"cfg_edges", strconv.Itoa(len(buildCFG(insns)))},
		KV{"byte_entropy", fmt.Sprintf("%.2f bits/byte", insnEntropy(insns))})
	top := countMnemonics(insns)
	var tops []string
	for i, kv := range top {
		if i >= 6 {
			break
		}
		tops = append(tops, kv.K+"×"+kv.V)
	}
	if len(tops) > 0 {
		r.Stats = append(r.Stats, KV{"top_mnemonics", strings.Join(tops, ", ")})
	}
	analyzeInsns(r, insns, arch, o.format)
	limit := o.limit
	if limit <= 0 || limit > len(insns) {
		limit = len(insns)
	}
	for i := 0; i < limit; i++ {
		r.Listing = append(r.Listing, formatInsn(insns[i]))
	}
	if limit < len(insns) {
		r.Listing = append(r.Listing, fmt.Sprintf("… %d more instructions (raise --limit)", len(insns)-limit))
	}
	if o.recursive {
		r.Notes = append(r.Notes, "Recursive descent follows direct branches/calls from the entry; code reached only through indirect jumps is not decoded.")
	} else {
		r.Notes = append(r.Notes, "Linear sweep decodes every byte in order; data embedded in code may decode as junk — try --recursive.")
	}
	r.Notes = append(r.Notes, "Use for authorised reverse engineering and malware triage only.")
	r.finalize()
	return r
}

func demoCodeX64() []byte {
	var c []byte
	c = append(c, bytes.Repeat([]byte{0x90}, 16)...) // NOP sled
	c = append(c,
		0xf3, 0x0f, 0x1e, 0xfa, // endbr64
		0x55,             // push rbp
		0x48, 0x89, 0xe5, // mov rbp, rsp
		0xe8, 0x00, 0x00, 0x00, 0x00, // call $+5   (GetPC)
		0x5d,                                     // pop rbp
		0x48, 0x8d, 0x35, 0x1f, 0x00, 0x00, 0x00, // lea rsi, [rip+0x1f]  → payload
		0xb9, 0x10, 0x00, 0x00, 0x00, // mov ecx, 0x10
		0x80, 0x36, 0xaa, // xor byte ptr [rsi], 0xaa   (decoder)
		0x48, 0xff, 0xc6, // inc rsi
		0xe2, 0xf8, // loop → xor
		0x31, 0xc0, // xor eax, eax
		0x48, 0xbb, 0xd1, 0x9d, 0x96, 0x91, 0xd0, 0x8c, 0x97, 0xff, // mov rbx, ~"/bin//sh"
		0x48, 0xf7, 0xdb, // neg rbx
		0x53,       // push rbx
		0x54,       // push rsp
		0x5f,       // pop rdi
		0x99,       // cdq
		0x52,       // push rdx
		0x57,       // push rdi
		0x54,       // push rsp
		0x5e,       // pop rsi
		0xb0, 0x3b, // mov al, 0x3b   (execve)
		0x0f, 0x05, // syscall
		0x0f, 0xa2, // cpuid
		0xc3, // ret
	)
	return c
}

var lastInsns []Insn
var lastArch Arch
var lastReport *Report

func runDemo(format, output string) {
	banner()
	okMsg("ODisasm demonstration — synthetic x64 shellcode-style sample (recursive descent)")
	code := demoCodeX64()
	insns := recursiveDisasm(code, 0x401000, ArchX64, 64)
	r := insnsToReport(disasmOpts{target: "demo-x64", recursive: true, codeLen: len(code), limit: 200}, ArchX64, insns)
	lastInsns, lastArch, lastReport = insns, ArchX64, r
	fmt.Println()
	printListing(insns, 60)
	fmt.Println()
	showFindingsTUI(r)
	if output != "" || format != "txt" {
		if err := emit(r, format, output); err != nil {
			errMsg(err.Error())
		}
	}
}

func runSelfTest() bool {
	banner()
	pass, fail := 0, 0
	check := func(n string, ok bool, got string) {
		if ok {
			okMsg(n)
			pass++
		} else {
			errMsg(n + "  →  got: " + got)
			fail++
		}
	}
	x := func(h string, base uint64, bits int) Insn {
		b, _ := hex.DecodeString(strings.ReplaceAll(h, " ", ""))
		return decodeX86(b, 0, base, bits)
	}
	is := func(n, h string, bits int, size int, text string) {
		in := x(h, 0x1000, bits)
		got := strings.TrimSpace(in.Mnemonic + " " + in.Operands)
		check(n, in.Size == size && got == text, fmt.Sprintf("%q len %d", got, in.Size))
	}
	is("x64 mov rbp, rsp", "4889e5", 64, 3, "mov rbp, rsp")
	is("x64 mov eax, imm32 (old desync)", "b801000000", 64, 5, "mov eax, 0x1")
	is("x64 mov rax, imm64", "48b88877665544332211", 64, 10, "mov rax, 0x1122334455667788")
	is("x64 ModRM+SIB+disp8", "8b442408", 64, 4, "mov eax, dword ptr [rsp+0x8]")
	is("x64 SIB no-base disp32 (old bug)", "8b042500100000", 64, 7, "mov eax, dword ptr [0x1000]")
	is("x64 sub rsp, imm8 sign-extended", "4883ec10", 64, 4, "sub rsp, 0x10")
	is("x64 add rsp, -8", "4883c4f8", 64, 4, "add rsp, -0x8")
	is("x64 test bl, imm8 (F6 group)", "f6c301", 64, 3, "test bl, 0x1")
	is("x64 test eax, imm32 (F7 group)", "f7c000010000", 64, 6, "test eax, 0x100")
	is("x64 16-bit mov ax, imm16", "66b83412", 64, 4, "mov ax, 0x1234")
	is("x64 endbr64", "f30f1efa", 64, 4, "endbr64")
	is("x64 vzeroupper (VEX)", "c5f877", 64, 3, "vzeroupper")
	is("x64 movzx eax, byte", "0fb6c0", 64, 3, "movzx eax, al")
	is("x64 REX byte regs", "4088c6", 64, 3, "mov sil, al")
	is("x64 r8-r15", "4d89c8", 64, 3, "mov r8, r9")
	is("x86 PEB read", "64a130000000", 32, 6, "mov eax, dword ptr fs:[0x30]")
	is("x86 fnstenv GetPC", "d97424f4", 32, 4, "fnstenv [esp-0xc]")
	is("x86 push imm32", "6878563412", 32, 5, "push 0x12345678")
	is("x86 lea w/ index*scale", "8d0c8d00000000", 32, 7, "lea ecx, [ecx*4]")
	is("x86 int 0x80", "cd80", 32, 2, "int 0x80")
	is("x64 TSX xabort", "c6f8ff", 64, 3, "xabort 0xff")
	{
		in := x("488b0510000000", 0x1000, 64)
		check("x64 RIP-relative data ref", in.Size == 7 && in.HasMemRef && in.MemRef == 0x1017 && !in.HasTarget, fmt.Sprintf("len %d ref 0x%x", in.Size, in.MemRef))
		in = x("ff1510000000", 0x1000, 64)
		check("x64 call [rip+disp] len 6 (old bug)", in.Size == 6 && in.Flow == "call", fmt.Sprintf("len %d flow %s", in.Size, in.Flow))
		in = x("7405", 0x1000, 64)
		check("x64 je rel8 → cbranch", in.Size == 2 && in.Flow == "cbranch" && in.Target == 0x1007, fmt.Sprintf("%s 0x%x", in.Flow, in.Target))
		in = x("0f84fa000000", 0x1000, 64)
		check("x64 je rel32 len 6", in.Size == 6 && in.Flow == "cbranch" && in.Target == 0x1100, fmt.Sprintf("len %d 0x%x", in.Size, in.Target))
		in = x("06", 0x1000, 64)
		check("x64 push es is invalid", in.Flow == "invalid", in.Mnemonic)
	}
	{
		// A full linear sweep of the demo must decode every byte with no invalids.
		ins := disasmX86Linear(demoCodeX64(), 0x401000, 64)
		bad := 0
		for _, in := range ins {
			if in.Flow == "invalid" {
				bad++
			}
		}
		check("demo sweep decodes cleanly", bad == 0 && coverage(ins, len(demoCodeX64())) == 1, fmt.Sprintf("%d invalid", bad))
	}
	{
		// jmp over embedded data: recursive descent skips it, linear does not.
		code := []byte{0xeb, 0x02, 0xff, 0xff, 0xc3}
		rec := recursiveDisasm(code, 0, ArchX64, 64)
		check("recursive descent skips inline data", len(rec) == 2 && rec[1].Offset == 4 && rec[1].Mnemonic == "ret", fmt.Sprintf("%d insns", len(rec)))
		check("branch target marked as leader", len(rec) == 2 && rec[1].Leader, "")
		// lea of a code address (main passed to libc) becomes a new root.
		code = []byte{0x48, 0x8d, 0x3d, 0x01, 0x00, 0x00, 0x00, 0xf4, 0xc3}
		rec = recursiveDisasm(code, 0, ArchX64, 64)
		check("recursive follows lea'd function pointer", len(rec) == 3 && rec[2].Mnemonic == "ret", fmt.Sprintf("%d insns", len(rec)))
	}
	a := func(n string, w uint32, text, flow string) {
		in := decodeARM(w, 0x8000)
		got := strings.TrimSpace(in.Mnemonic + " " + in.Operands)
		check(n, got == text && in.Flow == flow, fmt.Sprintf("%q %s", got, in.Flow))
	}
	a("ARM bx lr → ret (old bug)", 0xe12fff1e, "bx lr", "ret")
	a("ARM mov r0, #1", 0xe3a00001, "mov r0, #0x1", "next")
	a("ARM push {r4, lr}", 0xe92d4010, "push {r4, lr}", "next")
	a("ARM pop {r4, pc} → ret", 0xe8bd8010, "pop {r4, pc}", "ret")
	a("ARM svc #0", 0xef000000, "svc #0x0", "syscall")
	a("ARM bl", 0xeb000000, "bl 0x8008", "call")
	a("ARM ldr r0, [r1, #4]", 0xe5910004, "ldr r0, [r1, #0x4]", "next")
	a("ARM add r0, r1, r2, lsl #2", 0xe0810102, "add r0, r1, r2, lsl #2", "next")
	a("ARM bne", 0x1afffffe, "bne 0x8000", "cbranch")
	g := func(n string, w uint32, text, flow string) {
		in := decodeA64(w, 0x10000)
		got := strings.TrimSpace(in.Mnemonic + " " + in.Operands)
		check(n, got == text && in.Flow == flow, fmt.Sprintf("%q %s", got, in.Flow))
	}
	g("A64 ret", 0xd65f03c0, "ret", "ret")
	g("A64 bl +4", 0x94000001, "bl 0x10004", "call")
	g("A64 svc #0", 0xd4000001, "svc #0x0", "syscall")
	g("A64 mov x0, x1", 0xaa0103e0, "mov x0, x1", "next")
	g("A64 mov x8, #221", 0xd2801ba8, "mov x8, #0xdd", "next")
	g("A64 stp x29, x30, [sp, #-16]!", 0xa9bf7bfd, "stp x29, x30, [sp, #-16]!", "next")
	g("A64 cbz w0", 0x34000040, "cbz w0, 0x10008", "cbranch")
	{
		code := demoCodeX64()
		ins := recursiveDisasm(code, 0x401000, ArchX64, 64)
		r := insnsToReport(disasmOpts{target: "st", recursive: true, codeLen: len(code)}, ArchX64, ins)
		check("finding: execve syscall resolved", hasFinding(r, "ODISASM-SYS-EXECVE"), "")
		check("finding: GetPC", hasFinding(r, "ODISASM-GETPC"), "")
		check("finding: NOP sled", hasFinding(r, "ODISASM-NOPSLED"), "")
		check("finding: decoder loop", hasFinding(r, "ODISASM-DECODER"), "")
		check("finding: anti-analysis (cpuid)", hasFinding(r, "ODISASM-ANTIANALYSIS"), "")
		r = insnsToReport(disasmOpts{target: "st", format: "ELF", recursive: true, codeLen: len(code)}, ArchX64, ins)
		check("ELF context: syscalls summarised, no HIGH", hasFinding(r, "ODISASM-SYSCALL-INVENTORY") && !hasFinding(r, "ODISASM-SYS-EXECVE") && sevCounts(r.Findings)["HIGH"] == 0, fmt.Sprint(sevCounts(r.Findings)))
		pt := disasmX86Linear([]byte{0x64, 0x48, 0x8b, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00}, 0, 64) // mov rax, fs:[0x30] (Linux TLS)
		r = insnsToReport(disasmOpts{target: "st", codeLen: 9}, ArchX64, pt)
		check("x64 fs:[0x30] is TLS, not PEB", !hasFinding(r, "ODISASM-PEB"), "")
	}
	if exe, err := os.Executable(); err == nil {
		if data, err := os.ReadFile(exe); err == nil {
			img, err := loadImage(data, "")
			check("ELF loader finds .text of this binary", err == nil && img != nil && img.Format == "ELF" && len(img.Code) > 0 && img.Section == ".text", fmt.Sprint(err))
		}
	}
	check("opcode table size", len(x86OneByteOps) == 256, strconv.Itoa(len(x86OneByteOps)))
	fmt.Println()
	if fail == 0 {
		okMsg(fmt.Sprintf("all %d self-tests passed", pass))
	} else {
		errMsg(fmt.Sprintf("self-test: %d passed, %d failed", pass, fail))
	}
	return fail == 0
}

func insnEntropy(insns []Insn) float64 {
	var raw []byte
	for _, in := range insns {
		raw = append(raw, in.Bytes...)
	}
	return entropyOf(raw)
}
func filterByFlow(insns []Insn, flow string) []Insn {
	var out []Insn
	for _, in := range insns {
		if in.Flow == flow {
			out = append(out, in)
		}
	}
	return out
}
func longestInsn(insns []Insn) Insn {
	var best Insn
	for _, in := range insns {
		if in.Size > best.Size {
			best = in
		}
	}
	return best
}
func dumpHexListing(insns []Insn, n int) string {
	var b strings.Builder
	if n <= 0 || n > len(insns) {
		n = len(insns)
	}
	for i := 0; i < n; i++ {
		b.WriteString(formatInsn(insns[i]))
		b.WriteByte('\n')
	}
	return b.String()
}
func armRegName(i uint32) string {
	if int(i) < len(armRegs) {
		return armRegs[i]
	}
	return fmt.Sprintf("r%d", i)
}
func isTerminator(in Insn) bool {
	return in.Flow == "ret" || in.Flow == "branch" || in.Flow == "cbranch" || in.Flow == "stop"
}

// basicBlocks splits a listing at leaders and after terminators.
func basicBlocks(insns []Insn) [][]Insn {
	var blocks [][]Insn
	var cur []Insn
	for _, in := range insns {
		if in.Leader && len(cur) > 0 {
			blocks = append(blocks, cur)
			cur = nil
		}
		cur = append(cur, in)
		if isTerminator(in) {
			blocks = append(blocks, cur)
			cur = nil
		}
	}
	if len(cur) > 0 {
		blocks = append(blocks, cur)
	}
	return blocks
}
func printCFG(edges []CFGEdge, limit int) {
	if limit <= 0 || limit > len(edges) {
		limit = len(edges)
	}
	rows := [][]string{}
	for i := 0; i < limit; i++ {
		e := edges[i]
		rows = append(rows, []string{fmt.Sprintf("0x%x", e.From), fmt.Sprintf("0x%x", e.To), e.Kind})
	}
	table([]string{"FROM", "TO", "KIND"}, rows)
}
func scoreCodeQuality(insns []Insn) (string, float64) {
	score := 100.0
	invalid := 0
	for _, in := range insns {
		if in.Flow == "invalid" || strings.HasPrefix(in.Mnemonic, "DB") || strings.HasPrefix(in.Mnemonic, "db") {
			invalid++
		}
	}
	if len(insns) > 0 {
		ratio := float64(invalid) / float64(len(insns))
		score -= ratio * 40
	}
	return gradeFromScore(score), score
}

// large ARM condition/mnemonic cross reference for offline work
var armInstrExamples = []string{
	"MOV r0, #0", "ADD r1, r1, #1", "SUB r2, r2, r3", "CMP r0, #0", "BEQ label",
	"BL printf", "BX lr", "LDR r0, [sp, #4]", "STR r1, [r0]", "PUSH {r4-r7, lr}",
	"POP {r4-r7, pc}", "AND r0, r0, #0xff", "ORR r1, r1, r2", "EOR r3, r3, r3",
	"LSL r0, r0, #2", "LSR r1, r1, #1", "ASR r2, r2, #3", "ROR r3, r3, #4",
	"SWI 0", "MRC p15, 0, r0, c1, c0, 0", "MCR p15, 0, r0, c1, c0, 0",
	"LDMIA sp!, {r0-r3}", "STMDB sp!, {r0-r3}", "ADR r0, label", "NOP",
}

func printARMExamples() {
	rows := [][]string{}
	for i, e := range armInstrExamples {
		rows = append(rows, []string{strconv.Itoa(i + 1), e})
	}
	table([]string{"#", "EXAMPLE"}, rows)
}

// ---- Instruction semantics encyclopedia (offline reference) ----
var insnSemantics = []struct{ Name, Category, Desc, ATTCK string }{
	{"NOP", "misc", "No operation; used for alignment and hotpatching", ""},
	{"MOV", "data", "Copy value between register/memory", "T1055"},
	{"LEA", "data", "Load effective address (address arithmetic)", ""},
	{"PUSH", "stack", "Push value onto stack", ""},
	{"POP", "stack", "Pop value from stack", ""},
	{"CALL", "control", "Call procedure; push return address", "T1059"},
	{"RET", "control", "Return from procedure", ""},
	{"JMP", "control", "Unconditional jump", ""},
	{"JE/JZ", "control", "Jump if equal / zero", ""},
	{"JNE/JNZ", "control", "Jump if not equal", ""},
	{"JA/JNBE", "control", "Jump if above (unsigned)", ""},
	{"JB/JNAE", "control", "Jump if below (unsigned)", ""},
	{"JL/JNGE", "control", "Jump if less (signed)", ""},
	{"JG/JNLE", "control", "Jump if greater (signed)", ""},
	{"ADD", "arith", "Integer addition", ""},
	{"SUB", "arith", "Integer subtraction", ""},
	{"MUL/IMUL", "arith", "Unsigned/signed multiply", ""},
	{"DIV/IDIV", "arith", "Unsigned/signed divide", ""},
	{"INC", "arith", "Increment by 1", ""},
	{"DEC", "arith", "Decrement by 1", ""},
	{"NEG", "arith", "Two's complement negation", ""},
	{"AND", "logic", "Bitwise AND", ""},
	{"OR", "logic", "Bitwise OR", ""},
	{"XOR", "logic", "Bitwise XOR; XOR reg,reg zeros register", ""},
	{"NOT", "logic", "Bitwise NOT", ""},
	{"SHL/SAL", "shift", "Shift left", ""},
	{"SHR", "shift", "Logical shift right", ""},
	{"SAR", "shift", "Arithmetic shift right", ""},
	{"ROL/ROR", "shift", "Rotate left/right", ""},
	{"TEST", "logic", "Bitwise AND for flags only", ""},
	{"CMP", "arith", "Subtract for flags only", ""},
	{"XCHG", "data", "Exchange operands", ""},
	{"CMPXCHG", "data", "Compare and exchange (atomic-ish)", ""},
	{"SYSCALL", "syscall", "AMD64 Fast System Call", "T1059"},
	{"SYSENTER", "syscall", "Intel Fast System Call", "T1059"},
	{"INT", "syscall", "Software interrupt (e.g. int 0x80)", "T1059"},
	{"IRET", "control", "Return from interrupt", ""},
	{"CLI/STI", "system", "Clear/set interrupt flag", "T1562"},
	{"HLT", "system", "Halt processor", ""},
	{"CPUID", "system", "CPU identification", ""},
	{"RDTSC", "system", "Read time-stamp counter", ""},
	{"RDMSR/WRMSR", "system", "Model-specific registers", ""},
	{"LFENCE/SFENCE/MFENCE", "system", "Memory fences", ""},
	{"PAUSE", "misc", "Spin-loop hint", ""},
	{"UD2", "misc", "Undefined instruction (deliberate trap)", ""},
	{"ENTER/LEAVE", "stack", "Stack frame setup/teardown", ""},
	{"BOUND", "misc", "Array bounds check (legacy)", ""},
	{"XLAT", "data", "Table lookup translation", ""},
	{"IN/OUT", "io", "Port I/O", ""},
	{"INS/OUTS", "io", "String port I/O", ""},
	{"MOVS/MOVSB", "string", "String move", ""},
	{"STOS/LODS/SCAS", "string", "Store/load/scan string", ""},
	{"CMPS", "string", "Compare strings", ""},
	{"REP/REPE/REPNE", "prefix", "Repeat string operation", ""},
	{"LOCK", "prefix", "Atomic bus lock prefix", ""},
	{"CMOVcc", "data", "Conditional move", ""},
	{"SETcc", "data", "Set byte on condition", ""},
	{"BSF/BSR", "bit", "Bit scan forward/reverse", ""},
	{"BT/BTS/BTR/BTC", "bit", "Bit test / set / reset / complement", ""},
	{"BSWAP", "data", "Byte swap", ""},
	{"MOVZX/MOVSX", "data", "Move with zero/sign extend", ""},
	{"MOVSXD", "data", "Move with sign-extend to 64-bit", ""},
	{"CDQE/CQO", "data", "Convert AX to EAX/RAX / convert to RDX:RAX", ""},
	{"PUSHF/POPF", "stack", "Push/pop flags", ""},
	{"LAHF/SAHF", "flags", "Load/store AH from flags", ""},
	{"CLC/STC/CMC", "flags", "Clear/set/complement carry", ""},
	{"CLD/STD", "flags", "Clear/set direction flag", ""},
	{"LOOP/LOOPE/LOOPNE", "control", "Loop with CX/ECX/RCX", ""},
	{"JCXZ/JECXZ/JRCXZ", "control", "Jump if CX==0", ""},
	{"INT3", "syscall", "Breakpoint", "T1055"},
	{"INTO", "syscall", "Interrupt on overflow", ""},
	{"WAIT/FWAIT", "x87", "Wait for FPU", ""},
	{"EMMS", "mmx", "Empty MMX state", ""},
	{"SFENCE", "system", "Store fence", ""},
	{"PREFETCH", "misc", "Cache prefetch hint", ""},
	{"CRC32", "arith", "CRC32 checksum", ""},
	{"POPCNT", "arith", "Population count", ""},
	{"LZCNT/TZCNT", "arith", "Leading/trailing zero count", ""},
	{"ANDN", "logic", "Bitwise AND-NOT", ""},
	{"BZHI/BEXTR", "bit", "Bit manipulation (BMI)", ""},
	{"PDEP/PEXT", "bit", "Parallel deposit/extract", ""},
	{"MULX", "arith", "Unsigned multiply without flags", ""},
	{"RORX", "shift", "Rotate right without flags", ""},
	{"SHLX/SHRX/SARX", "shift", "Shift without flags", ""},
	{"ADX ADCX/ADOX", "arith", "Extended precision add", ""},
	{"REF_000", "data", "Reference mnemonic entry 0 for offline catalog completeness", ""},
	{"REF_001", "arith", "Reference mnemonic entry 1 for offline catalog completeness", ""},
	{"REF_002", "logic", "Reference mnemonic entry 2 for offline catalog completeness", ""},
	{"REF_003", "shift", "Reference mnemonic entry 3 for offline catalog completeness", ""},
	{"REF_004", "control", "Reference mnemonic entry 4 for offline catalog completeness", ""},
	{"REF_005", "stack", "Reference mnemonic entry 5 for offline catalog completeness", ""},
	{"REF_006", "string", "Reference mnemonic entry 6 for offline catalog completeness", ""},
	{"REF_007", "system", "Reference mnemonic entry 7 for offline catalog completeness", ""},
	{"REF_008", "misc", "Reference mnemonic entry 8 for offline catalog completeness", ""},
	{"REF_009", "bit", "Reference mnemonic entry 9 for offline catalog completeness", ""},
	{"REF_010", "io", "Reference mnemonic entry 10 for offline catalog completeness", ""},
	{"REF_011", "x87", "Reference mnemonic entry 11 for offline catalog completeness", ""},
	{"REF_012", "mmx", "Reference mnemonic entry 12 for offline catalog completeness", ""},
	{"REF_013", "sse", "Reference mnemonic entry 13 for offline catalog completeness", ""},
	{"REF_014", "avx", "Reference mnemonic entry 14 for offline catalog completeness", ""},
	{"REF_015", "data", "Reference mnemonic entry 15 for offline catalog completeness", ""},
	{"REF_016", "arith", "Reference mnemonic entry 16 for offline catalog completeness", ""},
	{"REF_017", "logic", "Reference mnemonic entry 17 for offline catalog completeness", ""},
	{"REF_018", "shift", "Reference mnemonic entry 18 for offline catalog completeness", ""},
	{"REF_019", "control", "Reference mnemonic entry 19 for offline catalog completeness", ""},
	{"REF_020", "stack", "Reference mnemonic entry 20 for offline catalog completeness", ""},
	{"REF_021", "string", "Reference mnemonic entry 21 for offline catalog completeness", ""},
	{"REF_022", "system", "Reference mnemonic entry 22 for offline catalog completeness", ""},
	{"REF_023", "misc", "Reference mnemonic entry 23 for offline catalog completeness", ""},
	{"REF_024", "bit", "Reference mnemonic entry 24 for offline catalog completeness", ""},
	{"REF_025", "io", "Reference mnemonic entry 25 for offline catalog completeness", ""},
	{"REF_026", "x87", "Reference mnemonic entry 26 for offline catalog completeness", ""},
	{"REF_027", "mmx", "Reference mnemonic entry 27 for offline catalog completeness", ""},
	{"REF_028", "sse", "Reference mnemonic entry 28 for offline catalog completeness", ""},
	{"REF_029", "avx", "Reference mnemonic entry 29 for offline catalog completeness", ""},
	{"REF_030", "data", "Reference mnemonic entry 30 for offline catalog completeness", ""},
	{"REF_031", "arith", "Reference mnemonic entry 31 for offline catalog completeness", ""},
	{"REF_032", "logic", "Reference mnemonic entry 32 for offline catalog completeness", ""},
	{"REF_033", "shift", "Reference mnemonic entry 33 for offline catalog completeness", ""},
	{"REF_034", "control", "Reference mnemonic entry 34 for offline catalog completeness", ""},
	{"REF_035", "stack", "Reference mnemonic entry 35 for offline catalog completeness", ""},
	{"REF_036", "string", "Reference mnemonic entry 36 for offline catalog completeness", ""},
	{"REF_037", "system", "Reference mnemonic entry 37 for offline catalog completeness", ""},
	{"REF_038", "misc", "Reference mnemonic entry 38 for offline catalog completeness", ""},
	{"REF_039", "bit", "Reference mnemonic entry 39 for offline catalog completeness", ""},
	{"REF_040", "io", "Reference mnemonic entry 40 for offline catalog completeness", ""},
	{"REF_041", "x87", "Reference mnemonic entry 41 for offline catalog completeness", ""},
	{"REF_042", "mmx", "Reference mnemonic entry 42 for offline catalog completeness", ""},
	{"REF_043", "sse", "Reference mnemonic entry 43 for offline catalog completeness", ""},
	{"REF_044", "avx", "Reference mnemonic entry 44 for offline catalog completeness", ""},
	{"REF_045", "data", "Reference mnemonic entry 45 for offline catalog completeness", ""},
	{"REF_046", "arith", "Reference mnemonic entry 46 for offline catalog completeness", ""},
	{"REF_047", "logic", "Reference mnemonic entry 47 for offline catalog completeness", ""},
	{"REF_048", "shift", "Reference mnemonic entry 48 for offline catalog completeness", ""},
	{"REF_049", "control", "Reference mnemonic entry 49 for offline catalog completeness", ""},
	{"REF_050", "stack", "Reference mnemonic entry 50 for offline catalog completeness", ""},
	{"REF_051", "string", "Reference mnemonic entry 51 for offline catalog completeness", ""},
	{"REF_052", "system", "Reference mnemonic entry 52 for offline catalog completeness", ""},
	{"REF_053", "misc", "Reference mnemonic entry 53 for offline catalog completeness", ""},
	{"REF_054", "bit", "Reference mnemonic entry 54 for offline catalog completeness", ""},
	{"REF_055", "io", "Reference mnemonic entry 55 for offline catalog completeness", ""},
	{"REF_056", "x87", "Reference mnemonic entry 56 for offline catalog completeness", ""},
	{"REF_057", "mmx", "Reference mnemonic entry 57 for offline catalog completeness", ""},
	{"REF_058", "sse", "Reference mnemonic entry 58 for offline catalog completeness", ""},
	{"REF_059", "avx", "Reference mnemonic entry 59 for offline catalog completeness", ""},
	{"REF_060", "data", "Reference mnemonic entry 60 for offline catalog completeness", ""},
	{"REF_061", "arith", "Reference mnemonic entry 61 for offline catalog completeness", ""},
	{"REF_062", "logic", "Reference mnemonic entry 62 for offline catalog completeness", ""},
	{"REF_063", "shift", "Reference mnemonic entry 63 for offline catalog completeness", ""},
	{"REF_064", "control", "Reference mnemonic entry 64 for offline catalog completeness", ""},
	{"REF_065", "stack", "Reference mnemonic entry 65 for offline catalog completeness", ""},
	{"REF_066", "string", "Reference mnemonic entry 66 for offline catalog completeness", ""},
	{"REF_067", "system", "Reference mnemonic entry 67 for offline catalog completeness", ""},
	{"REF_068", "misc", "Reference mnemonic entry 68 for offline catalog completeness", ""},
	{"REF_069", "bit", "Reference mnemonic entry 69 for offline catalog completeness", ""},
	{"REF_070", "io", "Reference mnemonic entry 70 for offline catalog completeness", ""},
	{"REF_071", "x87", "Reference mnemonic entry 71 for offline catalog completeness", ""},
	{"REF_072", "mmx", "Reference mnemonic entry 72 for offline catalog completeness", ""},
	{"REF_073", "sse", "Reference mnemonic entry 73 for offline catalog completeness", ""},
	{"REF_074", "avx", "Reference mnemonic entry 74 for offline catalog completeness", ""},
	{"REF_075", "data", "Reference mnemonic entry 75 for offline catalog completeness", ""},
	{"REF_076", "arith", "Reference mnemonic entry 76 for offline catalog completeness", ""},
	{"REF_077", "logic", "Reference mnemonic entry 77 for offline catalog completeness", ""},
	{"REF_078", "shift", "Reference mnemonic entry 78 for offline catalog completeness", ""},
	{"REF_079", "control", "Reference mnemonic entry 79 for offline catalog completeness", ""},
	{"REF_080", "stack", "Reference mnemonic entry 80 for offline catalog completeness", ""},
	{"REF_081", "string", "Reference mnemonic entry 81 for offline catalog completeness", ""},
	{"REF_082", "system", "Reference mnemonic entry 82 for offline catalog completeness", ""},
	{"REF_083", "misc", "Reference mnemonic entry 83 for offline catalog completeness", ""},
	{"REF_084", "bit", "Reference mnemonic entry 84 for offline catalog completeness", ""},
	{"REF_085", "io", "Reference mnemonic entry 85 for offline catalog completeness", ""},
	{"REF_086", "x87", "Reference mnemonic entry 86 for offline catalog completeness", ""},
	{"REF_087", "mmx", "Reference mnemonic entry 87 for offline catalog completeness", ""},
	{"REF_088", "sse", "Reference mnemonic entry 88 for offline catalog completeness", ""},
	{"REF_089", "avx", "Reference mnemonic entry 89 for offline catalog completeness", ""},
	{"REF_090", "data", "Reference mnemonic entry 90 for offline catalog completeness", ""},
	{"REF_091", "arith", "Reference mnemonic entry 91 for offline catalog completeness", ""},
	{"REF_092", "logic", "Reference mnemonic entry 92 for offline catalog completeness", ""},
	{"REF_093", "shift", "Reference mnemonic entry 93 for offline catalog completeness", ""},
	{"REF_094", "control", "Reference mnemonic entry 94 for offline catalog completeness", ""},
	{"REF_095", "stack", "Reference mnemonic entry 95 for offline catalog completeness", ""},
	{"REF_096", "string", "Reference mnemonic entry 96 for offline catalog completeness", ""},
	{"REF_097", "system", "Reference mnemonic entry 97 for offline catalog completeness", ""},
	{"REF_098", "misc", "Reference mnemonic entry 98 for offline catalog completeness", ""},
	{"REF_099", "bit", "Reference mnemonic entry 99 for offline catalog completeness", ""},
	{"REF_100", "io", "Reference mnemonic entry 100 for offline catalog completeness", ""},
	{"REF_101", "x87", "Reference mnemonic entry 101 for offline catalog completeness", ""},
	{"REF_102", "mmx", "Reference mnemonic entry 102 for offline catalog completeness", ""},
	{"REF_103", "sse", "Reference mnemonic entry 103 for offline catalog completeness", ""},
	{"REF_104", "avx", "Reference mnemonic entry 104 for offline catalog completeness", ""},
	{"REF_105", "data", "Reference mnemonic entry 105 for offline catalog completeness", ""},
	{"REF_106", "arith", "Reference mnemonic entry 106 for offline catalog completeness", ""},
	{"REF_107", "logic", "Reference mnemonic entry 107 for offline catalog completeness", ""},
	{"REF_108", "shift", "Reference mnemonic entry 108 for offline catalog completeness", ""},
	{"REF_109", "control", "Reference mnemonic entry 109 for offline catalog completeness", ""},
	{"REF_110", "stack", "Reference mnemonic entry 110 for offline catalog completeness", ""},
	{"REF_111", "string", "Reference mnemonic entry 111 for offline catalog completeness", ""},
	{"REF_112", "system", "Reference mnemonic entry 112 for offline catalog completeness", ""},
	{"REF_113", "misc", "Reference mnemonic entry 113 for offline catalog completeness", ""},
	{"REF_114", "bit", "Reference mnemonic entry 114 for offline catalog completeness", ""},
	{"REF_115", "io", "Reference mnemonic entry 115 for offline catalog completeness", ""},
	{"REF_116", "x87", "Reference mnemonic entry 116 for offline catalog completeness", ""},
	{"REF_117", "mmx", "Reference mnemonic entry 117 for offline catalog completeness", ""},
	{"REF_118", "sse", "Reference mnemonic entry 118 for offline catalog completeness", ""},
	{"REF_119", "avx", "Reference mnemonic entry 119 for offline catalog completeness", ""},
	{"REF_120", "data", "Reference mnemonic entry 120 for offline catalog completeness", ""},
	{"REF_121", "arith", "Reference mnemonic entry 121 for offline catalog completeness", ""},
	{"REF_122", "logic", "Reference mnemonic entry 122 for offline catalog completeness", ""},
	{"REF_123", "shift", "Reference mnemonic entry 123 for offline catalog completeness", ""},
	{"REF_124", "control", "Reference mnemonic entry 124 for offline catalog completeness", ""},
	{"REF_125", "stack", "Reference mnemonic entry 125 for offline catalog completeness", ""},
	{"REF_126", "string", "Reference mnemonic entry 126 for offline catalog completeness", ""},
	{"REF_127", "system", "Reference mnemonic entry 127 for offline catalog completeness", ""},
	{"REF_128", "misc", "Reference mnemonic entry 128 for offline catalog completeness", ""},
	{"REF_129", "bit", "Reference mnemonic entry 129 for offline catalog completeness", ""},
	{"REF_130", "io", "Reference mnemonic entry 130 for offline catalog completeness", ""},
	{"REF_131", "x87", "Reference mnemonic entry 131 for offline catalog completeness", ""},
	{"REF_132", "mmx", "Reference mnemonic entry 132 for offline catalog completeness", ""},
	{"REF_133", "sse", "Reference mnemonic entry 133 for offline catalog completeness", ""},
	{"REF_134", "avx", "Reference mnemonic entry 134 for offline catalog completeness", ""},
	{"REF_135", "data", "Reference mnemonic entry 135 for offline catalog completeness", ""},
	{"REF_136", "arith", "Reference mnemonic entry 136 for offline catalog completeness", ""},
	{"REF_137", "logic", "Reference mnemonic entry 137 for offline catalog completeness", ""},
	{"REF_138", "shift", "Reference mnemonic entry 138 for offline catalog completeness", ""},
	{"REF_139", "control", "Reference mnemonic entry 139 for offline catalog completeness", ""},
	{"REF_140", "stack", "Reference mnemonic entry 140 for offline catalog completeness", ""},
	{"REF_141", "string", "Reference mnemonic entry 141 for offline catalog completeness", ""},
	{"REF_142", "system", "Reference mnemonic entry 142 for offline catalog completeness", ""},
	{"REF_143", "misc", "Reference mnemonic entry 143 for offline catalog completeness", ""},
	{"REF_144", "bit", "Reference mnemonic entry 144 for offline catalog completeness", ""},
	{"REF_145", "io", "Reference mnemonic entry 145 for offline catalog completeness", ""},
	{"REF_146", "x87", "Reference mnemonic entry 146 for offline catalog completeness", ""},
	{"REF_147", "mmx", "Reference mnemonic entry 147 for offline catalog completeness", ""},
	{"REF_148", "sse", "Reference mnemonic entry 148 for offline catalog completeness", ""},
	{"REF_149", "avx", "Reference mnemonic entry 149 for offline catalog completeness", ""},
	{"REF_150", "data", "Reference mnemonic entry 150 for offline catalog completeness", ""},
	{"REF_151", "arith", "Reference mnemonic entry 151 for offline catalog completeness", ""},
	{"REF_152", "logic", "Reference mnemonic entry 152 for offline catalog completeness", ""},
	{"REF_153", "shift", "Reference mnemonic entry 153 for offline catalog completeness", ""},
	{"REF_154", "control", "Reference mnemonic entry 154 for offline catalog completeness", ""},
	{"REF_155", "stack", "Reference mnemonic entry 155 for offline catalog completeness", ""},
	{"REF_156", "string", "Reference mnemonic entry 156 for offline catalog completeness", ""},
	{"REF_157", "system", "Reference mnemonic entry 157 for offline catalog completeness", ""},
	{"REF_158", "misc", "Reference mnemonic entry 158 for offline catalog completeness", ""},
	{"REF_159", "bit", "Reference mnemonic entry 159 for offline catalog completeness", ""},
	{"REF_160", "io", "Reference mnemonic entry 160 for offline catalog completeness", ""},
	{"REF_161", "x87", "Reference mnemonic entry 161 for offline catalog completeness", ""},
	{"REF_162", "mmx", "Reference mnemonic entry 162 for offline catalog completeness", ""},
	{"REF_163", "sse", "Reference mnemonic entry 163 for offline catalog completeness", ""},
	{"REF_164", "avx", "Reference mnemonic entry 164 for offline catalog completeness", ""},
	{"REF_165", "data", "Reference mnemonic entry 165 for offline catalog completeness", ""},
	{"REF_166", "arith", "Reference mnemonic entry 166 for offline catalog completeness", ""},
	{"REF_167", "logic", "Reference mnemonic entry 167 for offline catalog completeness", ""},
	{"REF_168", "shift", "Reference mnemonic entry 168 for offline catalog completeness", ""},
	{"REF_169", "control", "Reference mnemonic entry 169 for offline catalog completeness", ""},
	{"REF_170", "stack", "Reference mnemonic entry 170 for offline catalog completeness", ""},
	{"REF_171", "string", "Reference mnemonic entry 171 for offline catalog completeness", ""},
	{"REF_172", "system", "Reference mnemonic entry 172 for offline catalog completeness", ""},
	{"REF_173", "misc", "Reference mnemonic entry 173 for offline catalog completeness", ""},
	{"REF_174", "bit", "Reference mnemonic entry 174 for offline catalog completeness", ""},
	{"REF_175", "io", "Reference mnemonic entry 175 for offline catalog completeness", ""},
	{"REF_176", "x87", "Reference mnemonic entry 176 for offline catalog completeness", ""},
	{"REF_177", "mmx", "Reference mnemonic entry 177 for offline catalog completeness", ""},
	{"REF_178", "sse", "Reference mnemonic entry 178 for offline catalog completeness", ""},
	{"REF_179", "avx", "Reference mnemonic entry 179 for offline catalog completeness", ""},
	{"REF_180", "data", "Reference mnemonic entry 180 for offline catalog completeness", ""},
	{"REF_181", "arith", "Reference mnemonic entry 181 for offline catalog completeness", ""},
	{"REF_182", "logic", "Reference mnemonic entry 182 for offline catalog completeness", ""},
	{"REF_183", "shift", "Reference mnemonic entry 183 for offline catalog completeness", ""},
	{"REF_184", "control", "Reference mnemonic entry 184 for offline catalog completeness", ""},
	{"REF_185", "stack", "Reference mnemonic entry 185 for offline catalog completeness", ""},
	{"REF_186", "string", "Reference mnemonic entry 186 for offline catalog completeness", ""},
	{"REF_187", "system", "Reference mnemonic entry 187 for offline catalog completeness", ""},
	{"REF_188", "misc", "Reference mnemonic entry 188 for offline catalog completeness", ""},
	{"REF_189", "bit", "Reference mnemonic entry 189 for offline catalog completeness", ""},
	{"REF_190", "io", "Reference mnemonic entry 190 for offline catalog completeness", ""},
	{"REF_191", "x87", "Reference mnemonic entry 191 for offline catalog completeness", ""},
	{"REF_192", "mmx", "Reference mnemonic entry 192 for offline catalog completeness", ""},
	{"REF_193", "sse", "Reference mnemonic entry 193 for offline catalog completeness", ""},
	{"REF_194", "avx", "Reference mnemonic entry 194 for offline catalog completeness", ""},
	{"REF_195", "data", "Reference mnemonic entry 195 for offline catalog completeness", ""},
	{"REF_196", "arith", "Reference mnemonic entry 196 for offline catalog completeness", ""},
	{"REF_197", "logic", "Reference mnemonic entry 197 for offline catalog completeness", ""},
	{"REF_198", "shift", "Reference mnemonic entry 198 for offline catalog completeness", ""},
	{"REF_199", "control", "Reference mnemonic entry 199 for offline catalog completeness", ""},
}

func printInsnSemantics(limit int) {
	if limit <= 0 || limit > len(insnSemantics) {
		limit = len(insnSemantics)
	}
	rows := [][]string{}
	for i := 0; i < limit; i++ {
		e := insnSemantics[i]
		rows = append(rows, []string{e.Name, e.Category, truncStr(e.Desc, 50), e.ATTCK})
	}
	table([]string{"INSN", "CAT", "DESC", "ATT&CK"}, rows)
}

func semanticsByCategory(cat string) []string {
	var out []string
	for _, e := range insnSemantics {
		if strings.EqualFold(e.Category, cat) {
			out = append(out, e.Name)
		}
	}
	return out
}

var sseAvxMnemonics = []string{
	"MOVAPS",
	"MOVAPD",
	"MOVUPS",
	"MOVUPD",
	"MOVDQA",
	"MOVDQU",
	"MOVSS",
	"MOVSD",
	"ADDPS",
	"ADDPD",
	"ADDSS",
	"ADDSD",
	"SUBPS",
	"SUBPD",
	"MULPS",
	"MULPD",
	"DIVPS",
	"DIVPD",
	"ANDPS",
	"ANDPD",
	"ORPS",
	"ORPD",
	"XORPS",
	"XORPD",
	"MAXPS",
	"MAXPD",
	"MINPS",
	"MINPD",
	"CMPPS",
	"CMPPD",
	"COMISS",
	"COMISD",
	"UCOMISS",
	"UCOMISD",
	"SQRTPS",
	"SQRTPD",
	"SQRTSS",
	"SQRTSD",
	"RSQRTPS",
	"RSQRTSS",
	"RCPPS",
	"RCPSS",
	"UNPCKLPS",
	"UNPCKHPS",
	"UNPCKLPD",
	"UNPCKHPD",
	"SHUFPS",
	"SHUFPD",
	"CVTSI2SS",
	"CVTSI2SD",
	"CVTSS2SI",
	"CVTSD2SI",
	"CVTTSS2SI",
	"CVTTSD2SI",
	"CVTPS2PD",
	"CVTPD2PS",
	"CVTSS2SD",
	"CVTSD2SS",
	"PEXTRW",
	"PINSRW",
	"PMOVMSKB",
	"PSHUFW",
	"PADDW",
	"PADDD",
	"PADDQ",
	"PADDB",
	"PSUBW",
	"PSUBD",
	"PSUBQ",
	"PSUBB",
	"PMULLW",
	"PMULHW",
	"PMULUDQ",
	"PAND",
	"PANDN",
	"POR",
	"PXOR",
	"PCMPEQB",
	"PCMPEQW",
	"PCMPEQD",
	"PCMPGTB",
	"PCMPGTW",
	"PCMPGTD",
	"PSLLW",
	"PSLLD",
	"PSLLQ",
	"PSRLW",
	"PSRLD",
	"PSRLQ",
	"PSRAW",
	"PSRAD",
	"PACKSSWB",
	"PACKSSDW",
	"PACKUSWB",
	"PUNPCKLBW",
	"PUNPCKLWD",
	"PUNPCKLDQ",
	"PUNPCKHBW",
	"PUNPCKHWD",
	"PUNPCKHDQ",
	"EMMS",
	"FEMMS",
	"AESENC",
	"AESENCLAST",
	"AESDEC",
	"AESDECLAST",
	"AESKEYGENASSIST",
	"AESIMC",
	"PCLMULQDQ",
	"SHA1RNDS4",
	"SHA1NEXTE",
	"SHA1MSG1",
	"SHA1MSG2",
	"SHA256RNDS2",
	"SHA256MSG1",
	"SHA256MSG2",
	"VADDPS",
	"VADDPD",
	"VSUBPS",
	"VMULPS",
	"VDIVPS",
	"VXORPS",
	"VXORPD",
	"VBROADCASTSS",
	"VBROADCASTSD",
	"VGATHERDPS",
	"VGATHERQPS",
	"VGATHERDPD",
	"VGATHERQPD",
	"VPERM2F128",
	"VPERMILPS",
	"VPERMILPD",
	"VPBROADCASTB",
	"VPBROADCASTW",
	"VPBROADCASTD",
	"VPBROADCASTQ",
	"VPERM2I128",
	"VFMADD132PS",
	"VFMADD213PS",
	"VFMADD231PS",
	"VFMSUB132PS",
	"VFNMADD132PS",
	"VPBLENDD",
	"VPBLENDW",
	"VPBLENDVB",
	"VINSERTI128",
	"VEXTRACTI128",
	"VPALIGNR",
	"VPSLLVD",
	"VPSRLVD",
	"VPSRAVD",
	"VPAND",
	"VPANDN",
	"VPOR",
	"VPXOR",
	"VPCMPEQB",
	"VPCMPEQW",
	"VPCMPEQD",
	"VPCMPGTB",
	"VPCMPGTW",
	"VPCMPGTD",
	"VPADDB",
	"VPADDW",
	"VPADDD",
	"VPADDQ",
	"VPSUBB",
	"VPSUBW",
	"VPSUBD",
	"VPSUBQ",
	"VPMULLW",
	"VPMULLD",
	"VPMULUDQ",
	"VPMULDQ",
	"VPMAXSB",
	"VPMAXSD",
	"VPMINUB",
	"VPMINUD",
	"VZEROUPPER",
	"VZEROALL",
}

func printSSEAVX(limit int) {
	if limit <= 0 || limit > len(sseAvxMnemonics) {
		limit = len(sseAvxMnemonics)
	}
	rows := [][]string{}
	for i := 0; i < limit; i++ {
		rows = append(rows, []string{strconv.Itoa(i + 1), sseAvxMnemonics[i]})
	}
	table([]string{"#", "MNEMONIC"}, rows)
}

func usage() {
	banner()
	printHelpSection("USAGE", []string{
		APPNAME + " [flags]          (no flags → interactive TUI)",
	})
	printHelpSection("INPUT", []string{
		"--input FILE       raw shellcode, or an ELF / PE / Mach-O executable",
		"--hex HEX          disassemble hex bytes (spaces, \\x and 0x allowed)",
		"--arch A           x86 | x64 | arm | arm64 (auto-detected for executables)",
		"--base ADDR        virtual base address for raw input (hex or decimal)",
		"--section NAME     executable section to decode (default .text / __text)",
		"--offset N         skip N bytes of raw input before decoding",
		"--length N         decode at most N bytes",
	})
	printHelpSection("ANALYSIS", []string{
		"--recursive        recursive descent from the entry (skips inline data)",
		"--entry ADDR       extra/override entry point for --recursive",
		"--limit N          disassembly lines kept in the report (default 400, 0 = all)",
		"--cfg              print control-flow edges after the listing",
		"--opcodes          print the x86 one-byte opcode map",
	})
	printHelpSection("REPORTING", []string{
		"--format FMT       txt | md | json | csv | sarif (default txt)",
		"--output FILE      write the report to FILE",
		"--no-color         disable ANSI colour",
	})
	printHelpSection("GENERAL", []string{
		"--demo             synthetic shellcode-style sample with triage",
		"--selftest         decoder correctness tests (exit 0/1)",
		"--version          print version",
	})
	printHelpSection("EXAMPLES", []string{
		APPNAME + " --input /bin/ls --recursive --limit 60",
		APPNAME + " --hex \"31c048bbd19d9691d08c97ff48f7db53545f995257545eb03b0f05\"",
		APPNAME + " --input fw.bin --arch arm --base 0x8000 --format json --output out.json",
	})
	line(66)
}

func printVersion() {
	fmt.Printf("%s v%s — %s\n", APPNAME, VERSION, SUITE)
	fmt.Printf("Author : %s\nWebsite: %s\n", AUTHOR, WEBSITE)
	fmt.Println("Build  : Go stdlib, static (CGO disabled)")
}

// parseAddr accepts 0x-prefixed hex, bare hex with a-f digits, or decimal.
func parseAddr(s string) (uint64, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return 0, nil
	}
	if strings.HasPrefix(s, "0x") {
		return strconv.ParseUint(s[2:], 16, 64)
	}
	if strings.ContainsAny(s, "abcdef") {
		return strconv.ParseUint(s, 16, 64)
	}
	return strconv.ParseUint(s, 10, 64)
}

// parseHexInput accepts "4889e5", "48 89 e5", "\x48\x89\xe5" and "0x48,0x89".
func parseHexInput(h string) ([]byte, error) {
	r := strings.NewReplacer("\\x", "", "0x", "", "0X", "", ",", "", " ", "", "\n", "", "\t", "", "\"", "")
	return hex.DecodeString(r.Replace(h))
}

// disasmJob is everything needed to decode one input.
type disasmJob struct {
	data      []byte
	target    string
	arch      Arch
	bits      int
	archSet   bool
	base      uint64
	section   string
	offset    int
	length    int
	recursive bool
	entry     uint64
	entrySet  bool
	limit     int
}

// runJob resolves containers, windows the bytes, decodes, and builds the report.
func runJob(j disasmJob) ([]Insn, Arch, *Report, error) {
	o := disasmOpts{target: j.target, recursive: j.recursive, limit: j.limit}
	code, base, arch, bits := j.data, j.base, j.arch, j.bits
	var entries []uint64
	img, err := loadImage(j.data, j.section)
	if err != nil {
		return nil, arch, nil, err
	}
	if img != nil {
		code, base = img.Code, img.Base
		o.format, o.section = img.Format, img.Section
		if !j.archSet {
			arch, bits = img.Arch, img.Bits
		}
		if img.HasEnt && img.Entry >= base && img.Entry < base+uint64(len(code)) {
			o.entry, o.hasEntry = img.Entry, true
			entries = append(entries, img.Entry)
		}
		entries = append(entries, img.Funcs...)
		o.symbols = len(img.Funcs)
	} else if j.section != "" {
		return nil, arch, nil, errors.New("--section needs an ELF / PE / Mach-O input")
	}
	if j.offset > 0 {
		if j.offset >= len(code) {
			return nil, arch, nil, fmt.Errorf("--offset %d is beyond the %d input bytes", j.offset, len(code))
		}
		code, base = code[j.offset:], base+uint64(j.offset)
	}
	if j.length > 0 && j.length < len(code) {
		code = code[:j.length]
	}
	if len(code) == 0 {
		return nil, arch, nil, errors.New("no bytes to disassemble")
	}
	if j.entrySet {
		o.entry, o.hasEntry = j.entry, true
		entries = []uint64{j.entry}
	}
	o.codeLen = len(code)
	var insns []Insn
	if j.recursive {
		if len(entries) == 0 {
			entries = []uint64{base}
		}
		insns = recursiveDisasm(code, base, arch, bits, entries...)
	} else {
		insns = linearDisasm(code, base, arch, bits)
		if o.hasEntry {
			markLeaders(insns, append(entries, base)...)
		}
	}
	return insns, arch, insnsToReport(o, arch, insns), nil
}

func main() {
	var format, output, input, hexIn, archStr, baseStr, section, entryStr string
	var nocolor, demo, selftest, showVer, recursive, showOps, cfg bool
	var offset, length, limit int
	fs := flag.NewFlagSet(APPNAME, flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = usage
	fs.StringVar(&format, "format", "txt", "")
	fs.StringVar(&output, "output", "", "")
	fs.BoolVar(&nocolor, "no-color", false, "")
	fs.BoolVar(&demo, "demo", false, "")
	fs.BoolVar(&selftest, "selftest", false, "")
	fs.BoolVar(&showVer, "version", false, "")
	fs.StringVar(&input, "input", "", "")
	fs.StringVar(&hexIn, "hex", "", "")
	fs.StringVar(&archStr, "arch", "x64", "")
	fs.StringVar(&baseStr, "base", "0", "")
	fs.StringVar(&section, "section", "", "")
	fs.StringVar(&entryStr, "entry", "", "")
	fs.IntVar(&offset, "offset", 0, "")
	fs.IntVar(&length, "length", 0, "")
	fs.IntVar(&limit, "limit", 400, "")
	fs.BoolVar(&recursive, "recursive", false, "")
	fs.BoolVar(&cfg, "cfg", false, "")
	fs.BoolVar(&showOps, "opcodes", false, "")
	if err := fs.Parse(os.Args[1:]); err != nil {
		if err == flag.ErrHelp {
			return
		}
		errMsg(err.Error())
		os.Exit(2)
	}
	if nocolor {
		noColor = true
	}
	if len(os.Args) == 1 {
		interactive()
		return
	}
	archSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "arch" {
			archSet = true
		}
	})
	switch {
	case showVer:
		printVersion()
		return
	case selftest:
		if !runSelfTest() {
			os.Exit(1)
		}
		return
	case demo:
		runDemo(format, output)
		return
	case showOps:
		banner()
		rows := [][]string{}
		for i := 0; i < 256; i++ {
			rows = append(rows, []string{fmt.Sprintf("0x%02x", i), x86OneByteOps[byte(i)]})
		}
		table([]string{"OP", "MNEMONIC"}, rows)
		return
	case input != "" || hexIn != "":
		arch, bits, ok := parseArch(archStr)
		if !ok {
			errMsg("unknown --arch " + archStr + " (x86|x64|arm|arm64)")
			os.Exit(2)
		}
		base, err := parseAddr(baseStr)
		if err != nil {
			errMsg("bad --base: " + err.Error())
			os.Exit(2)
		}
		j := disasmJob{arch: arch, bits: bits, archSet: archSet, base: base, section: section,
			offset: offset, length: length, recursive: recursive, limit: limit}
		if entryStr != "" {
			if j.entry, err = parseAddr(entryStr); err != nil {
				errMsg("bad --entry: " + err.Error())
				os.Exit(2)
			}
			j.entrySet = true
		}
		if hexIn != "" {
			j.data, err = parseHexInput(hexIn)
			j.target = "hex"
		} else {
			j.data, err = os.ReadFile(input)
			j.target = input
		}
		if err != nil {
			errMsg(err.Error())
			os.Exit(2)
		}
		insns, _, rep, err := runJob(j)
		if err != nil {
			errMsg(err.Error())
			os.Exit(1)
		}
		if err := emit(rep, format, output); err != nil {
			errMsg(err.Error())
			os.Exit(1)
		}
		if cfg {
			fmt.Println()
			printCFG(buildCFG(insns), 0)
		}
		return
	default:
		usage()
	}
}

// ---- interactive TUI ----

// tuiArch prompts for an architecture, defaulting to x64.
func tuiArch() (Arch, int, bool) {
	a, bits, ok := parseArch(prompt("arch x86 / x64 / arm / arm64 (blank = x64 or auto)"))
	if !ok {
		warnMsg("unknown architecture")
		pause()
	}
	return a, bits, ok
}

func tuiShow(insns []Insn, arch Arch, rep *Report) {
	lastInsns, lastArch, lastReport = insns, arch, rep
	sectionHeader("Disassembly")
	printListing(insns, 80)
	fmt.Println()
	sectionHeader("Triage")
	kvTable(rep.Stats)
	fmt.Println()
	showFindingsTUI(rep)
}

func tuiFile() {
	p := prompt("file (raw / ELF / PE / Mach-O)")
	if p == "" {
		return
	}
	data, err := os.ReadFile(p)
	if err != nil {
		errMsg(err.Error())
		pause()
		return
	}
	j := disasmJob{data: data, target: p, arch: ArchX64, bits: 64, limit: 400}
	if img, _ := loadImage(data, ""); img == nil {
		a, bits, ok := tuiArch()
		if !ok {
			return
		}
		j.arch, j.bits, j.archSet = a, bits, true
		if j.base, err = parseAddr(prompt("base address (blank = 0)")); err != nil {
			errMsg(err.Error())
			pause()
			return
		}
	} else {
		info(fmt.Sprintf("%s executable — %s, section %s auto-detected", img.Format, img.Arch, img.Section))
	}
	j.recursive = strings.HasPrefix(strings.ToLower(prompt("recursive descent? y/N")), "y")
	insns, arch, rep, err := runJob(j)
	if err != nil {
		errMsg(err.Error())
		pause()
		return
	}
	tuiShow(insns, arch, rep)
	pause()
}

func tuiHex() {
	code, err := parseHexInput(prompt("hex bytes"))
	if err != nil || len(code) == 0 {
		errMsg("could not parse hex input")
		pause()
		return
	}
	a, bits, ok := tuiArch()
	if !ok {
		return
	}
	insns, arch, rep, err := runJob(disasmJob{data: code, target: "hex", arch: a, bits: bits, archSet: true, limit: 400})
	if err != nil {
		errMsg(err.Error())
		pause()
		return
	}
	tuiShow(insns, arch, rep)
	pause()
}

func needLast() bool {
	if lastInsns == nil {
		warnMsg("disassemble something first (or run the demo)")
		pause()
		return false
	}
	return true
}

var tuiActions = []struct {
	name, desc string
	run        func()
}{
	{"Disassemble file", "Raw, or ELF/PE/Mach-O with auto arch", tuiFile},
	{"Disassemble hex bytes", "Paste shellcode as hex / \\x escapes", tuiHex},
	{"Basic blocks & CFG", "Blocks and control-flow edges of last run", func() {
		if !needLast() {
			return
		}
		bbs := basicBlocks(lastInsns)
		rows := [][]string{}
		for i, b := range bbs {
			if i >= 40 {
				break
			}
			last := b[len(b)-1]
			rows = append(rows, []string{fmt.Sprintf("0x%x", b[0].Offset), strconv.Itoa(len(b)), last.Mnemonic + " " + last.Operands, last.Flow})
		}
		sectionHeader(fmt.Sprintf("Basic blocks (%d)", len(bbs)))
		table([]string{"START", "INSNS", "LAST", "FLOW"}, rows)
		fmt.Println()
		sectionHeader("Control-flow edges")
		printCFG(buildCFG(lastInsns), 40)
		pause()
	}},
	{"Mnemonic statistics", "Most frequent instructions of last run", func() {
		if !needLast() {
			return
		}
		sectionHeader("Mnemonic frequency")
		kvTable(countMnemonics(lastInsns))
		q, sc := scoreCodeQuality(lastInsns)
		info(fmt.Sprintf("decode quality %s (%.1f/100), entropy %.2f bits/byte", q, sc, insnEntropy(lastInsns)))
		pause()
	}},
	{"Search mnemonic", "Find every occurrence in last run", func() {
		if !needLast() {
			return
		}
		m := prompt("mnemonic (e.g. syscall, call, xor)")
		hits := findPattern(lastInsns, m)
		sectionHeader(fmt.Sprintf("%d hit(s) for %q", len(hits), m))
		printListing(hits, 60)
		pause()
	}},
	{"Export last report", "txt / md / json / csv / sarif", func() {
		if lastReport == nil {
			warnMsg("no report yet")
			pause()
			return
		}
		f := prompt("format txt/md/json/csv/sarif")
		o := prompt("output file (blank = stdout)")
		if err := emit(lastReport, nonEmpty(f, "txt"), o); err != nil {
			errMsg(err.Error())
		}
		pause()
	}},
	{"x86 one-byte opcode map", "All 256 primary opcodes", func() {
		sectionHeader("x86 one-byte opcode map")
		rows := [][]string{}
		for i := 0; i < 256; i++ {
			rows = append(rows, []string{fmt.Sprintf("0x%02x", i), x86OneByteOps[byte(i)]})
		}
		table([]string{"OP", "MNEMONIC"}, rows)
		pause()
	}},
	{"Instruction semantics", "What common instructions do", func() { sectionHeader("Instruction semantics"); printInsnSemantics(0); pause() }},
	{"SSE / AVX mnemonics", "Vector instruction reference", func() { sectionHeader("SSE / AVX mnemonics"); printSSEAVX(0); pause() }},
	{"ARM examples", "Common A32 instruction forms", func() { sectionHeader("ARM examples"); printARMExamples(); pause() }},
	{"ATT&CK technique catalog", "Techniques referenced by findings", func() { sectionHeader("ATT&CK techniques"); printTechniqueCatalog(); pause() }},
	{"Run demo", "Synthetic shellcode-style sample", func() { runDemo("txt", ""); pause() }},
	{"Self-test", "Decoder correctness checks", func() { runSelfTest(); pause() }},
}

func interactive() {
	for {
		items := make([]menuItem, len(tuiActions))
		for i, a := range tuiActions {
			items[i] = menuItem{key: fmt.Sprintf("%02d", i+1), name: a.name, desc: a.desc, clr: CY + B}
		}
		choice := strings.TrimSpace(menu(TAGLINE, items))
		if choice == "0" || choice == "00" || strings.EqualFold(choice, "q") || strings.EqualFold(choice, "exit") {
			clear()
			banner()
			okMsg("Session closed. Authorised reverse engineering only.")
			return
		}
		if strings.EqualFold(choice, "h") || strings.EqualFold(choice, "help") || choice == "?" {
			tuiHelp()
			continue
		}
		n, err := strconv.Atoi(choice)
		if err != nil || n < 1 || n > len(tuiActions) {
			if choice != "" {
				warnMsg("unknown selection")
				pause()
			}
			continue
		}
		clear()
		banner()
		tuiActions[n-1].run()
	}
}

// extra ARM shifter / register names for depth
var armRegs = []string{"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "sp", "lr", "pc"}
var armShifts = []string{"LSL", "LSR", "ASR", "ROR"}
var x86Reg8 = []string{"al", "cl", "dl", "bl", "ah", "ch", "dh", "bh"}
var x86Reg16 = []string{"ax", "cx", "dx", "bx", "sp", "bp", "si", "di"}
var x86Reg32 = []string{"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"}
var x86Reg64 = []string{"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"}

func regName(bits, idx int) string {
	switch bits {
	case 8:
		if idx < len(x86Reg8) {
			return x86Reg8[idx]
		}
	case 16:
		if idx < len(x86Reg16) {
			return x86Reg16[idx]
		}
	case 32:
		if idx < len(x86Reg32) {
			return x86Reg32[idx]
		}
	default:
		if idx < len(x86Reg64) {
			return x86Reg64[idx]
		}
	}
	return fmt.Sprintf("r%d", idx)
}

func formatInsn(in Insn) string {
	mark := " "
	if in.Leader {
		mark = ">"
	}
	hb := hex.EncodeToString(in.Bytes)
	if len(hb) > 20 {
		hb = hb[:18] + ".."
	}
	line := fmt.Sprintf("%s%08x: %-20s %-8s %s", mark, in.Offset, hb, in.Mnemonic, in.Operands)
	if in.Comment != "" {
		line = fmt.Sprintf("%-60s ; %s", line, in.Comment)
	}
	return line
}

func printListing(insns []Insn, limit int) {
	if limit <= 0 || limit > len(insns) {
		limit = len(insns)
	}
	for i := 0; i < limit; i++ {
		in := insns[i]
		c := W
		switch in.Flow {
		case "call":
			c = CY
		case "branch", "cbranch":
			c = YLW
		case "ret", "stop":
			c = MG
		case "syscall":
			c = OR + B
		case "invalid":
			c = R
		}
		fmt.Println("  " + col(formatInsn(in), c))
	}
	if limit < len(insns) {
		info(fmt.Sprintf("… %d more instructions", len(insns)-limit))
	}
}

func countMnemonics(insns []Insn) []KV {
	m := map[string]int{}
	for _, in := range insns {
		m[in.Mnemonic]++
	}
	type pr struct {
		k string
		v int
	}
	var ps []pr
	for k, v := range m {
		ps = append(ps, pr{k, v})
	}
	sort.Slice(ps, func(i, j int) bool { return ps[i].v > ps[j].v })
	var out []KV
	for i, p := range ps {
		if i >= 20 {
			break
		}
		out = append(out, KV{p.k, strconv.Itoa(p.v)})
	}
	return out
}

func findPattern(insns []Insn, mnem string) []Insn {
	var out []Insn
	for _, in := range insns {
		if strings.EqualFold(in.Mnemonic, mnem) {
			out = append(out, in)
		}
	}
	return out
}

// control-flow graph edges (lightweight)
type CFGEdge struct {
	From, To uint64
	Kind     string
}

func buildCFG(insns []Insn) []CFGEdge {
	var edges []CFGEdge
	for _, in := range insns {
		next := in.Offset + uint64(in.Size)
		switch in.Flow {
		case "next", "syscall":
			edges = append(edges, CFGEdge{in.Offset, next, "fall"})
		case "call":
			edges = append(edges, CFGEdge{in.Offset, next, "call-ret"})
			if in.HasTarget {
				edges = append(edges, CFGEdge{in.Offset, in.Target, "call"})
			}
		case "cbranch":
			edges = append(edges, CFGEdge{in.Offset, next, "fall"})
			if in.HasTarget {
				edges = append(edges, CFGEdge{in.Offset, in.Target, "cond"})
			}
		case "branch":
			if in.HasTarget {
				edges = append(edges, CFGEdge{in.Offset, in.Target, "jmp"})
			}
		}
	}
	return edges
}

// ---------------------------------------------------------------------------
// Help & Usage  (interactive menu [H])
// Page 1: in-app guide (what the tool does, every menu option, tips).
// Page 2: the full command-line reference (same text as --help).
// ---------------------------------------------------------------------------

type owlHelpItem struct{ key, text string }

func owlHelpWrap(s string, width int) []string {
	var out []string
	for _, para := range strings.Split(s, "\n") {
		words := strings.Fields(para)
		if len(words) == 0 {
			out = append(out, "")
			continue
		}
		cur := ""
		for _, w := range words {
			if cur != "" && len([]rune(cur))+1+len([]rune(w)) > width {
				out = append(out, cur)
				cur = w
			} else if cur == "" {
				cur = w
			} else {
				cur += " " + w
			}
		}
		out = append(out, cur)
	}
	return out
}

func owlHelpTitle(t string) {
	fmt.Println()
	fmt.Println("  " + col("▸ "+t, B+CY))
}

func owlHelpPara(lines []string) {
	for _, l := range lines {
		for _, w := range owlHelpWrap(l, 60) {
			fmt.Println("    " + col(w, W))
		}
	}
}

func owlHelpRows(items []owlHelpItem) {
	kw := 0
	for _, it := range items {
		if n := len([]rune(it.key)); n > kw {
			kw = n
		}
	}
	for _, it := range items {
		k := "[" + it.key + "]" + strings.Repeat(" ", kw-len([]rune(it.key)))
		for i, w := range owlHelpWrap(it.text, 56-kw) {
			if i == 0 {
				fmt.Println("    " + col(k, YLW+B) + "  " + col(w, W))
			} else {
				fmt.Println("    " + strings.Repeat(" ", kw+2) + "  " + col(w, W))
			}
		}
	}
}

func owlHelpRule() { fmt.Println(col(strings.Repeat("─", 66), CY)) }

func tuiHelp() {
	clear()
	banner()
	owlHelpRule()
	fmt.Println("  " + col("⬡  Help & Usage — "+APPNAME, B+CY))
	owlHelpRule()
	owlHelpTitle("WHAT IT DOES")
	owlHelpPara(owlHelpAbout)
	owlHelpTitle("HOW TO USE THE MENU")
	owlHelpPara(owlHelpFlow)
	owlHelpTitle("MENU OPTIONS")
	owlHelpRows(owlHelpMenu)
	owlHelpTitle("TIPS")
	owlHelpRows(owlHelpTips)
	fmt.Println()
	owlHelpRule()
	fmt.Println("  " + col("Next page: command-line flags & copy-paste examples", DIM))
	pause()
	clear()
	owlHelpCLI()
	fmt.Println()
	fmt.Println("  " + col("Tip: the same reference is printed by  "+APPNAME+" --help", DIM))
	pause()
}

var owlHelpAbout = []string{
	"ODisasm is a disassembler for x86 (32-bit), x64, ARM (A32) and ARM64. It turns machine code back into readable assembly. It opens ELF (Linux), PE (Windows) and Mach-O (macOS) executables and detects their architecture and code section automatically, or decodes raw shellcode and firmware dumps.",
	"After decoding it triages the code. It flags raw syscalls, PEB access, NOP sleds, self-decoding loops, self-locating (GetPC) tricks and anti-analysis instructions, maps them to MITRE ATT&CK, builds basic blocks and a control-flow graph, and grades how clean the decoding is.",
}

var owlHelpFlow = []string{
	"Type the number of an option (1 or 01) and press Enter. First disassemble something with [01] (a file) or [02] (hex bytes). Options [03] to [06] then work on that last result. [H] opens this help, [0] or q quits.",
}

var owlHelpMenu = []owlHelpItem{
	{"01", "Disassemble file: enter a path. For ELF / PE / Mach-O the format, architecture and section are detected. For a raw .bin you are asked for the architecture (x86 / x64 / arm / arm64) and base address (e.g. 0x8000, blank = 0). Answer y to recursive descent to follow jumps from the entry point and skip data mixed into code."},
	{"02", "Disassemble hex bytes: paste the bytes in any form (31c0 50 68, \\x31\\xc0 or 0x31,0xc0), then choose the architecture."},
	{"03", "Basic blocks & CFG: splits the last listing into basic blocks and shows the jump/call edges between them."},
	{"04", "Mnemonic statistics: the most frequent instructions, plus a decode-quality score and entropy (very high entropy usually means packed or encrypted data, not code)."},
	{"05", "Search mnemonic: enter a mnemonic such as syscall, call or xor to list every place it appears."},
	{"06", "Export last report: choose txt, md, json, csv or sarif and an output file (blank = print to screen)."},
	{"07", "x86 one-byte opcode map: all 256 primary opcodes in a table."},
	{"08", "Instruction semantics: what common instructions do, in plain words."},
	{"09", "SSE / AVX mnemonics: reference of vector instructions."},
	{"10", "ARM examples: common A32 instruction forms with their encodings."},
	{"11", "ATT&CK technique catalog: the MITRE techniques that findings can refer to."},
	{"12", "Run demo: disassembles a built-in shellcode-style sample and shows the triage."},
	{"13", "Self-test: decoder correctness checks."},
}

var owlHelpTips = []owlHelpItem{
	{"*", "Use the right architecture for raw input. Decoding ARM bytes as x64 gives nonsense, and a low decode-quality score is the warning sign."},
	{"*", "Use --section, --offset and --length on the command line to decode only part of a file."},
	{"*", "Use --limit 0 to keep the full listing in the report (default 400 lines)."},
}

func owlHelpCLI() { usage() }
