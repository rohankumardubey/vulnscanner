package main

import (
    "bufio"
    "bytes"
    "encoding/json"
    "fmt"
    "io/ioutil"
    "net/http"
    "os"
    "path/filepath"
    "regexp"
    "strings"
    "unicode/utf8"

    "github.com/beevik/etree"
)

const ossIndexURL = "https://ossindex.sonatype.org/api/v3/component-report"

// ── ANSI Colors ────────────────────────────────────────────────
var (
    ColorReset = "\033[0m"
    ColorBold  = "\033[1m"
    ColorRed   = "\033[31m"
    ColorYel   = "\033[33m"
    ColorBlu   = "\033[34m"
)

// ── Types ──────────────────────────────────────────────────────

type OSSIndexRequest struct {
    Coordinates []string `json:"coordinates"`
}

type Vulnerability struct {
    ID          string  `json:"id"`
    Title       string  `json:"title"`
    Description string  `json:"description"`
    CVSSScore   float64 `json:"cvssScore"`
    CVE         string  `json:"cve"`
    Reference   string  `json:"reference"`
}

type OSSIndexResponse struct {
    Coordinates     string          `json:"coordinates"`
    Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

// ── Table‐Drawing Helpers ─────────────────────────────────────

func printTableLine(kind string, widths []int) {
    var left, sep, mid, right string
    switch kind {
    case "top":
        left, sep, mid, right = "┌", "┬", "─", "┐"
    case "mid":
        left, sep, mid, right = "├", "┼", "─", "┤"
    case "bot":
        left, sep, mid, right = "└", "┴", "─", "┘"
    }
    fmt.Print(left)
    for i, w := range widths {
        for j := 0; j < w+2; j++ {
            fmt.Print(mid)
        }
        if i < len(widths)-1 {
            fmt.Print(sep)
        }
    }
    fmt.Println(right)
}

func wrapText(s string, width int) []string {
    var lines []string
    words := strings.Fields(s)
    if len(words) == 0 {
        return []string{""}
    }
    line := words[0]
    for _, w := range words[1:] {
        if utf8.RuneCountInString(line)+1+utf8.RuneCountInString(w) > width {
            lines = append(lines, line)
            line = w
        } else {
            line += " " + w
        }
    }
    lines = append(lines, line)
    return lines
}

func truncate(s string, max int) string {
    if len(s) > max {
        return s[:max-3] + "..."
    }
    return s
}

func extractCWE(title string) string {
    re := regexp.MustCompile(`CWE-\d+`)
    return re.FindString(title)
}

// hyperlink makes text clickable in supporting terminals via OSC 8
func hyperlink(text, url string) string {
    return "\x1b]8;;" + url + "\x1b\\" + text + "\x1b]8;;\x1b\\"
}

// extractUpgradeSuggestion tries to pull a "fix" hint from the description
func extractUpgradeSuggestion(desc string) string {
    lower := strings.ToLower(desc)
    for _, p := range []string{
        "upgrade to version ", "fixed in ", "update to version ", "use version ",
    } {
        if idx := strings.Index(lower, p); idx != -1 {
            after := lower[idx+len(p):]
            parts := strings.Fields(after)
            if len(parts) > 0 {
                return "Upgrade to " + parts[0]
            }
        }
    }
    return ""
}

// Severity coloring based on CVSS
func severityColor(score float64) string {
    switch {
    case score >= 9.0:
        return ColorRed + ColorBold
    case score >= 7.0:
        return ColorRed
    case score >= 4.0:
        return ColorYel
    default:
        return ColorReset
    }
}

// ── Print One Dependency’s Vulnerabilities as Table ───────────

func printVulnTable(dep string, vulns []Vulnerability) {
    // Column widths: CVE, Severity, CWE, Description, Suggested Fix
    widths := []int{18, 9, 10, 40, 20}

    // Header
    fmt.Printf("\n%sDependency:%s %s\n\n", ColorBold, ColorReset, dep)
    printTableLine("top", widths)
    fmt.Printf(
        "%s│ %-*s │ %-*s │ %-*s │ %-*s │ %-*s │%s\n",
        ColorBold,
        widths[0], "CVE",
        widths[1], "Severity",
        widths[2], "CWE",
        widths[3], "Description",
        widths[4], "Suggested Fix",
        ColorReset,
    )
    printTableLine("mid", widths)

    // Rows
    for i, v := range vulns {
        cwe := extractCWE(v.Title)
        fix := extractUpgradeSuggestion(v.Description)
        if fix == "" {
            // clickable "Check reference URL"
            fix = hyperlink("Check reference URL", v.Reference)
        }
        desc := truncate(v.Description, widths[3])

        // Wrap description into lines
        descLines := wrapText(desc, widths[3])
        for j, dl := range descLines {
            if j == 0 {
                fmt.Printf(
                    "│ %s%-*s%s │ %s%-*.1f%s │ %-*s │ %-*s │ %s%-*s%s │\n",
                    ColorBlu+ColorBold, widths[0], v.CVE, ColorReset,
                    severityColor(v.CVSSScore), widths[1], v.CVSSScore, ColorReset,
                    widths[2], cwe,
                    widths[3], dl,
                    ColorYel, widths[4], fix, ColorReset,
                )
            } else {
                // subsequent lines continue only in Description column
                fmt.Printf(
                    "│ %-*s │ %-*s │ %-*s │ %-*s │ %-*s │\n",
                    widths[0], "",
                    widths[1], "",
                    widths[2], "",
                    widths[3], dl,
                    widths[4], "",
                )
            }
        }

        if i < len(vulns)-1 {
            printTableLine("mid", widths)
        }
    }
    printTableLine("bot", widths)
}

// ── Parsers ───────────────────────────────────────────────────

func parseGoMod(path string) ([]string, error) {
    f, err := os.Open(path)
    if err != nil {
        return nil, err
    }
    defer f.Close()

    var coords []string
    scanner := bufio.NewScanner(f)
    re := regexp.MustCompile(`^\s*([^\s]+)\s+v([0-9A-Za-z\.\-\+]+)`)
    inBlock := false

    for scanner.Scan() {
        line := scanner.Text()
        if strings.HasPrefix(line, "require (") {
            inBlock = true
            continue
        }
        if inBlock && strings.HasPrefix(line, ")") {
            inBlock = false
            continue
        }
        if inBlock || strings.HasPrefix(line, "require") {
            if m := re.FindStringSubmatch(line); len(m) == 3 {
                coords = append(coords,
                    fmt.Sprintf("pkg:golang/%s@v%s", m[1], m[2]),
                )
            }
        }
    }
    return coords, nil
}

func parsePomXML(path string) ([]string, error) {
    doc := etree.NewDocument()
    if err := doc.ReadFromFile(path); err != nil {
        return nil, err
    }
    var coords []string
    for _, dep := range doc.FindElements("//project/dependencies/dependency") {
        g := dep.SelectElement("groupId")
        a := dep.SelectElement("artifactId")
        v := dep.SelectElement("version")
        if g != nil && a != nil && v != nil {
            coords = append(coords,
                fmt.Sprintf("pkg:maven/%s/%s@%s", g.Text(), a.Text(), v.Text()),
            )
        }
    }
    return coords, nil
}

// ── OSS Index Call ────────────────────────────────────────────

func checkVulnerabilities(coords []string) ([]OSSIndexResponse, error) {
    body, _ := json.Marshal(OSSIndexRequest{Coordinates: coords})
    resp, err := http.Post(ossIndexURL, "application/json", bytes.NewBuffer(body))
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    data, _ := ioutil.ReadAll(resp.Body)

    var out []OSSIndexResponse
    if err := json.Unmarshal(data, &out); err != nil {
        return nil, err
    }
    return out, nil
}

// ── Main ─────────────────────────────────────────────────────

func main() {
    if len(os.Args) != 3 {
        fmt.Println("Usage: vulnscanner [go|java] /path/to/project")
        os.Exit(1)
    }
    lang, path := os.Args[1], os.Args[2]

    var coords []string
    var err error
    switch lang {
    case "go":
        coords, err = parseGoMod(filepath.Join(path, "go.mod"))
    case "java":
        coords, err = parsePomXML(filepath.Join(path, "pom.xml"))
    default:
        fmt.Println("Supported languages: go, java")
        os.Exit(1)
    }
    if err != nil {
        fmt.Fprintln(os.Stderr, "Error parsing:", err)
        os.Exit(1)
    }
    if len(coords) == 0 {
        fmt.Println("No dependencies found.")
        os.Exit(0)
    }

    fmt.Printf("%sParsing %s → found %d dependencies. Querying vulnerabilities…%s\n\n", ColorBold, lang, len(coords), ColorReset)
    results, err := checkVulnerabilities(coords)
    if err != nil {
        fmt.Fprintln(os.Stderr, "Error fetching vulnerabilities:", err)
        os.Exit(1)
    }

    totalDeps, totalVulns := 0, 0
    for _, r := range results {
        if len(r.Vulnerabilities) > 0 {
            totalDeps++
            printVulnTable(r.Coordinates, r.Vulnerabilities)
            totalVulns += len(r.Vulnerabilities)
        }
    }
    if totalVulns == 0 {
        fmt.Println("✅ No known vulnerabilities found!")
    } else {
        fmt.Printf("\nSummary: %d dependencies affected, %d vulnerabilities found.\n",
            totalDeps, totalVulns)
    }
}
