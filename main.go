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

// Box drawing characters
const (
    hLine  = "─"
    vLine  = "│"
    tl     = "┌"
    tr     = "┐"
    bl     = "└"
    br     = "┘"
    lJoint = "├"
    rJoint = "┤"
)

// ANSI colors
var (
    Red    = "\033[31m"
    Yellow = "\033[33m"
    Cyan   = "\033[36m"
    Reset  = "\033[0m"
    Bold   = "\033[1m"
)

// Types
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

// Color helpers
func severityColor(score float64) string {
    switch {
    case score >= 9:
        return Red + Bold
    case score >= 7:
        return Red
    case score >= 4:
        return Yellow
    default:
        return Reset
    }
}

// Wrap a string into lines of max width (word boundaries)
func wrapText(s string, width int) []string {
    var lines []string
    words := strings.Fields(s)
    if len(words) == 0 {
        return []string{""}
    }
    line := words[0]
    for _, word := range words[1:] {
        if utf8.RuneCountInString(line)+1+utf8.RuneCountInString(word) > width {
            lines = append(lines, line)
            line = word
        } else {
            line += " " + word
        }
    }
    lines = append(lines, line)
    return lines
}

// Print horizontal line for box
func printHLine(width int) {
    fmt.Print(tl)
    for i := 0; i < width; i++ {
        fmt.Print(hLine)
    }
    fmt.Println(tr)
}

// Print bottom line for box
func printBLine(width int) {
    fmt.Print(bl)
    for i := 0; i < width; i++ {
        fmt.Print(hLine)
    }
    fmt.Println(br)
}

// Print horizontal separator between vulnerabilities
func printInnerHLine(width int) {
    fmt.Printf("%s%s%s\n", lJoint, strings.Repeat(hLine, width), rJoint)
}

// Print a label/value row, with wrapping
func printRowContent(width int, label, value, color string) {
    wrapWidth := width - len(label) - 7 // 7: box, label padding, separator, space
    wrapped := wrapText(value, wrapWidth)
    for i, line := range wrapped {
        if i == 0 {
            fmt.Printf("%s   %s%s%-14s%s %s%s %s\n", vLine, Bold, color, label, Reset, line, Reset, vLine)
        } else {
            fmt.Printf("%s   %-16s %s%s %s\n", vLine, "", line, Reset, vLine)
        }
    }
}

// Try to extract upgrade suggestion from description text
func extractUpgradeSuggestion(desc string) string {
    lower := strings.ToLower(desc)
    patterns := []string{"upgrade to version ", "upgrade to ", "fixed in ", "update to version ", "use version "}
    for _, p := range patterns {
        idx := strings.Index(lower, p)
        if idx != -1 {
            after := lower[idx+len(p):]
            words := strings.Fields(after)
            if len(words) > 0 {
                return "Upgrade to version " + words[0]
            }
        }
    }
    return ""
}

// Truncate long description for consistent appearance
func truncate(s string, l int) string {
    if len(s) > l {
        return s[:l] + "..."
    }
    return s
}

// Print a vulnerability box for one dependency
func printVulnBox(dep string, vulns []Vulnerability) {
    width := 100 // You can adjust this to your terminal width
    printHLine(width)
    depLines := wrapText(dep, width-2)
    for _, l := range depLines {
        fmt.Printf("%s %-*s %s\n", vLine, width-2, Cyan+l+Reset, vLine)
    }
    printInnerHLine(width)
    for idx, v := range vulns {
        sevCol := severityColor(v.CVSSScore)
        // Remove duplicate CVE in the title if present
        cve := v.CVE
        title := v.Title
        if cve != "" && strings.Contains(title, cve) {
            title = strings.Replace(title, cve, "", 1)
            title = strings.TrimSpace(title)
            title = strings.TrimLeft(title, "[] ")
        }
        // Compose vulnerability heading
        var vulnHeader string
        if cve != "" {
            vulnHeader = fmt.Sprintf("[%s] %s", cve, title)
        } else {
            vulnHeader = title
        }
        // Vulnerability header row (wraps if too long)
        headerLines := wrapText(vulnHeader, width-8)
        for i, hl := range headerLines {
            if i == 0 {
                fmt.Printf("%s • %s%s%s%s %s\n", vLine, Bold, hl, Reset, Reset, vLine)
            } else {
                fmt.Printf("%s   %s%s%s %s\n", vLine, Bold, hl, Reset, vLine)
            }
        }
        // Severity
        printRowContent(width, "Severity:", fmt.Sprintf("%.1f", v.CVSSScore), sevCol)
        // Description
        printRowContent(width, "Description:", truncate(v.Description, 200), "")
        // Reference
        printRowContent(width, "Reference:", v.Reference, "")
        // Suggested Fix
        suggestion := extractUpgradeSuggestion(v.Description)
        if suggestion != "" {
            printRowContent(width, "Suggested Fix:", suggestion, "")
        } else {
            printRowContent(width, "Suggested Fix:", "Check latest version at reference URL.", "")
        }
        if idx != len(vulns)-1 {
            printInnerHLine(width)
        }
    }
    printBLine(width)
}

// Parse go.mod for dependencies
func parseGoMod(goModPath string) ([]string, error) {
    f, err := os.Open(goModPath)
    if err != nil {
        return nil, err
    }
    defer f.Close()

    var pkgs []string
    scanner := bufio.NewScanner(f)
    depPattern := regexp.MustCompile(`^\s*([^\s]+)\s+v([0-9A-Za-z\.\-\+]+)`)
    inRequireBlock := false

    for scanner.Scan() {
        line := scanner.Text()
        if strings.HasPrefix(line, "require (") {
            inRequireBlock = true
            continue
        }
        if inRequireBlock && strings.HasPrefix(line, ")") {
            inRequireBlock = false
            continue
        }

        if inRequireBlock || strings.HasPrefix(line, "require") {
            matches := depPattern.FindStringSubmatch(line)
            if len(matches) == 3 {
                mod := matches[1]
                version := matches[2]
                pkgs = append(pkgs, fmt.Sprintf("pkg:golang/%s@v%s", mod, version))
            }
        }
    }
    return pkgs, nil
}

// Parse pom.xml for Maven dependencies
func parsePomXML(pomPath string) ([]string, error) {
    doc := etree.NewDocument()
    if err := doc.ReadFromFile(pomPath); err != nil {
        return nil, err
    }

    var pkgs []string
    dependencies := doc.FindElements("//project/dependencies/dependency")
    for _, dep := range dependencies {
        group := dep.SelectElement("groupId")
        artifact := dep.SelectElement("artifactId")
        version := dep.SelectElement("version")
        if group != nil && artifact != nil && version != nil {
            pkgs = append(pkgs, fmt.Sprintf("pkg:maven/%s/%s@%s", group.Text(), artifact.Text(), version.Text()))
        }
    }
    return pkgs, nil
}

// Query OSS Index for vulnerabilities
func checkVulnerabilities(coords []string) ([]OSSIndexResponse, error) {
    reqBody, err := json.Marshal(OSSIndexRequest{Coordinates: coords})
    if err != nil {
        return nil, err
    }
    resp, err := http.Post(ossIndexURL, "application/json", bytes.NewBuffer(reqBody))
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        return nil, err
    }
    var result []OSSIndexResponse
    err = json.Unmarshal(body, &result)
    if err != nil {
        return nil, err
    }
    return result, nil
}

// Print overall report
func printReport(results []OSSIndexResponse) {
    vulnCount := 0
    depCount := 0

    for _, r := range results {
        if len(r.Vulnerabilities) > 0 {
            depCount++
            printVulnBox(r.Coordinates, r.Vulnerabilities)
            vulnCount += len(r.Vulnerabilities)
        }
    }
    if vulnCount == 0 {
        fmt.Println(Cyan + "No known vulnerabilities found!" + Reset)
    } else {
        fmt.Printf("%sSummary:%s %d dependencies affected, %d vulnerabilities found.\n\n",
            Bold, Reset, depCount, vulnCount)
    }
}

// Entry point
func main() {
    if len(os.Args) < 3 {
        fmt.Println("Usage: vulnscanner <language> <path_to_project>")
        fmt.Println("Example for Go: vulnscanner go /path/to/project")
        fmt.Println("Example for Java: vulnscanner java /path/to/project")
        os.Exit(1)
    }

    lang := strings.ToLower(os.Args[1])
    path := os.Args[2]
    var pkgs []string
    var err error

    switch lang {
    case "go":
        goModPath := filepath.Join(path, "go.mod")
        if _, err = os.Stat(goModPath); os.IsNotExist(err) {
            fmt.Println("go.mod not found in the specified path.")
            os.Exit(1)
        }
        fmt.Println("Parsing go.mod...")
        pkgs, err = parseGoMod(goModPath)
    case "java":
        pomPath := filepath.Join(path, "pom.xml")
        if _, err = os.Stat(pomPath); os.IsNotExist(err) {
            fmt.Println("pom.xml not found in the specified path.")
            os.Exit(1)
        }
        fmt.Println("Parsing pom.xml...")
        pkgs, err = parsePomXML(pomPath)
    default:
        fmt.Println("Supported languages: go, java")
        os.Exit(1)
    }

    if err != nil {
        fmt.Printf("Error parsing dependencies: %v\n", err)
        os.Exit(1)
    }
    if len(pkgs) == 0 {
        fmt.Println("No dependencies found.")
        os.Exit(0)
    }

    fmt.Printf("Found %d dependencies. Checking vulnerabilities...\n", len(pkgs))
    results, err := checkVulnerabilities(pkgs)
    if err != nil {
        fmt.Printf("Error querying vulnerabilities: %v\n", err)
        os.Exit(1)
    }
    printReport(results)
}
