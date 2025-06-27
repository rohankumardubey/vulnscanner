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

    "github.com/beevik/etree"
)

const ossIndexURL = "https://ossindex.sonatype.org/api/v3/component-report"

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
    Coordinates     string           `json:"coordinates"`
    Vulnerabilities []Vulnerability  `json:"vulnerabilities"`
}

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

func printReport(results []OSSIndexResponse) {
    vulnFound := false
    for _, r := range results {
        if len(r.Vulnerabilities) > 0 {
            vulnFound = true
            fmt.Printf("\n[!] Vulnerabilities found for %s:\n", r.Coordinates)
            for _, v := range r.Vulnerabilities {
                fmt.Printf("  - %s\n", v.Title)
                fmt.Printf("    CVE: %s\n", v.CVE)
                fmt.Printf("    Severity: %.1f\n", v.CVSSScore)
                fmt.Printf("    Description: %.120s...\n", v.Description)
                fmt.Printf("    More info: %s\n\n", v.Reference)
            }
        }
    }
    if !vulnFound {
        fmt.Println("No known vulnerabilities found!")
    }
}

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
