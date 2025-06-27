# vulnscanner

A lightweight CLI tool written in Go for scanning Java (Maven) and Go (modules) project dependencies against the OSS Index vulnerability database. Outputs a clean, colorized ASCII box report with clickable links, severity-based coloring, and upgrade suggestions.

---

## Features

* **Multi-language support**: Scans Maven (`pom.xml`) and Go modules (`go.mod`).
* **Batch querying**: Bundles all dependencies in a single API call to the OSS Index.
* **ASCII box layout**: Each dependency and its vulnerabilities are displayed in a neat box with borders and separators.
* **Color-coded output**:

  * **CVE identifiers** in blue and bold.
  * **High-severity** (CVSS ≥ 9.0) in red bold.
  * **Medium-severity** (7.0 ≤ CVSS < 9.0) in red.
  * **Low-severity** (CVSS ≥ 4.0) in yellow.
  * **Suggested fixes** in yellow.
* **Clickable links**: Reference hyperlinks use OSC 8 escape sequences ("View Details").
* **Upgrade hints**: Parses vulnerability descriptions for "fixed in" or "upgrade to" suggestions.
* **Customizable width**: Adjust the box width constant to match your terminal.

---

## Installation

1. **Clone the repository**

   ```bash
   git clone https://github.com/your-username/vulnscanner.git
   cd vulnscanner
   ```
2. **Install dependencies**

   ```bash
   go get github.com/beevik/etree
   ```
3. **Build**

   ```bash
   go build -o vulnscanner main.go
   ```

---

## Usage

```bash
# Scan a Go project
./vulnscanner go /path/to/your/go/project

# Scan a Java Maven project
./vulnscanner java /path/to/your/java/project
```

### Sample Output

```bash
Parsing java → found 5 dependencies. Checking vulnerabilities...

┌──────────────────────────────────────────────────────────────────────────────────────────────┐
│ pkg:maven/org.apache.kafka/kafka-clients@3.8.0                                             │
├──────────────────────────────────────────────────────────────────────────────────────────────┤
│ [CVE-2024-56128] Incorrect Implementation of Authentication Algorithm                       │
│ Severity: 6.3                                                                              │
│ Description: Incorrect Implementation of Authentication Algorithm in Apache Kafka's SCRAM... │
│ Reference: View Details                                                                    │
│ Suggested Fix: Upgrade to 3.7.2                                                            │
└──────────────────────────────────────────────────────────────────────────────────────────────┘

Summary: 1 dependencies affected, 1 vulnerability found.
```

---

## Configuration

* **Box width**: Modify the `width` constant in `printVulnBox` to fit your terminal width.
* **API URL**: Change `ossIndexURL` to point to a different feed or local mirror if needed.

---

## Contributing

1. Fork the repo
2. Create your feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -m "Add feature"`)
4. Push to your branch (`git push origin feature/my-feature`)
5. Open a Pull Request

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

*This tool is provided as-is without warranty. Use responsibly and ensure compliance with your organizational security policies.*
