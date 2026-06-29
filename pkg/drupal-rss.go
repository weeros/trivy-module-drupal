package pkg

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/aquasecurity/trivy/pkg/module/wasm"

	stdhtml "html"

	xhtml "golang.org/x/net/html"
)

// ---------------- RSS ----------------

type RSS struct {
    Channel Channel `xml:"channel"`
}

type Channel struct {
    Items []Item `xml:"item"`
}

type Item struct {
    Title       string `xml:"title"`
    Link        string `xml:"link"`
    Description string `xml:"description"`
}

// ---------------- Output ----------------

type AdvisoryItem struct {
    CVE           string `json:"cve"`
    Versions      string `json:"versions"`
    Criticality   string `json:"criticality"`
    Vulnerability string `json:"vulnerability"`
    IssueURL      string `json:"issue_url"`
}

type Output struct {
    Slug        string         `json:"slug"`
    ProjectName string         `json:"project_name"`
    ProjectURL  string         `json:"project_url"`
    Advisories  []AdvisoryItem `json:"advisories"`
}

// ---------------- Internal ----------------

type Advisory struct {
    ProjectName      string
    ProjectURL       string
    ProjectSlug      string
    Criticality      string
    Vulnerability    string
    AffectedVersions string
    CVE              string
    IssueURL         string
}

// ---------------- Main ----------------

func LoadJSON(file string) ([]Output, error) {
    data, err := os.ReadFile(file)
    if err != nil {
        return nil, err
    }

    wasm.Info(fmt.Sprintf("WordPress Version: %s", "lkmlllllllllllllllll.Slug"))
    var outputs []Output

    err = json.Unmarshal(data, &outputs)
    if err != nil {
        return nil, err
    }

				wasm.Info(fmt.Sprintf("WordPress Version: %s", "lkmlllllllllllllllll.Slug"))
    return outputs, nil
}

func IndexBySlug(outputs []Output) map[string]Output {
    index := make(map[string]Output)

    for _, o := range outputs {
        index[o.Slug] = o
    }

    return index
}

func GenerateNameFile() string {
    return "./drupal_advisories.json";
}

func GenereatIndex() map[string]Output {
    
    filepath := GenerateNameFile()
    outputs, err := LoadJSON(filepath)
    if err != nil {
        wasm.Error(fmt.Sprintf("Open Drupal Json CVE: %s", err))
        return nil
    }
    return IndexBySlug(outputs)
}

func FindBySlug(index map[string]Output, slug string) (Output, bool) {
    res, ok := index[slug]
    return res, ok
}

func GenerateJson(filepath string) {
    rssURL := "https://www.drupal.org/security/all/rss.xml"
       
    resolver := &net.Resolver{
        PreferGo: true,
        Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
            d := net.Dialer{}
            return d.DialContext(ctx, "udp", "1.1.1.1:53")
        },
    }

    dialer := &net.Dialer{
        Timeout: 10 * time.Second,
        Resolver: resolver,
    }

    transport := &http.Transport{
        DialContext: dialer.DialContext,
    }

    client := &http.Client{
        Transport: transport,
        Timeout:   15 * time.Second,
    }
        wasm.Info(fmt.Sprintf("Request error: %s", "err.Error()"))

    // ✅ NewRequest ici
    req, err := http.NewRequest("GET", rssURL, nil)
    if err != nil {
        wasm.Info(fmt.Sprintf("Request error: %s", err.Error()))
        return
    }

    // (optionnel) header
    req.Header.Set("User-Agent", "Trivy-Module")

    // ✅ exécution
    resp, err := client.Do(req)
    if err != nil {
        wasm.Info(fmt.Sprintf("HTTP error: %s", err.Error()))
        return
    }
    defer resp.Body.Close()


    var rss RSS
    if err := xml.NewDecoder(resp.Body).Decode(&rss); err != nil {
        log.Fatal(err)
    }
        wasm.Info(fmt.Sprintf("iuh Version: %s", "grouped.Slug"))

    grouped := make(map[string]*Output)
        wasm.Info(fmt.Sprintf("aef Version: %s", "rsssssssssssss.Slug"))

    for _, item := range rss.Channel.Items {
        adv := parseDescription(item.Description)
        adv.IssueURL = item.Link

        ok := isCVEPublished(adv.CVE)
        if ok {
            continue
        }

        slug := adv.ProjectSlug
        if slug == "" {
            continue
        }

        // init
        if _, exists := grouped[slug]; !exists {
            grouped[slug] = &Output{
                Slug:        slug,
                ProjectName: adv.ProjectName,
                ProjectURL:  adv.ProjectURL,
            }
        }

        entry := grouped[slug]

        // ✅ prendre 1 seul CVE
        cves := parseCVE(adv.CVE)
        var cve string
        if len(cves) > 0 {
            cve = cves[0]
        }

        advisory := AdvisoryItem{
            CVE:           cve,
            Versions:      strings.TrimSpace(adv.AffectedVersions),
            Criticality:   adv.Criticality,
            Vulnerability: adv.Vulnerability,
            IssueURL:      adv.IssueURL,
        }

        entry.Advisories = append(entry.Advisories, advisory)
    }

    // convertir map → slice
    var outputs []Output
    for _, v := range grouped {
        outputs = append(outputs, *v)
    }

    // JSON propre
    var buf bytes.Buffer
    encoder := json.NewEncoder(&buf)
    encoder.SetIndent("", "  ")
    encoder.SetEscapeHTML(false)

    if err := encoder.Encode(outputs); err != nil {
        log.Fatal(err)
    }

    jsonData := buf.Bytes()

    // écrire fichier
    fileName := fmt.Sprintf(filepath)
    err = os.WriteFile(fileName, jsonData, 0644)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println("✅ JSON généré :", fileName)
}

// ---------------- Helpers ----------------

func parseCVE(raw string) []string {
    return strings.Fields(raw)
}

func isCVEPublished(cve string) bool {
    url := "https://cveawg.mitre.org/api/cve/" + cve

    tr := &http.Transport{
        TLSClientConfig: &tls.Config{
            InsecureSkipVerify: true,
        },
    }

    client := &http.Client{
        Timeout:   5 * time.Second,
        Transport: tr,
    }

    resp, err := client.Get(url)
    if err != nil {
        return false
    }
    defer resp.Body.Close()

    return resp.StatusCode == http.StatusOK
}

func extractProjectSlug(rawURL string) string {
    u, err := url.Parse(rawURL)
    if err != nil {
        return ""
    }

    parts := strings.Split(u.Path, "/")

    for i, p := range parts {
        if p == "project" && i+1 < len(parts) {
            slug := parts[i+1]
            if slug == "drupal" {
                return "core"
            }
            return slug
        }
    }

    return ""
}

func parseDescription(desc string) Advisory {
    var adv Advisory

    decoded := stdhtml.UnescapeString(desc)

    doc, err := xhtml.Parse(strings.NewReader(decoded))
    if err != nil {
        log.Println("HTML parse error:", err)
        return adv
    }

    adv.ProjectName, adv.ProjectURL = findProject(doc)
    adv.ProjectSlug = extractProjectSlug(adv.ProjectURL)
    adv.Criticality = findField(doc, "Security risk:")
    adv.Vulnerability = findField(doc, "Vulnerability:")
    adv.AffectedVersions = findField(doc, "Affected versions:")
    adv.CVE = findField(doc, "CVE IDs:")

    return adv
}

func extractText(n *xhtml.Node) string {
    var parts []string

    var f func(*xhtml.Node)
    f = func(node *xhtml.Node) {
        if node.Type == xhtml.TextNode {
            txt := strings.TrimSpace(node.Data)
            if txt != "" {
                parts = append(parts, txt)
            }
        }
        for c := node.FirstChild; c != nil; c = c.NextSibling {
            f(c)
        }
    }

    f(n)
    return strings.Join(parts, " ")
}

func findProject(n *xhtml.Node) (string, string) {
    var name, url string

    var f func(*xhtml.Node)
    f = func(node *xhtml.Node) {
        if node.Type == xhtml.ElementNode && node.Data == "a" {
            for _, attr := range node.Attr {
                if attr.Key == "href" && strings.Contains(attr.Val, "/project/") {
                    name = extractText(node)
                    url = attr.Val
                }
            }
        }
        for c := node.FirstChild; c != nil; c = c.NextSibling {
            f(c)
        }
    }

    f(n)
    return name, url
}

func findField(n *xhtml.Node, label string) string {
    var result string

    var f func(*xhtml.Node)
    f = func(node *xhtml.Node) {
        if node.Type == xhtml.TextNode && strings.TrimSpace(node.Data) == label {
            if node.Parent != nil && node.Parent.Parent != nil {
                result = extractText(node.Parent.Parent)
                result = strings.ReplaceAll(result, label, "")
                result = strings.TrimSpace(result)
            }
        }
        for c := node.FirstChild; c != nil; c = c.NextSibling {
            f(c)
        }
    }

    f(n)
    return result
}