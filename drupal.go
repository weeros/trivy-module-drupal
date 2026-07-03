package main

import (
	"fmt"
	"strings"
	"github.com/weeros/trivy-module-drupal/pkg"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/module/api"
	"github.com/aquasecurity/trivy/pkg/module/serialize"
	"github.com/aquasecurity/trivy/pkg/module/wasm"
	"github.com/aquasecurity/trivy/pkg/types"
)

type Module interface {
	Version() int
	Name() string
}

type Analyzer interface {
	RequiredFiles() []string
	Analyze(filePath string) (*serialize.AnalysisResult, error)
}

type PostScanner interface {
	PostScanSpec() serialize.PostScanSpec
	PostScan(types.Results) (types.Results, error)
}

const (
	moduleVersion = 1
	name          = "drupal-module"
)

func main() {}

func init() {
	wasm.RegisterModule(drupalModule{})
}

type drupalModule struct {
	// Cannot define fields as modules can't keep state.
}

func (drupalModule) Version() int {
	return moduleVersion
}

func (drupalModule) Name() string {
	return name
}

const typeDrupalModule = "drupal-module"

func (drupalModule) RequiredFiles() []string {
	return []string{
		`composer.lock`,
	}
}


func (drupalModule) Analyze(filePath string) (*serialize.AnalysisResult, error) {
    modules := pkg.ExtractDrupalModules(filePath)
   
    var modulesList []map[string]string
    for k, v := range modules {
        modulesList = append(modulesList, map[string]string{
            "name":    k,
            "version": v,
        })
    }

    customResources := []ftypes.CustomResource{
        {
            Type:     typeDrupalModule,
            FilePath: filePath,
            Data:     modulesList,
        },
    }

    return &serialize.AnalysisResult{
        CustomResources: customResources,
    }, nil
}


func (drupalModule) PostScanSpec() serialize.PostScanSpec {
	return serialize.PostScanSpec{
		Action: api.ActionInsert, // Add new vulnerabilities
	}
}

func (drupalModule) PostScan(results types.Results) (types.Results, error) {
	var finalReults = results
	for _, result := range results {
		if result.Class != types.ClassCustom {
			continue
		}
		for _, c := range result.CustomResources {
			if c.Type != typeDrupalModule {
				continue
			}

			dataSlice, ok := c.Data.([]interface{})
			if !ok {
				continue
			}

			var vulns []types.DetectedVulnerability
			for _, item := range dataSlice {
				moduleMap, ok := item.(map[string]interface{})
				if !ok {
					continue
				}

				moduleName, _ := moduleMap["name"].(string)
				moduleVersion, _ := moduleMap["version"].(string)
				wasm.Info(fmt.Sprintf("moduleName Version: %s", moduleName))
				slug := strings.TrimPrefix(moduleName, "drupal/")
				search, found := pkg.FindBySlug(pkg.Projects, slug)
				if !found {
					continue
				}
				for _, item := range search.Advisories {
					vulns = append(vulns, types.DetectedVulnerability{
						VulnerabilityID:  item.CVE,
						PkgName:          moduleName,
						InstalledVersion: moduleVersion,
						FixedVersion:     "6",
						Vulnerability: dbTypes.Vulnerability{
							Title:    item.IssueURL,
							Severity: "CRITICAL",
						},
					})
				}
			}

			finalReults = append(finalReults, types.Result{
				Target:          c.FilePath,
				Class:           types.ClassLangPkg,
				Type:            "composer",
				Vulnerabilities: vulns,
			})
		}
	}
	return finalReults, nil
}
