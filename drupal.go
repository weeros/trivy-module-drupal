package main

import (
	"fmt"

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

    index := pkg.GenereatIndex()
	if index == nil {
		return results, nil
	}

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

				wasm.Info(fmt.Sprintf("WordPress Version: %s", "cccccccccccccccccc.Slug"))
				moduleName, _ := moduleMap["name"].(string)
				moduleVersion, _ := moduleMap["version"].(string)

				wasm.Info(fmt.Sprintf("WordPress Version: %s", "aaaaaaaaaaaaaaaaa.Slug"))
				result, found := pkg.FindBySlug(pkg.Projects, "core")
				if !found {
					continue
				}

				wasm.Info(fmt.Sprintf("WordPress Version: %s", "lkmlllllllllllllllll.Slug"))
				println("Slug:", result.Slug)
				println("Advisories:", len(result.Advisories))

				wasm.Info(fmt.Sprintf("WordPress Version: %s", "eeeeeeeeeeeeeeeeeeeeee.Slug"))
				for _, item := range result.Advisories {
					vulns = append(vulns, types.DetectedVulnerability{
						VulnerabilityID:  item.CVE,
						PkgName:          moduleName,
						InstalledVersion: moduleVersion,
						FixedVersion:     "",
						Vulnerability: dbTypes.Vulnerability{
							Title:    item.IssueURL,
							Severity: item.Criticality,
						},
					})
				}
			}

			results = append(results, types.Result{
				Target:          c.FilePath,
				Class:           types.ClassLangPkg,
				Type:            "composer",
				Vulnerabilities: vulns,
			})
		}
	}
	return results, nil
}
