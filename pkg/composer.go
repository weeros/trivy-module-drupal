package pkg

import (
    "encoding/json"
    "fmt"
    "os"
    "strings"

)

type ComposerLock struct {
    Packages    []Package `json:"packages"`
    PackagesDev []Package `json:"packages-dev"`
}

type Package struct {
    Name    string `json:"name"`
    Version string `json:"version"`
}

func ExtractDrupalModules(filePath string) map[string]string {
    data, err := os.ReadFile(filePath)
    if err != nil {
        fmt.Printf("Erreur lecture fichier: %v\n", err)
        os.Exit(1)
    }

    var lock ComposerLock
    if err := json.Unmarshal(data, &lock); err != nil {
        fmt.Printf("Erreur parsing JSON: %v\n", err)
        os.Exit(1)
    }

	result := make(map[string]string)
    all := append(lock.Packages, lock.PackagesDev...)

    for _, pkg := range all {
        if strings.HasPrefix(pkg.Name, "drupal/") {
            result[pkg.Name] = pkg.Version
        }
    }
    return result
}

