# Trivy WoredPress Module

This module provides a more in-depth investigation of drupal detection.

## Set up

```
GOOS=wasip1 GOARCH=wasm go build -o drupal.wasm -buildmode=c-shared drupal.go 
mkdir -p ~/.trivy/modules
mv drupal.wasm ~/.trivy/modules
```

It is also available in [GHCR][trivy-module-drupal].
You can install it via `trivy module install`.

```bash
$ trivy module install ghcr.io/aquasecurity/trivy-module-drupal
2022-06-13T15:32:21.972+0300    INFO    Installing the module from ghcr.io/aquasecurity/trivy-module-drupal...
```

## Run Trivy

```
$ trivy image drupal:5.7.1
2022-05-29T22:35:04.873+0300    INFO    Loading drupal.wasm...
2022-05-29T22:35:05.348+0300    INFO    Registering WASM module: drupal@v1
```

In the above example, CVE-2020-36326 and CVE-2018-19296 will be detected if the drupal version is vulnerable.

[trivy-module-drupal]: https://github.com/orgs/aquasecurity/packages/container/package/trivy-module-drupal




go get -u
GOPROXY=https://proxy.golang.org go mod tidy



