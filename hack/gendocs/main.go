package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/appscode/go/runtime"
	"github.com/soter/scanner/pkg/cmds"
	"github.com/spf13/cobra/doc"
)

const (
	version = "0.1.0"
)

// ref: https://github.com/spf13/cobra/blob/master/doc/md_docs.md
func main() {
	genScannerDocs()
	genCliDocs()
}

func genScannerDocs() {
	var (
		tplFrontMatter = template.Must(template.New("index").Parse(`---
title: Scanner
description: Scanner Reference
menu:
  product_scanner_{{ .Version }}:
    identifier: scanner
    name: Scanner
    parent: reference
    weight: 10
menu_name: product_scanner_{{ .Version }}
---
`))

		_ = template.Must(tplFrontMatter.New("cmd").Parse(`---
title: {{ .Name }}
menu:
  product_scanner_{{ .Version }}:
    identifier: {{ .ID }}
    name: {{ .Name }}
    parent: scanner-cli
{{- if .RootCmd }}
    weight: 0
{{ end }}
product_name: scanner
section_menu_id: reference
menu_name: product_scanner_{{ .Version }}
{{- if .RootCmd }}
url: /products/scanner/{{ .Version }}/reference/scanner/
aliases:
  - products/scanner/{{ .Version }}/reference/scanner/scanner/
{{ end }}
---
`))
	)
	rootCmd := cmds.NewCmdScanner()
	dir := runtime.GOPath() + "/src/github.com/soter/scanner/docs/reference/scanner"
	fmt.Printf("Generating cli markdown tree in: %v\n", dir)
	err := os.RemoveAll(dir)
	if err != nil {
		log.Fatalln(err)
	}
	err = os.MkdirAll(dir, 0755)
	if err != nil {
		log.Fatalln(err)
	}

	filePrepender := func(filename string) string {
		filename = filepath.Base(filename)
		base := strings.TrimSuffix(filename, path.Ext(filename))
		name := strings.Title(strings.Replace(base, "_", " ", -1))
		parts := strings.Split(name, " ")
		if len(parts) > 1 {
			name = strings.Join(parts[1:], " ")
		}
		data := struct {
			ID      string
			Name    string
			Version string
			RootCmd bool
		}{
			strings.Replace(base, "_", "-", -1),
			name,
			version,
			!strings.ContainsRune(base, '_'),
		}
		var buf bytes.Buffer
		if err := tplFrontMatter.ExecuteTemplate(&buf, "cmd", data); err != nil {
			log.Fatalln(err)
		}
		return buf.String()
	}

	linkHandler := func(name string) string {
		return "/docs/reference/scanner/" + name
	}
	doc.GenMarkdownTreeCustom(rootCmd, dir, filePrepender, linkHandler)

	index := filepath.Join(dir, "_index.md")
	f, err := os.OpenFile(index, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		log.Fatalln(err)
	}
	err = tplFrontMatter.ExecuteTemplate(f, "index", struct{ Version string }{version})
	if err != nil {
		log.Fatalln(err)
	}
	if err := f.Close(); err != nil {
		log.Fatalln(err)
	}
}

func genCliDocs() {
	var (
		tplFrontMatter = template.Must(template.New("index").Parse(`---
title: Scanner CLI
description: Searchlight Scanner CLI Reference
menu:
  product_scanner_{{ .Version }}:
    identifier: scanner-cli
    name: Scanner CLI
    parent: reference
    weight: 20
menu_name: product_scanner_{{ .Version }}
---
`))

		_ = template.Must(tplFrontMatter.New("cmd").Parse(`---
title: {{ .Name }}
menu:
  product_scanner_{{ .Version }}:
    identifier: {{ .ID }}
    name: {{ .Name }}
    parent: scanner-cli
{{- if .RootCmd }}
    weight: 0
{{ end }}
product_name: scanner
section_menu_id: reference
menu_name: product_scanner_{{ .Version }}
{{- if .RootCmd }}
url: /products/scanner/{{ .Version }}/reference/scanner-cli/
aliases:
  - products/scanner/{{ .Version }}/reference/scanner-cli/scanner-cli/
{{ end }}
---
`))
	)
	rootCmd := cmds.NewCmdCli("", false)
	dir := runtime.GOPath() + "/src/github.com/soter/scanner/docs/reference/scanner-cli"
	fmt.Printf("Generating cli markdown tree in: %v\n", dir)
	err := os.RemoveAll(dir)
	if err != nil {
		log.Fatalln(err)
	}
	err = os.MkdirAll(dir, 0755)
	if err != nil {
		log.Fatalln(err)
	}

	filePrepender := func(filename string) string {
		filename = filepath.Base(filename)
		base := strings.TrimSuffix(filename, path.Ext(filename))
		name := strings.Title(strings.Replace(base, "_", " ", -1))
		parts := strings.Split(name, " ")
		if len(parts) > 1 {
			name = strings.Join(parts[1:], " ")
		}
		data := struct {
			ID      string
			Name    string
			Version string
			RootCmd bool
		}{
			strings.Replace(base, "_", "-", -1),
			name,
			version,
			!strings.ContainsRune(base, '_'),
		}
		var buf bytes.Buffer
		if err := tplFrontMatter.ExecuteTemplate(&buf, "cmd", data); err != nil {
			log.Fatalln(err)
		}
		return buf.String()
	}

	linkHandler := func(name string) string {
		return "/docs/reference/scanner-cli/" + name
	}
	doc.GenMarkdownTreeCustom(rootCmd, dir, filePrepender, linkHandler)

	index := filepath.Join(dir, "_index.md")
	f, err := os.OpenFile(index, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		log.Fatalln(err)
	}
	err = tplFrontMatter.ExecuteTemplate(f, "index", struct{ Version string }{version})
	if err != nil {
		log.Fatalln(err)
	}
	if err := f.Close(); err != nil {
		log.Fatalln(err)
	}
}
