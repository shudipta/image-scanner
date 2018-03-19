package main

import (
	"fmt"
	"os"
	"k8s.io/kubernetes/pkg/util/parsers"
	"log"
	reg "github.com/heroku/docker-registry-client/registry"
	"bytes"
	"encoding/json"
	"net/http"
	"time"
	"github.com/shudipta/image-scanner/clair"
	"crypto/tls"
	"github.com/tamalsaha/go-oneliners"
	"flag"
)

type config struct {
	MediaType string
	Size int
	Digest    string
}

type layer struct {
	MediaType string
	Size int
	Digest    string
}

type Canonical struct {
	SchemaVersion int
	MediaType string
	Config        config
	Layers        []layer
}

func keepFootStep(f string, a ...interface{}) {
	s := fmt.Sprintf("%s\n", f)
	fmt.Fprintf(os.Stderr, s, a...)
}

func RequestBearerToken(repo, user, pass string) *http.Request {
	url := "https://auth.docker.io/token?service=registry.docker.io&scope=repository:" + repo +":pull&account=" + user
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatalf("\nerror in creating request for Bearer Token:\n%s\n%v\n",
			"--------------------------------------------------", err)
	}
	if user != "" {
		req.SetBasicAuth(user, pass)
	}

	return req
}

func GetBearerToken(resp *http.Response, err error) string {
	if err != nil {
		log.Fatalf("\nerror in getting response for Bearer Token request:\n%s\n%v\n",
			"--------------------------------------------------", err)
	}

	defer resp.Body.Close()

	var token struct {
		Token string
	}

	if err = json.NewDecoder(resp.Body).Decode(&token); err != nil {
		log.Fatal("\nerror in decoding Bearer Token response Body:\n%s\n%v\n",
			"--------------------------------------------------", err)
	}
	return fmt.Sprintf("Bearer %s", token.Token)
}

func RequestSendingLayer(l *clair.LayerType) *http.Request {
	//oneliners.PrettyJson(l)

	var layerApi struct{
		Layer *clair.LayerType
	}
	layerApi.Layer = l
	reqBody, err := json.Marshal(layerApi)
	if err != nil {
		log.Fatalf("\nerror in converting request body for sending layer request:\n%s\n%v\n",
			"--------------------------------------------------", err)
	}
	url := "http://192.168.99.100:30060/v1/layers"

	req, err := http.NewRequest("POST", url, bytes.NewReader(reqBody))
	if err != nil {
		log.Fatalln("\nerror in creating request for sending layer:\n%s\n%v\n",
			"--------------------------------------------------", err)
	}
	req.Header.Set("Content-Type", "application/json")

	return req
}

func RequestVulnerabilities(hashNameOfImage string) *http.Request {
	url := "http://192.168.99.100:30060/v1/layers/" + hashNameOfImage + "?vulnerabilities"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatalf("\nerror in creating request for getting vulnerabilities:\n%s\n%v\n",
			"--------------------------------------------------", err)
	}

	return req
}

func GetVulnerabilities(resp *http.Response, err error) []*clair.Vulnerability {
	if err != nil {
		log.Fatalf("\nerror in getting response for vulnerabilities request:\n%s\n%v\n",
			"--------------------------------------------------", err)
	}

	defer resp.Body.Close()

	var layerApi struct{
		Layer *clair.LayerType
	}
	err = json.NewDecoder(resp.Body).Decode(&layerApi)
	if err != nil {
		log.Fatalln("\nerror in converting response body into structure:\n%s\n%v\n",
			"--------------------------------------------------", err)
	}
	//oneliners.PrettyJson(layerApi)
	var vuls []*clair.Vulnerability
	for _, feature := range layerApi.Layer.Features {
		for _, vul := range feature.Vulnerabilities {
			vuls = append(vuls, &vul)
		}
	}

	return vuls
}

var imageName, user, pass string
func init() {
	flag.StringVar(&imageName, "image", "", "name of the image (for private image <user>/<name>)")
	flag.StringVar(&user, "user", "", "username of private docker repo")
	flag.StringVar(&pass, "pass", "", "password of private docker repo")
}

func main() {
	//clairAddr := "http://192.168.99.100:30060"
	//clairOutput := "Low"
	flag.Parse()

	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false, //true
			},
		},
		Timeout: time.Minute,
	}
	repo, tag, _, err := parsers.ParseImageName(imageName)
	if err != nil {
		log.Fatal(err)
	}
	repo = repo[10:]
	registry := "https://registry-1.docker.io/v2"

	hub, err := reg.New("https://registry-1.docker.io/", user, pass)
	if err != nil {
		log.Fatalf("couldn't create registry %v: ", err)
	}

	manifest, err := hub.ManifestV2(repo, tag)
	if err != nil {
		log.Fatalf("couldn't get the manifest: %v", err)
	}
	canonical, err := manifest.MarshalJSON()
	if err != nil {
		log.Fatalf("couldn't get the manifest.canonical: %v", err)
	}
	can := bytes.NewReader(canonical)

	var img Canonical
	if err := json.NewDecoder(can).Decode(&img); err != nil {
		log.Fatalf("\nerror in decoding canonical into Image:\n%s\n%v\n",
			"--------------------------------------------------", err)
	}
	oneliners.PrettyJson(img,"img")

	var ls []layer
	for _, l := range img.Layers {
		if l.Digest == "" {
			continue
		}
		ls = append(ls, l)
	}
	digest := img.Config.Digest
	//schemaVersion := img.SchemaVersion

	if len(ls) == 0 {
		keepFootStep("Can't pull fsLayers")
	} else {
		fmt.Println("Analysing", len(ls), "layers")
	}

	clairClient := http.Client{
		Timeout: time.Minute,
	}
	lsLen := len(ls)
	var parent string
	var token string = GetBearerToken(
		client.Do(
			RequestBearerToken(repo, user, pass),
		),
	)
	for i := 0; i < lsLen; i++ {
		//if i > 0 {
		//	parent = digest[7:] + ls[i - 1].Digest[7:]
		//}
		l := &clair.LayerType{
			Name: digest[7:] + ls[i].Digest[7:],
			Path: fmt.Sprintf("%s/%s/%s/%s", registry, repo, "blobs", ls[i].Digest),
			ParentName: parent,
			Format: "Docker",
			Headers: clair.HeadersType{
				Authorization: token,
			},
		}
		//oneliners.FILE("bearer token is:", l.Headers.Authorization)
		parent = l.Name

		_, err := clairClient.Do(
			RequestSendingLayer(l),
		)
		if err != nil {
			log.Fatalf("\nerror in sending layer request:\n%s\n%v\n",
				"--------------------------------------------------", err)
		}
	}

	vuls := GetVulnerabilities(
		clairClient.Do(
			RequestVulnerabilities(digest[7:] + ls[lsLen - 1].Digest[7:]),
		),
	)

	oneliners.PrettyJson(vuls)
}
