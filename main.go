package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	reg "github.com/heroku/docker-registry-client/registry"
	"github.com/shudipta/image-scanner/clair"
	"github.com/tamalsaha/go-oneliners"
	//"os/exec"
	"strings"

	"github.com/coreos/clair/api/v3/clairpb"
	"google.golang.org/grpc"
	"context"
	"k8s.io/kubernetes/pkg/util/parsers"
)

type config struct {
	MediaType string
	Size      int
	Digest    string
}

type layer struct {
	MediaType string
	Size      int
	Digest    string
}

type Canonical struct {
	SchemaVersion int
	MediaType     string
	Config        config
	Layers        []layer
}

type Canonical2 struct {
	SchemaVersion int
	FsLayers      []layer2
}

type layer2 struct {
	BlobSum string
}

func keepFootStep(f string, a ...interface{}) {
	s := fmt.Sprintf("%s\n", f)
	fmt.Fprintf(os.Stderr, s, a...)
}

func RequestBearerToken(repo, user, pass string) *http.Request {
	url := "https://auth.docker.io/token?service=registry.docker.io&scope=repository:" + repo + ":pull&account=" + user
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

func GetVulnerabilities(res *clairpb.GetAncestryResponse) []*clair.Vulnerability {
	//return nil
	var vuls []*clair.Vulnerability
	for _, feature := range res.Ancestry.Features {
		for _, vul := range feature.Vulnerabilities {
			vuls = append(vuls, &clair.Vulnerability{
				Name: vul.Name,
				NamespaceName: vul.NamespaceName,
				Description: vul.Description,
				Link: vul.Link,
				Severity: vul.Severity,
				FixedBy: vul.FixedBy,
				FeatureName: feature.Name,
			})
		}
	}

	return vuls
}

func GetFeaturs(res *clairpb.GetAncestryResponse) []*clair.Feature {
	var fs []*clair.Feature
	for _, feature := range res.Ancestry.Features {
		fs = append(fs, &clair.Feature{
			Name:          feature.Name,
			NamespaceName: feature.NamespaceName,
			Version:       feature.Version,
		})
	}

	return fs
}

func parseImageName(imageName, registryUrl string) (string, string, string, string, error) {
	repo, tag, digest, err := parsers.ParseImageName(imageName)
	if err != nil {
		return "", "", "", "", err
	}
	// the repo part should have registry url as prefix followed by a '/'
	// for example, if image name = "ubuntu" then
	//					repo = "docker.io/library/ubuntu", tag = "latest", digest = ""
	// 				if image name = "k8s.gcr.io/kubernetes-dashboard-amd64:v1.8.1" then
	//					repo = "k8s.gcr.io/kubernetes-dashboard-amd64", tag = "v1.8.1", digest = ""
	// here, for docker registry the api url is "https://registry-1.docker.io"
	// and for other registry the url is "https://k8s.gcr.io"(gcr) or "https://quay.io"(quay)
	parts := strings.Split(repo, "/")
	if registryUrl == "" {
		if parts[0] == "docker.io" {
			registryUrl = "https://registry-1." + parts[0]
		} else {
			registryUrl = "https://" + parts[0]
		}
	}
	repo = strings.Join(parts[1:], "/")

	return registryUrl, repo, tag, digest, err
}

func hashPart(digest string) string {
	if len(digest) < 7 {
		return ""
	}

	return digest[7:]
}

func clairClientSetup(clairAddress string) clairpb.AncestryServiceClient {
	conn, err := grpc.Dial(clairAddress, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}

	c := clairpb.NewAncestryServiceClient(conn)
	return c
}

func sendLayer(
	img Canonical, registry, repo string, clairClient clairpb.AncestryServiceClient) {
	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false, //true
			},
		},
		Timeout: time.Minute,
	}
	token := GetBearerToken(
		client.Do(
			RequestBearerToken(repo, user, pass),
		),
	)

	var v3Layers []*clairpb.PostAncestryRequest_PostLayer
	for i := 0; i < len(img.Layers); i++ {
		v3Layers = append(v3Layers, &clairpb.PostAncestryRequest_PostLayer{
			Hash: hashPart(img.Config.Digest) + hashPart(img.Layers[i].Digest),
			Path: fmt.Sprintf("%s/%s/%s/%s", registry, repo, "blobs", img.Layers[i].Digest),
			Headers: map[string]string{"Authorization": token},
		})
	}
	req := &clairpb.PostAncestryRequest {
		AncestryName: imageName,
		Format: "Docker",
		Layers: v3Layers,
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_, err := clairClient.PostAncestry(ctx, req)
	if err != nil {
		log.Fatalf("\nerror in sending layer request:\n%s\n%v\n",
			"--------------------------------------------------", err)
	}
}

func getLayer(
	clairAddress string, img Canonical, 
	clairClient clairpb.AncestryServiceClient) ([]*clair.Feature, []*clair.Vulnerability) {

	req := &clairpb.GetAncestryRequest {
		AncestryName: imageName,
		WithFeatures: true,
		WithVulnerabilities: true,
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	resp, err := clairClient.GetAncestry(ctx, req)
	if err != nil {
		log.Fatalf("\nerror in getting layer:\n%s\n%v\n",
			"--------------------------------------------------", err)
	}
	return GetFeaturs(resp), GetVulnerabilities(resp)
}

var imageName, user, pass, clairAddress string

func init() {
	flag.StringVar(&imageName, "image", "", "name of the image (for private image <user>/<name>)")
	flag.StringVar(&user, "user", "", "username of private docker repo")
	flag.StringVar(&pass, "pass", "", "password of private docker repo")
	flag.StringVar(&clairAddress, "clairAdress", "http://192.168.99.100:30060", "password of private docker repo")
}

func main() {
	//clairAddr := "http://192.168.99.100:30060"
	//clairOutput := "Low"
	flag.Parse()

	fmt.Println("========", imageName, "========")
	fmt.Println("========", user, "========")
	fmt.Println("========", clairAddress, "========")
	registry, repo, tag, _, err := parseImageName(imageName, "")
	//registry := "https://registry-1.docker.io"
	fmt.Println("=======", registry, "=====", repo, "=======", tag, "=======")
	if strings.HasPrefix(repo, "docker.io/") {
		repo = repo[10:]
	}
	hub := &reg.Registry{
		URL: registry,
		Client: &http.Client{
			Transport: reg.WrapTransport(http.DefaultTransport, registry, user, pass),
		},
		Logf: reg.Quiet,
	}

	fmt.Println("======= getting manifests =======")
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

	oneliners.PrettyJson(img, imageName)
	if img.Layers == nil {
		var img2 Canonical2
		if err := json.NewDecoder(bytes.NewReader(canonical)).Decode(&img2); err != nil {
			log.Fatalf("\nerror in decoding canonical into Image2:\n%s\n%v\n",
				"--------------------------------------------------", err)
		}
		img.Layers = make([]layer, len(img2.FsLayers))
		for i, l := range img2.FsLayers {
			img.Layers[len(img2.FsLayers)-1-i].Digest = l.BlobSum
		}
		img.SchemaVersion = img2.SchemaVersion
	}

	if len(img.Layers) == 0 {
		keepFootStep("Can't pull fsLayers")
	} else {
		fmt.Println("Analysing", len(img.Layers), "layers")
	}
	
	clairClient := clairClientSetup(clairAddress)
	sendLayer(img, registry, repo, clairClient)
	fs, vuls := getLayer(clairAddress, img, clairClient)
	
	oneliners.PrettyJson(fs)
	oneliners.PrettyJson(vuls)
}
