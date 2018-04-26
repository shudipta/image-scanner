package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	reg "github.com/heroku/docker-registry-client/registry"
	"github.com/shudipta/image-scanner/clair"
	"github.com/tamalsaha/go-oneliners"
	//"os/exec"
	"strings"

	"context"

	"github.com/coreos/clair/api/v3/clairpb"
	manifestV1 "github.com/docker/distribution/manifest/schema1"
	manifestV2 "github.com/docker/distribution/manifest/schema2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
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
				Name:          vul.Name,
				NamespaceName: vul.NamespaceName,
				Description:   vul.Description,
				Link:          vul.Link,
				Severity:      vul.Severity,
				FixedBy:       vul.FixedBy,
				FeatureName:   feature.Name,
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

func parseImageName(imageName string) (string, string, string, string, error) {
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
	registryUrl := ""
	parts := strings.Split(repo, "/")
	if parts[0] == "docker.io" {
		registryUrl = "https://registry-1." + parts[0]
	} else {
		registryUrl = "https://" + parts[0]
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
	var dialOption grpc.DialOption
	if secure {
		pemCert, err := ioutil.ReadFile("/home/ac/go/src/github.com/soter/scanner/clair-cert/client@soter.ac.crt")
		if err != nil {
			log.Fatalf("failed to read ca cert: %s", err)
		}
		fmt.Printf(string(pemCert))
		certificate, err := tls.LoadX509KeyPair(
			//"/var/clairapi-client-cert/client.crt",
			//"/var/clairapi-client-cert/client.key",
			"/home/ac/go/src/github.com/soter/scanner/clair-cert/client@soter.ac.crt",
			"/home/ac/go/src/github.com/soter/scanner/clair-cert/client@soter.ac.key",
		)
		if err != nil {
			log.Fatalf("failed to load client cert: %v", err)
		}

		certPool := x509.NewCertPool()
		//pemCert, err := ioutil.ReadFile("/var/clairapi-client-cert/ca.crt")
		pemCert, err = ioutil.ReadFile("/home/ac/go/src/github.com/soter/scanner/clair-cert/ca.crt")
		if err != nil {
			log.Fatalf("failed to read ca cert: %s", err)
		}
		fmt.Printf(string(pemCert))

		ok := certPool.AppendCertsFromPEM(pemCert)
		if !ok {
			log.Fatal("failed to append certs")
		}

		transportCreds := credentials.NewTLS(&tls.Config{
			//ServerName:   "example.com",
			Certificates: []tls.Certificate{certificate},
			RootCAs:      certPool,
		})

		dialOption = grpc.WithTransportCredentials(transportCreds)
	} else {
		dialOption = grpc.WithInsecure()
	}

	conn, err := grpc.Dial(clairAddress, dialOption)
	if err != nil {
		log.Fatalf("error in connecting", err)
	}

	c := clairpb.NewAncestryServiceClient(conn)
	return c
}

func sendLayer(
	req *clairpb.PostAncestryRequest, clairClient clairpb.AncestryServiceClient) {

	oneliners.PrettyJson(req, "post request")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*5)
	defer cancel()
	_, err := clairClient.PostAncestry(ctx, req)
	//_, err := clairClient.PostAncestry(context.Background(), req)
	if err != nil {
		log.Fatalf("\nerror in sending layer request:\n%s\n%v\n",
			"--------------------------------------------------", err)
	}
}

func getLayer(
	repo string,
	clairClient clairpb.AncestryServiceClient) ([]*clair.Feature, []*clair.Vulnerability) {

	req := &clairpb.GetAncestryRequest{
		AncestryName:        repo,
		WithFeatures:        true,
		WithVulnerabilities: true,
	}
	oneliners.PrettyJson(req, "get request")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*5)
	defer cancel()
	resp, err := clairClient.GetAncestry(ctx, req)
	//resp, err := clairClient.GetAncestry(context.Background(), req)
	if err != nil {
		log.Fatalf("\nerror in getting layer:\n%s\n%v\n",
			"--------------------------------------------------", err)
	}
	return GetFeaturs(resp), GetVulnerabilities(resp)
}

var imageName, user, pass, clairAddress string
var secure bool

func init() {
	flag.StringVar(&imageName, "image", "", "name of the image (for private image <user>/<name>)")
	flag.StringVar(&user, "user", "", "username of private docker repo")
	flag.StringVar(&pass, "pass", "", "password of private docker repo")
	flag.StringVar(&clairAddress, "clairAddress", "192.168.99.100:30060", "password of private docker repo")
	flag.BoolVar(&secure, "secure", true, "insecure")
}

func main() {
	//clairAddr := "http://192.168.99.100:30060"
	//clairOutput := "Low"
	flag.Parse()

	fmt.Println("========", imageName, "========")
	fmt.Println("========", user, "========")
	fmt.Println("========", clairAddress, "========")
	registryUrl, repo, tag, _, err := parseImageName(imageName)
	//registry := "https://registry-1.docker.io"
	fmt.Println("=======", registryUrl, "=====", repo, "=======", tag, "=======")
	//if strings.HasPrefix(repo, "docker.io/") {
	//	repo = repo[10:]
	//}

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

	hub := &reg.Registry{
		URL: registryUrl,
		Client: &http.Client{
			Transport: reg.WrapTransport(http.DefaultTransport, registryUrl, user, pass),
		},
		Logf: reg.Quiet,
	}

	// TODO: need to work with hub.ManifestVx()
	fmt.Println("======= getting manifests =======")
	mx, err := hub.ManifestVx(repo, tag)
	if err != nil {
		log.Fatalf("couldn't get the manifest: %v", err)
	}
	registryUrl = registryUrl + "/v2"
	postAncestryRequest := &clairpb.PostAncestryRequest{
		AncestryName: repo,
		Format:       "Docker",
	}

	token = "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
	switch manifest := mx.(type) {
	case *manifestV2.DeserializedManifest:
		layers := make([]*clairpb.PostAncestryRequest_PostLayer, len(manifest.Layers))
		for i, layer := range manifest.Layers {
			layers[i] = &clairpb.PostAncestryRequest_PostLayer{
				Hash:    hashPart(manifest.Config.Digest.String()) + hashPart(layer.Digest.String()),
				Path:    fmt.Sprintf("%s/%s/%s/%s", registryUrl, repo, "blobs", layer.Digest.String()),
				Headers: map[string]string{"Authorization": token},
			}
		}
		postAncestryRequest.Layers = layers
	case *manifestV1.SignedManifest:
		layers := make([]*clairpb.PostAncestryRequest_PostLayer, len(manifest.FSLayers))
		for i, layer := range manifest.FSLayers {
			layers[len(manifest.FSLayers)-1-i] = &clairpb.PostAncestryRequest_PostLayer{
				Hash:    hashPart(layer.BlobSum.String()),
				Path:    fmt.Sprintf("%s/%s/%s/%s", registryUrl, repo, "blobs", layer.BlobSum.String()),
				Headers: map[string]string{"Authorization": token},
			}
		}
		postAncestryRequest.Layers = layers
	default:
		log.Fatalf("unknown manifest type")
	}

	if len(postAncestryRequest.Layers) == 0 {
		keepFootStep("Can't pull fsLayers")
	} else {
		fmt.Println("Analysing", len(postAncestryRequest.Layers), "layers")
	}

	clairClient := clairClientSetup(clairAddress)
	sendLayer(postAncestryRequest, clairClient)
	_, vuls := getLayer(repo, clairClient)

	//oneliners.PrettyJson(fs)
	oneliners.PrettyJson(vuls)
	if vuls != nil {
		fmt.Println("Contains vuls")
	}
}
