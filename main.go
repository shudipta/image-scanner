package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
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
	url := "https://auth.docker.io/token?service=registry.docker.io&scope=repository:" + repo + ":pull"
	if user != "" {
		url = url + "&account=" + user
	}
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
		log.Fatalf("\nerror in decoding Bearer Token response Body:\n%s\n%v\n",
			"--------------------------------------------------", err)
	}
	if token.Token == "" {
		log.Fatal("\nEmpty Bearer Token\n",
			"--------------------------------------------------")
	}
	return fmt.Sprintf("Bearer %s", token.Token)
}

func GetVulnerabilities(res clair.ScanResult) []clair.Vulnerability {
	var vuls []clair.Vulnerability
	for _, l := range res.Layers {
		for _, f := range l.Features {
			vuls = append(vuls, f.Vulnerabilities...)
		}
	}

	return vuls
}

func GetResult(res *clairpb.GetAncestryResponse) clair.ScanResult {
	var r clair.ScanResult
	r.Name = res.Ancestry.Name
	r.Layers = make([]clair.Layer, 0, len(res.Ancestry.Layers))

	for _, l := range res.Ancestry.Layers {
		layer := clair.Layer{}
		if l != nil {
			if l.Layer != nil {
				layer.Hash = l.Layer.Hash
			}
			for _, f := range l.DetectedFeatures {
				if f != nil {
					feat := clair.Feature{
						Name: f.Name,
						Version: f.Version,
					}
					if f.Namespace != nil {
						feat.NamespaceName = f.Namespace.Name
					}
					for _, v := range f.Vulnerabilities {
						if v != nil {
							feat.Vulnerabilities = append(feat.Vulnerabilities, clair.Vulnerability{
								Name: v.Name,
								NamespaceName: v.NamespaceName,
								Description: v.Description,
								Link: v.Link,
								Severity: v.Severity,
								FixedBy: v.FixedBy,
							})
						}
					}
					layer.Features = append(layer.Features, feat)
				}
			}
		}
		r.Layers = append(r.Layers, layer)
	}

	return r
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
		log.Fatalf("error in connecting: %v", err)
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
	clairClient clairpb.AncestryServiceClient) clair.ScanResult {

	req := &clairpb.GetAncestryRequest{
		AncestryName:        repo,
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
	return GetResult(resp)
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

var tokenRe = regexp.MustCompile(`Bearer realm="(.*?)",service="(.*?)",scope="(.*?)"`)
func requestToken(client *http.Client, resp *http.Response) (string, error) {
	authHeader := resp.Header.Get("Www-Authenticate")
	if authHeader == "" {
		return "", fmt.Errorf("Empty Www-Authenticate")
	}
	parts := tokenRe.FindStringSubmatch(authHeader)
	if parts == nil {
		return "", fmt.Errorf("Can't parse Www-Authenticate: %s", authHeader)
	}
	realm, service, scope := parts[1], parts[2], parts[3]
	var url string
	if user != "" {
		url = fmt.Sprintf("%s?service=%s&scope=%s&account=%s", realm, service, scope, user)
	} else {
		url = fmt.Sprintf("%s?service=%s&scope=%s", realm, service, scope)
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println(os.Stderr, "Can't create a request")
		return "", err
	}
	if user != "" {
		req.SetBasicAuth(user, pass)
	}
	tResp, err := client.Do(req)
	if err != nil {
		return "", err
	}

	defer tResp.Body.Close()
	if tResp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Token request returned %d", tResp.StatusCode)
	}
	var tokenEnv struct {
		Token string
	}

	if err = json.NewDecoder(tResp.Body).Decode(&tokenEnv); err != nil {
		fmt.Fprintln(os.Stderr, "Token response decode error")
		return "", err
	}
	return fmt.Sprintf("Bearer %s", tokenEnv.Token), nil
}

func pullLayer(client *http.Client, url string, token *string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatalln(os.Stderr, "Can't create a request")
	}
	if user != "" {
		req.SetBasicAuth(user, pass)
		*token = req.Header.Get("Authorization")
	}

	return client.Do(req)
}

func getAuthToken(client *http.Client, url string, token *string) error {
	resp, err := pullLayer(client, url, token)
	if err != nil {
		log.Fatal("err = ", err)
		return err
	}

	if resp.StatusCode == http.StatusUnauthorized {
		if *token == "" {
			*token, err = requestToken(client, resp)
		}
		if err != nil {
			log.Fatal("err = ", err)
			return err
		}
		// try again
		resp, err = pullLayer(client, url, token)
		if err != nil {
			log.Fatal("err = ", err)
			return err
		}
		defer resp.Body.Close()
		// try one more time by clearing the token to request it
		if resp.StatusCode == http.StatusUnauthorized {
			*token, err = requestToken(client, resp)
			if err != nil {
				log.Fatal("err = ", err)
				return err
			}
		}
	}

	return nil
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
		Logf: reg.Log,
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

	//token = "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
	//token = "Bearer " + "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjVmYjAxYzFmMGIzYTVmNjJhODBkMDQyMTAzZGFkOTA1YTAxYzJiOTk3Y2QwZDllYTJlMzZmMDBkY2Q0ODQ0MjYifQ.eyJhY2Nlc3MiOlt7InR5cGUiOiJyZXBvc2l0b3J5IiwibmFtZSI6ImNvcmVvcy9jbGFpci1naXQiLCJhY3Rpb25zIjpbInB1bGwiXX1dLCJjb250ZXh0Ijp7ImNvbS5hcG9zdGlsbGUucm9vdHMiOnsiY29yZW9zL2NsYWlyLWdpdCI6IiRkaXNhYmxlZCJ9LCJjb20uYXBvc3RpbGxlLnJvb3QiOiIkZGlzYWJsZWQifSwiYXVkIjoicXVheS5pbyIsImV4cCI6MTU0NjUxODQzNSwiaXNzIjoicXVheSIsImlhdCI6MTU0NjUxNDgzNSwibmJmIjoxNTQ2NTE0ODM1LCJzdWIiOiIoYW5vbnltb3VzKSJ9.dOn3Zk9HPS9aJOXFgobt25gx3k5zrFcG2wf5OPxWkQFiQ7w2oSXqXy3v3VnsuEsMe8AFDUNBj1-3DM5rODMBdXcOJXhmF8XelqTe1v3jXc84tG5f97UgNloLahtFzcBa79-4Rnh3Zmng03JsNGVzvka6IGmdl0UFyPo2XL1JWgE5hPJWAWYRNpuqRNG_ccIzH7XmJYxDl1ImW3BV5aFmoT0d0GtVtS_8i6tx8cWqK3gV3iNGx7YCVtFEsRnoVfEfmfDgVtgORK0BtVU6Dc_WUOw98EIuV4C-wFJSEDXKZFS3BBEi57EGpdDFv1nKHevTMisJu3KsLO5IqTcB02qdtg"
	switch manifest := mx.(type) {
	case *manifestV2.DeserializedManifest:
		oneliners.PrettyJson(*manifest, "v2")
		layers := make([]*clairpb.PostAncestryRequest_PostLayer, len(manifest.Layers))
		for i, layer := range manifest.Layers {
			if token == "" {
				url := fmt.Sprintf("%s/%s/%s/%s", registryUrl, repo, "blobs", layer.Digest.String())
				err = getAuthToken(&client, url, &token)
				if err != nil {
					log.Fatal(err)
				}
			}
			layers[i] = &clairpb.PostAncestryRequest_PostLayer{
				Hash:    hashPart(manifest.Config.Digest.String()) + hashPart(layer.Digest.String()),
				Path:    fmt.Sprintf("%s/%s/%s/%s", registryUrl, repo, "blobs", layer.Digest.String()),
				Headers: map[string]string{"Authorization": token},
			}
		}
		postAncestryRequest.Layers = layers
	case *manifestV1.SignedManifest:
		oneliners.PrettyJson(*manifest, "v1")
		layers := make([]*clairpb.PostAncestryRequest_PostLayer, len(manifest.FSLayers))
		for i, layer := range manifest.FSLayers {
			if token == "" {
				url := fmt.Sprintf("%s/%s/%s/%s", registryUrl, repo, "blobs", layer.BlobSum.String())
				err = getAuthToken(&client, url, &token)
				if err != nil {
					log.Fatal(err)
				}
			}
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
	scanResult := getLayer(repo, clairClient)
	vuls := GetVulnerabilities(scanResult)

	//oneliners.PrettyJson(fs)
	oneliners.PrettyJson(scanResult)
	oneliners.PrettyJson(vuls)
	if len(vuls) > 0 {
		fmt.Println("Contains vuls")
	}
}
