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

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"path/filepath"
	"strconv"

	"github.com/coreos/clair/api/v3/clairpb"
	"google.golang.org/grpc"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/homedir"
	"context"
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

func getAddr() (string, error) {
	var host, port string
	kubeconfig := filepath.Join(homedir.HomeDir(), ".kube", "config")

	cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return "", err
	}
	kubeClient, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return "", err
	}

	pods, err := kubeClient.CoreV1().Pods("default").List(metav1.ListOptions{})
	if err != nil {
		return "", err
	}
	for _, pod := range pods.Items {
		if strings.HasPrefix(pod.Name, "clair") {
			host = pod.Status.HostIP
		}
	}

	clairSvc, err := kubeClient.CoreV1().Services("default").Get("clairsvc", metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	for _, p := range clairSvc.Spec.Ports {
		if p.TargetPort.IntVal == 6060 {
			port = strconv.Itoa(int(p.NodePort))
			break
		}
	}

	if host != "" && port != "" {
		return "http://" + host + ":" + port, nil
	}

	return "", fmt.Errorf("clair isn't running in minikube")
}

func RequestSendingLayer(l *clair.LayerType, serverAddr string) *http.Request {
	//oneliners.PrettyJson(l)

	var layerApi struct {
		Layer *clair.LayerType
	}
	layerApi.Layer = l
	reqBody, err := json.Marshal(layerApi)
	if err != nil {
		log.Fatalf("\nerror in converting request body for sending layer request:\n%s\n%v\n",
			"--------------------------------------------------", err)
	}
	url := serverAddr + "/v1/layers"
	//url = "http://192.168.99.100:30060/v1/layers"
	fmt.Println("==============", url)
	//url = "http://192.168.99.100:30060/v1/layers"

	req, err := http.NewRequest("POST", url, bytes.NewReader(reqBody))
	if err != nil {
		log.Fatalln("\nerror in creating request for sending layer:\n%s\n%v\n",
			"--------------------------------------------------", err)
	}
	req.Header.Set("Content-Type", "application/json")

	return req
}

func RequestVulnerabilities(hashNameOfImage string, serverAddr string) *http.Request {
	url := serverAddr + "/v1/layers/" + hashNameOfImage + "?vulnerabilities"
	//url = "http://192.168.99.100:30060/v1/layers/" + hashNameOfImage + "?vulnerabilities"
	fmt.Println("==============", url)
	//url = "http://192.168.99.100:30060/v1/layers/" + hashNameOfImage + "?vulnerabilities"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		//continue
		log.Fatalf("\nerror in creating request for getting vulnerabilities:\n%s\n%v\n",
			"--------------------------------------------------", err)
	}

	return req
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

func parseImageName(image string) (string, string, string) {
	registry := "registry-1.docker.io"
	tag := "latest"
	var nameParts, tagParts []string
	var name, port string
	state := 0
	start := 0
	for i, c := range image {
		if c == ':' || c == '/' || c == '@' || i == len(image)-1 {
			if i == len(image)-1 {
				i += 1
			}
			part := image[start:i]
			start = i + 1
			switch state {
			case 0:
				if strings.Contains(part, ".") {
					// it's registry, let's check what's next =port of image name
					registry = part
					if c == ':' {
						state = 1
					} else {
						state = 2
					}
				} else {
					if c == '/' {
						start = 0
						state = 2
					} else {
						state = 3
						name = fmt.Sprintf("library/%s", part)
					}
				}
			case 3:
				tag = ""
				tagParts = append(tagParts, part)
			case 1:
				state = 2
				port = part
			case 2:
				if c == ':' || c == '@' {
					state = 3
				}
				nameParts = append(nameParts, part)
			}
		}
	}

	if port != "" {
		registry = fmt.Sprintf("%s:%s", registry, port)
	}

	if name == "" {
		name = strings.Join(nameParts, "/")
	}

	if tag == "" {
		tag = strings.Join(tagParts, ":")
	}

	registry = fmt.Sprintf("https://%s", registry)

	return registry, name, tag
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
	flag.StringVar(&clairAddress, "clairAdress", "192.168.99.100:30060", "password of private docker repo")
}

func main() {
	//clairAddr := "http://192.168.99.100:30060"
	//clairOutput := "Low"
	flag.Parse()

	fmt.Println("========", imageName, "========")
	registry, repo, tag := parseImageName(imageName)
	//registry := "https://registry-1.docker.io"
	//repo, tag, _, err := parsers.ParseImageName(imageName)
	fmt.Println("=======", registry, "=====", repo, "=======", tag, "=======")
	//if err != nil {
	//	log.Fatal(err)
	//}
	if strings.HasPrefix(repo, "docker.io/") {
		repo = repo[10:]
	}
	//registry := "https://registry-1.docker.io/v2"

	//hub, err := reg.New("https://registry-1.docker.io/", user, pass)
	hub := &reg.Registry{
		URL: registry,
		Client: &http.Client{
			Transport: reg.WrapTransport(http.DefaultTransport, registry, user, pass),
		},
		Logf: reg.Quiet,
	}
	//hub, err := reg.New(registry, user, pass)
	//if err != nil {
	//	log.Fatalf("couldn't connect to the registry: %v", err)
	//}

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

	serverAddr, err := getAddr()
	if err != nil {
		log.Fatalf("error in getting ClairAddr: %v", err)
	} else if serverAddr == "" {
		serverAddr = "http://clairsvc:30060"
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
