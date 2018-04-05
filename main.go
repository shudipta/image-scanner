package main

import (
	"fmt"
	"os"
	"log"
	"bytes"
	"encoding/json"
	"net/http"
	"time"
	"github.com/shudipta/image-scanner/clair"
	"crypto/tls"
	"github.com/tamalsaha/go-oneliners"
	"flag"
	//"os/exec"
	"strings"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/kubernetes"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/homedir"
	"path/filepath"
	"strconv"
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

func GetManifests(registry, repo, tag string, client http.Client) (string, Canonical) {
	bearertoken := ""
	url := fmt.Sprintf("%s/%s/manifests/%s", registry, repo, tag)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatalf("error in creating request for manifests: \n%s\n%v\n",
			"---------------------------------------", err)
	}
	req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json")
	if user != "" {
		req.SetBasicAuth(user, pass)
		bearertoken = req.Header.Get("Authorization")
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("\nerror in getting response for manifests request:\n%s\n%v\n",
			"--------------------------------------------------", err)
	} else if resp.StatusCode == 401 {
		bearertoken = GetBearerToken(
			RequestBearerToken(client, resp),
		)
	}
	req.Header.Set("Authorization", bearertoken)

	resp, err = client.Do(req)
	defer resp.Body.Close()

	var imageManifest Canonical
	if err := json.NewDecoder(resp.Body).Decode(&imageManifest); err != nil {
		log.Fatalf("\nerror in decoding canonical into Image:\n%s\n%v\n",
			"--------------------------------------------------", err)
	}

	return bearertoken, imageManifest
}

func GetAuthInfoParts(authInfo string) (string, string, string, string) {
	parts := strings.Split(authInfo, " ")
	tokenType := parts[0]
	parts = strings.Split(parts[1], ",")
	var realm, service, scope string
	for _, p := range parts {
		subParts := strings.Split(p, "=")
		val := subParts[1][1:len(subParts[1]) - 1]
		switch subParts[0] {
		case "realm":
			realm = "realm=" + val
		case "service":
			service = "service=" + val
		case "scope":
			scope = "scope=" + val
		}
	}

	return tokenType, realm, service, scope
}

//Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/nginx:pull"
func RequestBearerToken(client http.Client, resp *http.Response) (string, *http.Response, error) {
	authInfo := resp.Header.Get("Www-Authenticate")
	if authInfo == ""{
		log.Fatalf("can't get authInfo")
	}
	tokenType, realm, service, scope := GetAuthInfoParts(authInfo)
	fmt.Println("....tokenType=", tokenType, "....realm=", realm, "....service=", service, "....scope=", scope)
	url := realm + "?" + service + "&" + scope
	//url := "h" + repo +":pull&account=" + user
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatalf("\nerror in creating request for Bearer Token:\n%s\n%v\n",
			"--------------------------------------------------", err)
	}
	if user != "" {
		req.SetBasicAuth(user, pass)
	}

	resp1, err := client.Do(req)

	return tokenType, resp1, err
}

func GetBearerToken(tokenType string, resp *http.Response, err error) string {
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

	return fmt.Sprintf("%s %s",tokenType, token.Token)
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

	var layerApi struct{
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
	oneliners.PrettyJson(layerApi)
	//return nil
	var vuls []*clair.Vulnerability
	for _, feature := range layerApi.Layer.Features {
		for _, vul := range feature.Vulnerabilities {
			vuls = append(vuls, &vul)
		}
	}

	return vuls
}

func GetFeaturs(resp *http.Response, err error) []*clair.Feature {
	if err != nil {
		log.Fatalf("\nerror in getting response for features request:\n%s\n%v\n",
			"--------------------------------------------------", err)
	}

	defer resp.Body.Close()
	var layerApi struct{
		Layer *clair.LayerType
	}
	err = json.NewDecoder(resp.Body).Decode(&layerApi)
	if err != nil {
		log.Fatalln("\nerror in converting response body into structure in GetFeatures():\n%s\n%v\n",
			"--------------------------------------------------", err)
	}
	//oneliners.PrettyJson(layerApi)
	//return nil
	var fs []*clair.Feature
	for _, feature := range layerApi.Layer.Features {
		//
		//fmt.Println("================")
		//fmt.Println("\t", feature)

		fs = append(fs, &clair.Feature{
			Name: feature.Name,
			NamespaceName: feature.NamespaceName,
			Version: feature.Version,
		})
	}

	return fs
}

func parseImageName(image string) (string, string, string, error) {
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

	registry = fmt.Sprintf("https://%s/v2", registry)

	return registry, name, tag, nil
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
	fmt.Println("========", imageName, "========")
	registry, repo, tag, err := parseImageName(imageName)
	fmt.Println("=========", registry, "=====", repo, "=======", tag, "=======")
	if err != nil {
		log.Fatal(err)
	}
	//if strings.HasPrefix(repo, "docker.io/") {
	//	repo = repo[10:]
	//}
	token, img := GetManifests(registry, repo, tag, client)
	////registry := "https://registry-1.docker.io/v2"
	//
	////hub, err := reg.New("https://registry-1.docker.io/", user, pass)
	//hub, err := reg.New(registry, user, pass)
	//if err != nil {
	//	log.Fatalf("couldn't connect to the registry %v: ", err)
	//}
	//
	//manifest, err := hub.ManifestV2(repo, tag)
	//if err != nil {
	//	log.Fatalf("couldn't get the manifest: %v", err)
	//}
	//canonical, err := manifest.MarshalJSON()
	//if err != nil {
	//	log.Fatalf("couldn't get the manifest.canonical: %v", err)
	//}
	//can := bytes.NewReader(canonical)
	//
	//var img Canonical
	//if err := json.NewDecoder(can).Decode(&img); err != nil {
	//	log.Fatalf("\nerror in decoding canonical into Image:\n%s\n%v\n",
	//		"--------------------------------------------------", err)
	//}
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
		Timeout: time.Minute * 5,
	}
	lsLen := len(ls)
	var parent string
	//var token string = GetBearerToken(
	//	client.Do(
	//		RequestBearerToken(registry, repo, user, pass),
	//	),
	//)
	serverAddr, err := getAddr()
	if err != nil {
		log.Fatalf("error in getting ClairAddr: %v", err)
	} else if serverAddr == "" {
		serverAddr = "http://clairsvc:30060"
	}

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
		parent = ""//l.Name

		_, err := clairClient.Do(
			RequestSendingLayer(l, serverAddr),
		)
		if err != nil {
			log.Fatalf("\nerror in sending layer request:\n%s\n%v\n",
				"--------------------------------------------------", err)
		}

		//if i == 0 {
		//	resp, err := clairClient.Do(
		//		RequestVulnerabilities(digest[7:] + ls[i].Digest[7:], serverAddr),
		//	)
		//
		//	//fs := GetFeaturs(resp, err)
		//	vuls := GetVulnerabilities(resp, err)
		//
		//	oneliners.PrettyJson(vuls)
		//
		//	return
		//}
	}

	resp, err := clairClient.Do(
		RequestVulnerabilities(digest[7:] + ls[lsLen - 1].Digest[7:], serverAddr),
	)

	//fs := GetFeaturs(resp, err)
	vuls := GetVulnerabilities(resp, err)

	oneliners.PrettyJson(vuls)
	//oneliners.PrettyJson(fs)
}
