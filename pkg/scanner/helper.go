package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"github.com/coreos/clair/api/v3/clairpb"
	api "github.com/soter/scanner/apis/scanner/v1alpha1"
	"google.golang.org/grpc"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/kubernetes/pkg/util/parsers"
	"time"
)

func requestBearerToken(repo, userName, password string) (*http.Request, error) {
	url := "https://auth.docker.io/token?service=registry.docker.io&scope=repository:" + repo + ":pull&account=" + userName
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	if userName != "" {
		req.SetBasicAuth(userName, password)
	}

	return req, nil
}

func getBearerToken(resp *http.Response, err error) (string, error) {
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	var token struct {
		Token string
	}

	if err = json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return "", err
	}
	return fmt.Sprintf("Bearer %s", token.Token), nil
}

func getAddress(kubeClient kubernetes.Interface) (string, error) {
	var host, port string
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
		return host + ":" + port, nil
	}

	return "", fmt.Errorf("clair isn't running")
}

func getVulnerabilities(res *clairpb.GetAncestryResponse) []api.Vulnerability {
	//return nil
	var vuls []api.Vulnerability
	for _, feature := range res.Ancestry.Features {
		for _, vul := range feature.Vulnerabilities {
			vuls = append(vuls, api.Vulnerability{
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

func getFeaturs(res *clairpb.GetAncestryResponse) []api.Feature {
	var fs []api.Feature
	for _, feature := range res.Ancestry.Features {
		fs = append(fs, api.Feature{
			Name:          feature.Name,
			NamespaceName: feature.NamespaceName,
			Version:       feature.Version,
		})
	}

	return fs
}

func parseImageName(imageName, registryUrl string) (string, string, string, string, error) {

	fmt.Println("=========== initial url =", registryUrl)
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

func clairClientSetup(clairAddress string) (clairpb.AncestryServiceClient, error) {
	conn, err := grpc.Dial(clairAddress, grpc.WithInsecure())
	if err != nil {
		return nil, err
	}

	c := clairpb.NewAncestryServiceClient(conn)
	return c, nil
}

func sendLayer(postAncestryRequest *clairpb.PostAncestryRequest, clairClient clairpb.AncestryServiceClient) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	_, err := clairClient.PostAncestry(ctx, postAncestryRequest)
	//_, err := clairClient.PostAncestry(context.Background(), postAncestryRequest)

	return err
}

func getLayer(
	repo string, clairClient clairpb.AncestryServiceClient) ([]api.Feature, []api.Vulnerability, error) {
	req := &clairpb.GetAncestryRequest{
		AncestryName:        repo,
		WithFeatures:        true,
		WithVulnerabilities: true,
	}
	//ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	//defer cancel()
	//resp, err := clairClient.GetAncestry(ctx, req)
	resp, err := clairClient.GetAncestry(context.Background(), req)
	if err != nil {
		return []api.Feature{}, []api.Vulnerability{}, err
	}

	return getFeaturs(resp), getVulnerabilities(resp), nil
}
