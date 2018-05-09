package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/appscode/go/log"
	"github.com/soter/scanner/apis/scanner/v1alpha1"
	cs "github.com/soter/scanner/client/clientset/versioned"
	"github.com/soter/scanner/client/clientset/versioned/scheme"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientsetscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

func main() {
	scheme.AddToScheme(clientsetscheme.Scheme)

	masterURL := ""
	kubeconfigPath := filepath.Join(homedir.HomeDir(), ".kube/config")

	config, err := clientcmd.BuildConfigFromFlags(masterURL, kubeconfigPath)
	if err != nil {
		log.Fatalf("Could not get Kubernetes config: %s", err)
	}
	client := cs.NewForConfigOrDie(config)

	{
		options := v1alpha1.ImageReviewOptions{
			//Image:            "appscode/voyager:6.0.0",
			Image:            "nginx",
			Namespace:        "",
			ImagePullSecrets: []string{},
		}
		result := &v1alpha1.ImageReview{}
		err = client.ScannerV1alpha1().RESTClient().Get().
			Resource("imagereviews"). //Namespace("").
			Name("ignores").
			VersionedParams(&options, scheme.ParameterCodec).
			Do().
			Into(result)

		out, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			log.Fatalln(err)
		}
		fmt.Println(string(out))
	}

	// for pod
	{
		options := metav1.GetOptions{}
		result := &v1alpha1.WorkloadReview{}
		err = client.ScannerV1alpha1().RESTClient().Get().
			Resource("pods").Namespace("kube-system").
			Name("kube-dns-86f4d74b45-vsm6r").
			VersionedParams(&options, scheme.ParameterCodec).
			Do().
			Into(result)

		out, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			log.Fatalln(err)
		}
		fmt.Println(string(out))
	}
}
