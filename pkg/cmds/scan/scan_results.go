package scan

import (
	"encoding/json"

	"github.com/soter/scanner/apis/scanner/v1alpha1"
	cs "github.com/soter/scanner/client/clientset/versioned"
	"github.com/soter/scanner/client/clientset/versioned/scheme"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientsetscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
)

func ScanResult(client *cs.Clientset, resource, name, namespace string, secrets ...string) (string, error) {
	scheme.AddToScheme(clientsetscheme.Scheme)

	var (
		out []byte
		err error
	)
	switch resource {
	case "image":
		options := v1alpha1.ImageReviewOptions{
			//Image:            "appscode/voyager:6.0.0",
			Image:            name,
			Namespace:        namespace,
			ImagePullSecrets: secrets,
		}
		result := &v1alpha1.ImageReview{}
		err = client.ScannerV1alpha1().RESTClient().Get().
			Resource("imagereviews").
			Name("ignores").
			VersionedParams(&options, scheme.ParameterCodec).
			Do().
			Into(result)
		if err != nil {
			return "", err
		}
		out, err = json.MarshalIndent(result, "", "  ")
	default:
		options := metav1.GetOptions{}
		result := &v1alpha1.WorkloadReview{}
		err = client.ScannerV1alpha1().RESTClient().Get().
			Resource(resource).Namespace(namespace).
			Name(name).
			VersionedParams(&options, scheme.ParameterCodec).
			Do().
			Into(result)
		if err != nil {
			return "", err
		}
		out, err = json.MarshalIndent(result, "", "  ")
	}

	if err != nil {
		return "", err
	}
	return string(out), nil
}
