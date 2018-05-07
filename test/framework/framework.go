package framework

import (
	"github.com/appscode/go/crypto/rand"
	clientset "github.com/soter/scanner/client/clientset/versioned"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	ka "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"
)

type Framework struct {
	KubeClient     kubernetes.Interface
	ScannerClient  clientset.Interface
	KAClient       ka.Interface
	namespace      string
	WebhookEnabled bool

	ClientConfig *rest.Config
}

func New(kubeClient kubernetes.Interface, scannerClient clientset.Interface, kaClient ka.Interface, webhookEnabled bool, clientConfig *rest.Config) *Framework {
	return &Framework{
		KubeClient:     kubeClient,
		ScannerClient:  scannerClient,
		KAClient:       kaClient,
		namespace:      rand.WithUniqSuffix("scanner-e2e"),
		WebhookEnabled: webhookEnabled,
		ClientConfig:   clientConfig,
	}
}

func (f *Framework) Invoke() *Invocation {
	return &Invocation{
		Framework: f,
		app:       rand.WithUniqSuffix("test-scanner"),
	}
}

type Invocation struct {
	*Framework
	app string
}

func (f *Invocation) App() string {
	return f.app
}
