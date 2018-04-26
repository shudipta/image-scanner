package controller

import (
	"time"

	hooks "github.com/appscode/kubernetes-webhook-util/admission/v1beta1"
	"github.com/soter/scanner/pkg/eventer"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"github.com/soter/scanner/pkg/clair-api"
	"fmt"
)

type Config struct {
	ScannerImageTag string
	DockerRegistry  string
	MaxNumRequeues  int
	NumThreads      int
	ResyncPeriod    time.Duration
}

type ControllerConfig struct {
	Config

	ClientConfig   *rest.Config
	KubeClient     kubernetes.Interface
	AdmissionHooks []hooks.AdmissionHook
}

func NewControllerConfig(clientConfig *rest.Config) *ControllerConfig {
	return &ControllerConfig{
		ClientConfig: clientConfig,
	}
}

func (c *ControllerConfig) New() (*ScannerController, error) {
	//clairAddress := "192.168.99.100:30060"
	clairAddress := "0.0.0.0:6060"
	//dialOption, err := clair_api.DialOptionForTLSConfig()
	//if err != nil {
	//	return nil, fmt.Errorf("failed to get dial option for tls: %v", err)
	//}

	clairAncestryServiceClient, err := clair_api.NewClairAncestryServiceClient(clairAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to connect for Ancestry Service: %v", err)
	}

	clairNotificationServiceClient, err := clair_api.NewClairNotificationServiceClient(clairAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to connect for Notification Service: %v", err)
	}

	ctrl := &ScannerController{
		Config: c.Config,

		KubeClient: c.KubeClient,

		ClairAncestryServiceClient:     clairAncestryServiceClient,
		ClairNotificationServiceClient: clairNotificationServiceClient,

		recorder: eventer.NewEventRecorder(c.KubeClient, "soter-scanner"),
	}
	return ctrl, nil
}
