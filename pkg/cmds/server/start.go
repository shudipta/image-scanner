package server

import (
	"fmt"
	"io"
	"net"

	"github.com/soter/scanner/apis/scanner/v1alpha1"
	"github.com/soter/scanner/pkg/controller"
	"github.com/soter/scanner/pkg/server"
	"github.com/spf13/pflag"
	admissionv1beta1 "k8s.io/api/admission/v1beta1"
	genericapiserver "k8s.io/apiserver/pkg/server"
	genericoptions "k8s.io/apiserver/pkg/server/options"
)

const defaultEtcdPathPrefix = "/registry/soter.ac"

type ScannerOptions struct {
	RecommendedOptions *genericoptions.RecommendedOptions
	ExtraOptions       *ExtraOptions

	StdOut io.Writer
	StdErr io.Writer
}

func NewScannerOptions(out, errOut io.Writer) *ScannerOptions {
	o := &ScannerOptions{
		// TODO we will nil out the etcd storage options.  This requires a later level of k8s.io/apiserver
		RecommendedOptions: genericoptions.NewRecommendedOptions(defaultEtcdPathPrefix, server.Codecs.LegacyCodec(admissionv1beta1.SchemeGroupVersion)),
		ExtraOptions:       NewExtraOptions(),
		StdOut:             out,
		StdErr:             errOut,
	}
	o.RecommendedOptions.Etcd = nil
	o.RecommendedOptions.Admission = nil

	return o
}

func (o ScannerOptions) AddFlags(fs *pflag.FlagSet) {
	o.RecommendedOptions.AddFlags(fs)
	o.ExtraOptions.AddFlags(fs)
}

func (o ScannerOptions) Validate(args []string) error {
	return nil
}

func (o *ScannerOptions) Complete() error {
	return nil
}

func (o ScannerOptions) Config() (*server.ScannerConfig, error) {
	// TODO have a "real" external address
	if err := o.RecommendedOptions.SecureServing.MaybeDefaultWithSelfSignedCerts("localhost", nil, []net.IP{net.ParseIP("127.0.0.1")}); err != nil {
		return nil, fmt.Errorf("error creating self-signed certificates: %v", err)
	}

	serverConfig := genericapiserver.NewRecommendedConfig(server.Codecs)
	if err := o.RecommendedOptions.ApplyTo(serverConfig, server.Scheme); err != nil {
		return nil, err
	}
	serverConfig.EnableMetrics = true
	serverConfig.OpenAPIConfig = genericapiserver.DefaultOpenAPIConfig(v1alpha1.GetOpenAPIDefinitions, server.Scheme)
	serverConfig.OpenAPIConfig.Info.Title = "soter-clair"
	serverConfig.OpenAPIConfig.Info.Version = v1alpha1.SchemeGroupVersion.Version
	serverConfig.OpenAPIConfig.IgnorePrefixes = []string{
		"/swaggerapi",
		// webhooks
		"/apis/admission.scanner.soter.ac/v1alpha1/deployments",
		"/apis/admission.scanner.soter.ac/v1alpha1/daemonsets",
		"/apis/admission.scanner.soter.ac/v1alpha1/statefulsets",
		"/apis/admission.scanner.soter.ac/v1alpha1/replicationcontrollers",
		"/apis/admission.scanner.soter.ac/v1alpha1/replicasets",
		"/apis/admission.scanner.soter.ac/v1alpha1/jobs",
		"/apis/admission.scanner.soter.ac/v1alpha1/cronjobs",
		"/apis/admission.scanner.soter.ac/v1alpha1/deploymentconfigs",
		// image review endpoints
		"/apis/scanner.soter.ac/v1alpha1/pods",
		"/apis/scanner.soter.ac/v1alpha1/deployments",
		"/apis/scanner.soter.ac/v1alpha1/daemonsets",
		"/apis/scanner.soter.ac/v1alpha1/statefulsets",
		"/apis/scanner.soter.ac/v1alpha1/replicationcontrollers",
		"/apis/scanner.soter.ac/v1alpha1/replicasets",
		"/apis/scanner.soter.ac/v1alpha1/jobs",
		"/apis/scanner.soter.ac/v1alpha1/cronjobs",
		"/apis/scanner.soter.ac/v1alpha1/deploymentconfigs",
		"/apis/scanner.soter.ac/v1alpha1/imagereviews",
	}

	controllerConfig := controller.NewConfig(serverConfig.ClientConfig)
	if err := o.ExtraOptions.ApplyTo(controllerConfig); err != nil {
		return nil, err
	}

	config := &server.ScannerConfig{
		GenericConfig: serverConfig,
		ScannerConfig: controllerConfig,
	}
	return config, nil
}

func (o ScannerOptions) Run(stopCh <-chan struct{}) error {
	config, err := o.Config()
	if err != nil {
		return err
	}

	s, err := config.Complete().New()
	if err != nil {
		return err
	}

	return s.Run(stopCh)
}
