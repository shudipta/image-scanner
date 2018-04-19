package framework

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	shell "github.com/codeskyblue/go-sh"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	srvr "github.com/soter/scanner/pkg/cmds/server"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	genericapiserver "k8s.io/apiserver/pkg/server"
	kapi "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1beta1"
)

func (f *Framework) NewScannerOptions(kubeConfigPath string, controllerOptions *srvr.ControllerOptions) *srvr.ScannerOptions {
	opts := srvr.NewScannerOptions(os.Stdout, os.Stderr)
	opts.RecommendedOptions.Authentication.RemoteKubeConfigFile = kubeConfigPath
	//opts.RecommendedOptions.Authentication.SkipInClusterLookup = true
	opts.RecommendedOptions.Authorization.RemoteKubeConfigFile = kubeConfigPath
	opts.RecommendedOptions.CoreAPI.CoreAPIKubeconfigPath = kubeConfigPath
	opts.RecommendedOptions.SecureServing.BindPort = 8443
	opts.RecommendedOptions.SecureServing.BindAddress = net.ParseIP("127.0.0.1")
	opts.ControllerOptions = controllerOptions
	opts.StdErr = os.Stderr
	opts.StdOut = os.Stdout

	return opts
}

func (f *Framework) StartAPIServerAndOperator(kubeConfigPath string, controllerOptions *srvr.ControllerOptions) {
	sh := shell.NewSession()
	args := []interface{}{"--namespace", f.Namespace()}
	cmd := filepath.Join("..", "..", "hack", "dev", "setup-server.sh")

	By("Creating API server and webhook stuffs")
	err := sh.Command(cmd, args...).Run()
	Expect(err).ShouldNot(HaveOccurred())

	By("Starting Server and Operator")
	stopCh := genericapiserver.SetupSignalHandler()
	opts := f.NewScannerOptions(kubeConfigPath, controllerOptions)
	err = opts.Run(stopCh)
	Expect(err).ShouldNot(HaveOccurred())
}

func (f *Framework) EventuallyAPIServerReady(name string) GomegaAsyncAssertion {
	fn := func() error {
		apisvc, err := f.KAClient.ApiregistrationV1beta1().APIServices().Get(name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		for _, cond := range apisvc.Status.Conditions {
			if cond.Type == kapi.Available && cond.Status == kapi.ConditionTrue {
				return nil
			}
		}
		return fmt.Errorf("ApiService not ready yet")
	}
	return Eventually(fn, time.Minute*5, time.Microsecond*10)
}
