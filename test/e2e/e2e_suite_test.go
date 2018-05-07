package e2e_test

import (
	"testing"
	"time"

	logs "github.com/appscode/go/log/golog"
	"github.com/appscode/kutil/meta"
	"github.com/appscode/kutil/tools/clientcmd"
	. "github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/reporters"
	. "github.com/onsi/gomega"
	clientset "github.com/soter/scanner/client/clientset/versioned"
	"github.com/soter/scanner/test/framework"
	"k8s.io/client-go/kubernetes"
	ka "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"
)

const (
	TIMEOUT = 20 * time.Minute
)

var (
	root *framework.Framework
)

func TestE2e(t *testing.T) {
	logs.InitLogs()
	RegisterFailHandler(Fail)
	SetDefaultEventuallyTimeout(TIMEOUT)
	junitReporter := reporters.NewJUnitReporter("junit.xml")
	RunSpecsWithDefaultAndCustomReporters(t, "e2e Suite", []Reporter{junitReporter})
}

var _ = BeforeSuite(func() {
	clientConfig, err := clientcmd.BuildConfigFromContext(options.KubeConfig, options.KubeContext)
	Expect(err).NotTo(HaveOccurred())

	kubeClient, err := kubernetes.NewForConfig(clientConfig)
	Expect(err).NotTo(HaveOccurred())

	scannerClient, err := clientset.NewForConfig(clientConfig)
	Expect(err).NotTo(HaveOccurred())

	kaClient, err := ka.NewForConfig(clientConfig)
	Expect(err).NotTo(HaveOccurred())

	root = framework.New(kubeClient, scannerClient, kaClient, options.StartAPIServer, clientConfig)
	err = root.CreateNamespace()
	Expect(err).NotTo(HaveOccurred())
	By("Using test namespace " + root.Namespace())

	go root.StartAPIServerAndOperator(options.KubeConfig, options.ExtraOptions)
	root.EventuallyAPIServerReady("v1alpha1.admission.scanner.soter.ac").Should(Succeed())
	// let's API server be warmed up
	time.Sleep(time.Second * 5)
})

var _ = AfterSuite(func() {
	if options.StartAPIServer {
		By("Cleaning API server and Webhook stuff")
		root.KubeClient.AdmissionregistrationV1beta1().ValidatingWebhookConfigurations().Delete("admission.scanner.soter.ac", meta.DeleteInBackground())
		root.KubeClient.CoreV1().Endpoints(root.Namespace()).Delete("scanner-local-apiserver", meta.DeleteInBackground())
		root.KubeClient.CoreV1().Services(root.Namespace()).Delete("scanner-local-apiserver", meta.DeleteInBackground())
		root.KAClient.ApiregistrationV1beta1().APIServices().Delete("v1alpha1.admission.scanner.soter.ac", meta.DeleteInBackground())
	}
	root.DeleteNamespace()
})
