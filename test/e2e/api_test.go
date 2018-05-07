package e2e_test

import (
	"os"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	api "github.com/soter/scanner/apis/scanner/v1alpha1"
	"github.com/soter/scanner/test/framework"
	appsv1 "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

var _ = Describe("Api test", func() {
	var (
		f *framework.Invocation

		deploymentObj, deployment             *appsv1.Deployment
		containers1, containers2, containers3 []core.Container

		irObj, ir *api.ImageReview
		wr        *api.WorkloadReview
		obj       runtime.Object

		labels                        map[string]string
		name, generateName, namespace string
		secret1, secret2              *core.Secret
		//service, svc     *core.Service
		err error

		image1, image2, image3 string
		data1, data2           string
		skip1, skip2           bool
		//str1, str2, str3 string

	)

	BeforeEach(func() {
		f = root.Invoke()

		name = f.App()
		generateName = "nginx"
		namespace = f.Namespace()
		labels = map[string]string{
			"app": f.App(),
		}

		image1 = "tigerworks/labels"
		image2 = "alittleprogramming/hello:test"
		image3 = "nginx"

		data1 = ""
		skip1 = false
		if val, ok := os.LookupEnv("DOCKER_CFG_1"); !ok {
			skip1 = true
		} else {
			data1 = val
			secret1 = f.NewSecret(name+"-secret-1", namespace, data1, labels)
		}

		data2 = ""
		skip2 = false
		if val, ok := os.LookupEnv("DOCKER_CFG_2"); !ok {
			skip2 = true
		} else {
			data2 = val
			secret2 = f.NewSecret(name+"-secret-2", namespace, data2, labels)
		}

		containers1 = []core.Container{
			{
				Name:  "labels",
				Image: image1,
				Ports: []core.ContainerPort{
					{
						ContainerPort: 10000,
					},
				},
			},
		}
		containers2 = []core.Container{
			{
				Name:  "hello",
				Image: image2,
				Ports: []core.ContainerPort{
					{
						ContainerPort: 80,
					},
				},
			},
		}

		containers3 = []core.Container{
			{
				Name:  "nginx",
				Image: image3,
				Ports: []core.ContainerPort{
					{
						ContainerPort: 80,
					},
				},
			},
		}
	})

	Describe("Api for Deployment", func() {
		BeforeEach(func() {
			By("Creating secret-1")
			_, err := root.KubeClient.CoreV1().Secrets(secret1.Namespace).Create(secret1)
			Expect(err).NotTo(HaveOccurred())

			By("Creating Deployment")
			deploymentObj = framework.NewDeploymentUsingGenerateName(generateName, namespace, labels, containers1, secret1.Name)
			deployment, err = root.KubeClient.AppsV1().Deployments(namespace).Create(deploymentObj)
			Expect(err).NotTo(HaveOccurred())

			By("Creating ImageReviews")
			irObj = framework.NewImageReview("labels", "tigerworks/labels", secret1.Name, labels)
			ir, err = root.ScannerClient.ScannerV1alpha1().ImageReviews(namespace).Create(ir)
			Expect(err).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			f.DeleteAllSecrets()
			f.DeleteWorkloads(&appsv1.Deployment{})
		})

		Context("Getting Deployment", func() {
			//ctx1(&appsv1.Deployment{})
			It("Should contain vulnerabilities", func() {
				if skip1 {
					Skip("environment var \"DOCKER_CFG_1\" not found")
				}

				By("Should contain vulnerabilities")
				//wr, err = root.ScannerClient.ScannerV1alpha1().WorkloadReviews(namespace).Get(deployment.Name, metav1.GetOptions{})
				obj, err = root.KubeClient.AppsV1().Deployments(namespace).Get(deployment.Name, metav1.GetOptions{})
				Expect(err).NotTo(HaveOccurred())
				wr = obj.(*api.WorkloadReview)
				Expect(wr.Response.Images).NotTo(Equal(nil))
				//f.EventuallyCreateWithVulnerableImage(root, obj).Should(Equal(true))
			})
		})
	})
})
