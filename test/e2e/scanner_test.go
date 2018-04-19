package e2e_test

import (
	"os"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/soter/scanner/test/framework"
	apps "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	batchv1beta1 "k8s.io/api/batch/v1beta1"
	core "k8s.io/api/core/v1"
	extensions "k8s.io/api/extensions/v1beta1"
	"k8s.io/apimachinery/pkg/runtime"
	"fmt"
)

var _ = Describe("Image Scanner", func() {
	var (
		f *framework.Invocation

		labels          map[string]string
		name, namespace string
		containers1     []core.Container
		containers2     []core.Container
		containers3     []core.Container
		data1, data2    string
		skip1, skip2    bool

		secret1, secret2 *core.Secret
		service, svc     *core.Service
		err              error

		obj              runtime.Object
		str1, str2, str3 string

		ctx1 = func(workloadType runtime.Object) {
			Context("When some images are vulnerable", func() {
				BeforeEach(func() {
					By("Creating secret-1")
					_, err := root.KubeClient.CoreV1().Secrets(secret1.Namespace).Create(secret1)
					Expect(err).NotTo(HaveOccurred())

					obj = f.NewWorkload(name, namespace, labels, containers1, secret1.Name, workloadType)
				})

				It("Shouldn't be created", func() {
					if skip1 {
						Skip("environment var \"DOCKER_CFG_1\" not found")
					}

					By("Should contain vulnerabilities")
					f.EventuallyCreateWithVulnerableImage(root, obj).Should(Equal(true))
				})
			})
		}

		ctx2 = func(workloadType runtime.Object, update bool) {
			str1 = "When no image is vulnerable"
			if update {
				str1 = "When some images are vulnerable"
			}
			Context(str1, func() {
				BeforeEach(func() {
					if update {
						By("Creating secret-1")
						_, err := root.KubeClient.CoreV1().Secrets(secret1.Namespace).Create(secret1)
						Expect(err).NotTo(HaveOccurred())
					}

					By("Creating secret-2")
					_, err := root.KubeClient.CoreV1().Secrets(secret2.Namespace).Create(secret2)
					Expect(err).NotTo(HaveOccurred())

					obj = f.NewWorkload(name, namespace, labels, containers2, secret2.Name, workloadType)
				})

				AfterEach(func() {
					f.DeleteWorkloads(workloadType)
				})

				str2 = "Should be created"
				if update {
					str2 = "Shouldn't be updated"
				}
				It(str2, func() {
					if skip2 {
						Skip("environment var \"DOCKER_CFG_2\" not found")
					}

					str3 = "No vulnerabilities"
					if update {
						str3 = "Creating"
					}
					By(str3)
					f.EventuallyCreateWithNonVulnerableImage(root, obj).ShouldNot(HaveOccurred())

					if update {
						By("Updating")
						obj = f.NewWorkload(name, namespace, labels, containers1, secret1.Name, workloadType)
						f.EventuallyUpdateWithVulnerableImage(root, obj).Should(Equal(true))
					}
				})
			})
		}
	)

	BeforeEach(func() {
		f = root.Invoke()
		name = f.App()
		namespace = f.Namespace()
		labels = map[string]string{
			"app": f.App(),
		}

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
			fmt.Println()
			secret2 = f.NewSecret(name+"-secret-2", namespace, data2, labels)
		}

		containers1 = []core.Container{
			{
				Name:  "label-practice",
				Image: "shudipta/labels",
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
				Image: "alittleprogramming/hello:test",
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
				Image: "nginx",
				Ports: []core.ContainerPort{
					{
						ContainerPort: 80,
					},
				},
			},
		}
	})

	Describe("Scan images in Deployment", func() {
		AfterEach(func() {
			f.DeleteAllSecrets()
		})

		Context("Creating Deployment with some vulnerable images", func() {
			ctx1(&apps.Deployment{})
		})

		FContext("Creating Deployment with non-vulnerable images", func() {
			ctx2(&apps.Deployment{}, false)
		})

		Context("Updating Deployment", func() {
			ctx2(&apps.Deployment{}, true)
		})
	})

	Describe("Scan images in ReplicationController", func() {
		AfterEach(func() {
			f.DeleteAllSecrets()
		})

		Context("Creating ReplicationController with some vulnerable images", func() {
			ctx1(&core.ReplicationController{})
		})

		Context("Creating ReplicationController with non-vulnerable images", func() {
			ctx2(&core.ReplicationController{}, false)
		})

		Context("Updating ReplicationController", func() {
			ctx2(&core.ReplicationController{}, true)
		})
	})

	Describe("Scan images in ReplicaSet", func() {
		AfterEach(func() {
			f.DeleteAllSecrets()
		})

		Context("Creating ReplicaSet with some vulnerable images", func() {
			ctx1(&extensions.ReplicaSet{})
		})

		Context("Creating ReplicaSet with non-vulnerable images", func() {
			ctx2(&extensions.ReplicaSet{}, false)
		})

		Context("Updating ReplicaSet", func() {
			ctx2(&extensions.ReplicaSet{}, true)
		})
	})

	Describe("Scan images in DaemonSet", func() {
		AfterEach(func() {
			f.DeleteAllSecrets()
		})

		Context("Creating DaemonSet with some vulnerable images", func() {
			ctx1(&extensions.DaemonSet{})
		})

		Context("Creating DaemonSet with non-vulnerable images", func() {
			ctx2(&extensions.DaemonSet{}, false)
		})

		Context("Updating DaemonSet", func() {
			ctx2(&extensions.DaemonSet{}, true)
		})
	})

	Describe("Scan images in Job", func() {
		AfterEach(func() {
			f.DeleteAllSecrets()
		})

		Context("Creating Job with some vulnerable images", func() {
			ctx1(&batchv1.Job{})
		})

		Context("Creating Job with some vulnerable images", func() {
			ctx2(&batchv1.Job{}, false)
		})

		//Context("Updating Job", func() {
		//	ctx2(&batchv1.Job{}, true)
		//})
	})

	Describe("Scan images in CronJob", func() {
		AfterEach(func() {
			f.DeleteAllSecrets()
		})

		Context("Creating CronJob with some vulnerable images", func() {
			ctx1(&batchv1beta1.CronJob{})
		})

		Context("Creating CronJob with some vulnerable images", func() {
			ctx2(&batchv1beta1.CronJob{}, false)
		})
	})

	Describe("Scan images in StatefulSet", func() {
		BeforeEach(func() {
			By("Creating service")
			service = f.NewService(name, namespace, labels)
			svc, err = root.KubeClient.CoreV1().Services(service.Namespace).Create(service)
			Expect(err).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			f.DeleteAllSecrets()
			f.DeleteAllServices()
		})

		Context("Creating StatefulSet with some vulnerable images", func() {
			ctx1(&apps.StatefulSet{})
		})

		Context("Creating StatefulSet with some vulnerable images", func() {
			ctx2(&apps.StatefulSet{}, false)
		})

		Context("Updating StatefulSet", func() {
			ctx2(&apps.StatefulSet{}, true)
		})
	})
})
