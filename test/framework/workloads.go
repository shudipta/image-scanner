package framework

import (
	"strings"
	"time"

	workload "github.com/appscode/kubernetes-webhook-util/client/workload/v1"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	batchv1beta1 "k8s.io/api/batch/v1beta1"
	core "k8s.io/api/core/v1"
	extensions "k8s.io/api/extensions/v1beta1"
	kerr "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func int32Ptr(i int32) *int32 { return &i }

func newObjectMeta(name, namespace string, labels map[string]string) metav1.ObjectMeta {
	return metav1.ObjectMeta{
		Name:      name,
		Namespace: namespace,
		Labels:    labels,
	}
}

func newSelector(labels map[string]string) *metav1.LabelSelector {
	return &metav1.LabelSelector{MatchLabels: labels}
}

func newPodTemplateSpec(
	secret string, labels map[string]string,
	containers []core.Container) core.PodTemplateSpec {
	var podSpec core.PodSpec
	if secret == "" {
		podSpec = core.PodSpec{Containers: containers}
	} else {
		podSpec = core.PodSpec{
			Containers: containers,
			ImagePullSecrets: []core.LocalObjectReference{
				{
					Name: secret,
				},
			},
		}
	}

	return core.PodTemplateSpec{
		ObjectMeta: newObjectMeta("", "", labels),
		Spec:       podSpec,
	}
}

func newDeployment(
	name, namespace string,
	labels map[string]string,
	containers []core.Container, secret string) *appsv1.Deployment {

	return &appsv1.Deployment{
		ObjectMeta: newObjectMeta(name, namespace, labels),
		Spec: appsv1.DeploymentSpec{
			Replicas: int32Ptr(1),
			Selector: newSelector(labels),
			Template: newPodTemplateSpec(secret, labels, containers),
		},
	}
}

func NewDeploymentUsingGenerateName(
	name, namespace string,
	labels map[string]string,
	containers []core.Container, secret string) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: name,
			Namespace:    namespace,
			Labels:       labels,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: int32Ptr(1),
			Selector: newSelector(labels),
			Template: newPodTemplateSpec(secret, labels, containers),
		},
	}
}

func newReplicationController(
	name, namespace string,
	labels map[string]string,
	containers []core.Container, secret string) *core.ReplicationController {

	podTemplateSpec := newPodTemplateSpec(secret, labels, containers)
	return &core.ReplicationController{
		ObjectMeta: newObjectMeta(name, namespace, labels),
		Spec: core.ReplicationControllerSpec{
			Replicas: int32Ptr(1),
			Selector: labels,
			Template: &podTemplateSpec,
		},
	}
}

func newReplicaSet(
	name, namespace string,
	labels map[string]string,
	containers []core.Container, secret string) *extensions.ReplicaSet {

	return &extensions.ReplicaSet{
		ObjectMeta: newObjectMeta(name, namespace, labels),
		Spec: extensions.ReplicaSetSpec{
			Replicas: int32Ptr(1),
			Selector: newSelector(labels),
			Template: newPodTemplateSpec(secret, labels, containers),
		},
	}
}

func newDaemonSet(
	name, namespace string,
	labels map[string]string,
	containers []core.Container, secret string) *extensions.DaemonSet {

	return &extensions.DaemonSet{
		ObjectMeta: newObjectMeta(name, namespace, labels),
		Spec: extensions.DaemonSetSpec{
			Selector: newSelector(labels),
			Template: newPodTemplateSpec(secret, labels, containers),
		},
	}
}

func newJob(
	name, namespace string,
	labels map[string]string,
	containers []core.Container, secret string) *batchv1.Job {

	podTemplateSpec := newPodTemplateSpec(secret, labels, containers)
	podTemplateSpec.Spec.RestartPolicy = "Never"
	return &batchv1.Job{
		ObjectMeta: newObjectMeta(name, namespace, labels),
		Spec: batchv1.JobSpec{
			Template: podTemplateSpec,
		},
	}
}

func newCronJob(
	name, namespace string,
	labels map[string]string,
	containers []core.Container, secret string) *batchv1beta1.CronJob {

	podTemplateSpec := newPodTemplateSpec(secret, labels, containers)
	podTemplateSpec.Spec.RestartPolicy = "OnFailure"
	return &batchv1beta1.CronJob{
		ObjectMeta: newObjectMeta(name, namespace, labels),
		Spec: batchv1beta1.CronJobSpec{
			Schedule: "*/1 * * * *",
			JobTemplate: batchv1beta1.JobTemplateSpec{
				ObjectMeta: newObjectMeta("", "", labels),
				Spec: batchv1.JobSpec{
					Template: podTemplateSpec,
				},
			},
		},
	}
}

func newStatefulSet(
	name, namespace string,
	labels map[string]string,
	containers []core.Container, secret string) *appsv1.StatefulSet {

	return &appsv1.StatefulSet{
		ObjectMeta: newObjectMeta(name, namespace, labels),
		Spec: appsv1.StatefulSetSpec{
			ServiceName: name,
			Replicas:    int32Ptr(1),
			Selector:    newSelector(labels),
			Template:    newPodTemplateSpec(secret, labels, containers),
		},
	}
}

func (f *Invocation) NewService(
	name, namespace string,
	labels map[string]string) *core.Service {

	return &core.Service{
		ObjectMeta: newObjectMeta(name, namespace, labels),
		Spec: core.ServiceSpec{
			Ports: []core.ServicePort{
				{
					Protocol: core.ProtocolTCP,
					Port:     80,
					TargetPort: intstr.IntOrString{
						Type:   intstr.Int,
						IntVal: 80,
					},
				},
			},
			Type:     core.ServiceTypeNodePort,
			Selector: labels,
		},
	}
}

func (f *Invocation) NewSecret(name, namespace, data string, labels map[string]string) *core.Secret {
	return &core.Secret{
		ObjectMeta: newObjectMeta(name, namespace, labels),
		StringData: map[string]string{
			".dockerconfigjson": data,
		},
		Type: "kubernetes.io/dockerconfigjson",
	}
}

func (f *Invocation) NewWorkload(
	name, namespace string,
	labels map[string]string,
	containers []core.Container, secret string, workloadType runtime.Object) runtime.Object {

	switch workloadType.(type) {
	case *appsv1.Deployment:
		return newDeployment(name, namespace, labels, containers, secret)
	case *core.ReplicationController:
		return newReplicationController(name, namespace, labels, containers, secret)
	case *extensions.ReplicaSet:
		return newReplicaSet(name, namespace, labels, containers, secret)
	case *extensions.DaemonSet:
		return newDaemonSet(name, namespace, labels, containers, secret)
	case *batchv1.Job:
		return newJob(name, namespace, labels, containers, secret)
	case *batchv1beta1.CronJob:
		return newCronJob(name, namespace, labels, containers, secret)
	case *appsv1.StatefulSet:
		return newStatefulSet(name, namespace, labels, containers, secret)
	default:
		return nil
	}
}

func (f *Invocation) EventuallyCreateWithVulnerableImage(root *Framework, obj runtime.Object) GomegaAsyncAssertion {
	wc, err := workload.NewForConfig(root.ClientConfig)
	Expect(err).NotTo(HaveOccurred())
	w, err := workload.ConvertToWorkload(obj)
	Expect(err).NotTo(HaveOccurred())

	return Eventually(
		func() bool {
			_, err := wc.Workloads(w.Namespace).Create(w)
			Expect(err).To(HaveOccurred())

			return strings.Contains(err.Error(), "contains vulnerabilities")
		},
		time.Minute*5,
		time.Millisecond*5,
	)
}

func (f *Invocation) EventuallyUpdateWithVulnerableImage(root *Framework, obj runtime.Object) GomegaAsyncAssertion {
	wc, err := workload.NewForConfig(root.ClientConfig)
	Expect(err).NotTo(HaveOccurred())
	w, err := workload.ConvertToWorkload(obj)
	Expect(err).NotTo(HaveOccurred())

	return Eventually(
		func() bool {
			_, err := wc.Workloads(w.Namespace).Update(w)
			Expect(err).To(HaveOccurred())

			return strings.Contains(err.Error(), "contains vulnerabilities")
		},
		time.Minute*5,
		time.Millisecond*5,
	)
}

func (f *Invocation) EventuallyCreateWithNonVulnerableImage(root *Framework, obj runtime.Object) GomegaAsyncAssertion {
	wc, err := workload.NewForConfig(root.ClientConfig)
	Expect(err).NotTo(HaveOccurred())
	w, err := workload.ConvertToWorkload(obj)
	Expect(err).NotTo(HaveOccurred())

	return Eventually(
		func() error {
			_, err := wc.Workloads(w.Namespace).Create(w)
			return err
		},
		time.Minute*5,
		time.Millisecond*5,
	)
}

func (f *Invocation) deleteAllDeployments() {
	objects, err := f.KubeClient.AppsV1beta1().Deployments(metav1.NamespaceAll).List(metav1.ListOptions{
		LabelSelector: labels.Set{
			"app": f.App(),
		}.String(),
	})
	Expect(err).NotTo(HaveOccurred())

	for _, deploy := range objects.Items {
		err := f.KubeClient.AppsV1beta1().Deployments(deploy.Namespace).Delete(deploy.Name, &metav1.DeleteOptions{})
		if kerr.IsNotFound(err) {
			err = nil
		}
		Expect(err).NotTo(HaveOccurred())
	}
}

func (f *Invocation) deleteAllReplicationControllers() {
	objects, err := f.KubeClient.CoreV1().ReplicationControllers(metav1.NamespaceAll).List(metav1.ListOptions{
		LabelSelector: labels.Set{
			"app": f.App(),
		}.String(),
	})
	Expect(err).NotTo(HaveOccurred())

	for _, rc := range objects.Items {
		err := f.KubeClient.CoreV1().ReplicationControllers(rc.Namespace).Delete(rc.Name, &metav1.DeleteOptions{})
		if kerr.IsNotFound(err) {
			err = nil
		}
		Expect(err).NotTo(HaveOccurred())
	}
}

func (f *Invocation) deleteAllReplicaSets() {
	objects, err := f.KubeClient.ExtensionsV1beta1().ReplicaSets(metav1.NamespaceAll).List(metav1.ListOptions{
		LabelSelector: labels.Set{
			"app": f.App(),
		}.String(),
	})
	Expect(err).NotTo(HaveOccurred())

	for _, rs := range objects.Items {
		err := f.KubeClient.ExtensionsV1beta1().ReplicaSets(rs.Namespace).Delete(rs.Name, &metav1.DeleteOptions{})
		if kerr.IsNotFound(err) {
			err = nil
		}
		Expect(err).NotTo(HaveOccurred())
	}
}

func (f *Invocation) deleteAllDaemonSet() {
	objects, err := f.KubeClient.ExtensionsV1beta1().DaemonSets(metav1.NamespaceAll).List(metav1.ListOptions{
		LabelSelector: labels.Set{
			"app": f.App(),
		}.String(),
	})
	Expect(err).NotTo(HaveOccurred())

	for _, ds := range objects.Items {
		err := f.KubeClient.ExtensionsV1beta1().DaemonSets(ds.Namespace).Delete(ds.Name, &metav1.DeleteOptions{})
		if kerr.IsNotFound(err) {
			err = nil
		}
		Expect(err).NotTo(HaveOccurred())
	}
}

func (f *Invocation) deleteAllJobs() {
	objects, err := f.KubeClient.BatchV1().Jobs(metav1.NamespaceAll).List(metav1.ListOptions{
		LabelSelector: labels.Set{
			"app": f.App(),
		}.String(),
	})
	Expect(err).NotTo(HaveOccurred())

	for _, job := range objects.Items {
		err := f.KubeClient.BatchV1().Jobs(job.Namespace).Delete(job.Name, &metav1.DeleteOptions{})
		if kerr.IsNotFound(err) {
			err = nil
		}
		Expect(err).NotTo(HaveOccurred())
	}
}

func (f *Invocation) deleteAllCronJobs() {
	objects, err := f.KubeClient.BatchV1beta1().CronJobs(metav1.NamespaceAll).List(metav1.ListOptions{
		LabelSelector: labels.Set{
			"app": f.App(),
		}.String(),
	})
	Expect(err).NotTo(HaveOccurred())

	for _, cronJob := range objects.Items {
		err := f.KubeClient.BatchV1beta1().CronJobs(cronJob.Namespace).Delete(cronJob.Name, &metav1.DeleteOptions{})
		if kerr.IsNotFound(err) {
			err = nil
		}
		Expect(err).NotTo(HaveOccurred())
	}
}

func (f *Invocation) deleteAllStatefulSets() {
	objects, err := f.KubeClient.AppsV1beta1().StatefulSets(metav1.NamespaceAll).List(metav1.ListOptions{
		LabelSelector: labels.Set{
			"app": f.App(),
		}.String(),
	})
	Expect(err).NotTo(HaveOccurred())

	for _, sts := range objects.Items {
		err := f.KubeClient.AppsV1beta1().StatefulSets(sts.Namespace).Delete(sts.Name, &metav1.DeleteOptions{})
		if kerr.IsNotFound(err) {
			err = nil
		}
		Expect(err).NotTo(HaveOccurred())
	}
}

func (f *Invocation) DeleteWorkloads(workloadType runtime.Object) {
	switch workloadType.(type) {
	case *appsv1.Deployment:
		f.deleteAllDeployments()
	case *core.ReplicationController:
		f.deleteAllReplicationControllers()
	case *extensions.ReplicaSet:
		f.deleteAllReplicaSets()
	case *extensions.DaemonSet:
		f.deleteAllDaemonSet()
	case *batchv1.Job:
		f.deleteAllJobs()
	case *batchv1beta1.CronJob:
		f.deleteAllCronJobs()
	case *appsv1.StatefulSet:
		f.deleteAllStatefulSets()
	}
}

func (f *Invocation) DeleteAllServices() {
	services, err := f.KubeClient.CoreV1().Services(metav1.NamespaceAll).List(metav1.ListOptions{
		LabelSelector: labels.Set{
			"app": f.App(),
		}.String(),
	})
	Expect(err).NotTo(HaveOccurred())

	for _, svc := range services.Items {
		err := f.KubeClient.CoreV1().Services(svc.Namespace).Delete(svc.Name, &metav1.DeleteOptions{})
		if kerr.IsNotFound(err) {
			err = nil
		}
		Expect(err).NotTo(HaveOccurred())
	}
}

func (f *Invocation) DeleteAllSecrets() {
	secrets, err := f.KubeClient.CoreV1().Secrets(metav1.NamespaceAll).List(metav1.ListOptions{
		LabelSelector: labels.Set{
			"app": f.App(),
		}.String(),
	})
	Expect(err).NotTo(HaveOccurred())

	for _, value := range secrets.Items {
		err := f.KubeClient.CoreV1().Secrets(value.Namespace).Delete(value.Name, &metav1.DeleteOptions{})
		if kerr.IsNotFound(err) {
			err = nil
		}
		Expect(err).NotTo(HaveOccurred())
	}
}
