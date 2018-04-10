package controller

import (
	hooks "github.com/appscode/kubernetes-webhook-util/admission/v1beta1"
	"github.com/appscode/kubernetes-webhook-util/admission/v1beta1/workload"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func (c *ScannerController) NewDeploymentWebhook() hooks.AdmissionHook {
	return workload.NewWorkloadWebhook(
		schema.GroupVersionResource{
			Group:    "scanner.soter.cloud",
			Version:  "v1alpha1",
			Resource: "deployments",
		},
		"deployment",
		"Deployment",
		nil,
		c,
	)
}
