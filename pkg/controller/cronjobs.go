package controller

import (
	hooks "github.com/appscode/kubernetes-webhook-util/admission/v1beta1"
	"github.com/appscode/kubernetes-webhook-util/admission/v1beta1/workload"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func (c *Controller) NewCronJobWebhook() hooks.AdmissionHook {
	return workload.NewWorkloadWebhook(
		schema.GroupVersionResource{
			Group:    "admission.scanner.soter.ac",
			Version:  "v1alpha1",
			Resource: "cronjobs",
		},
		"cronjob",
		"CronJob",
		nil,
		c,
	)
}
