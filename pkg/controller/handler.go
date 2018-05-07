package controller

import (
	"github.com/appscode/kubernetes-webhook-util/admission"
	workload "github.com/appscode/kubernetes-webhook-util/apis/workload/v1"
	wpi "github.com/appscode/kubernetes-webhook-util/apis/workload/v1"
	"github.com/pkg/errors"
	api "github.com/soter/scanner/apis/scanner/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/reference"
	"k8s.io/kubernetes/pkg/apis/core"
)

var _ admission.ResourceHandler = &Controller{}

func (c *Controller) OnCreate(obj runtime.Object) (runtime.Object, error) {
	w := obj.(*workload.Workload)
	w.Object = nil
	return c.checkWorkload(w)
}

func (c *Controller) OnUpdate(oldObj, newObj runtime.Object) (runtime.Object, error) {
	w := newObj.(*workload.Workload)
	w.Object = nil
	return c.checkWorkload(w)
}

func (c *Controller) OnDelete(obj runtime.Object) error {
	return nil
}

func (c *Controller) checkWorkload(w *wpi.Workload) (runtime.Object, error) {
	if result, err := c.scanner.ScanWorkloadObject(w); err != nil {
		return nil, err
	} else {
		resp := api.WorkloadReviewResponse{Images: result}
		if resp.HasVulnerabilities(c.Severity) {
			ref, err := reference.GetReference(scheme.Scheme, w.Object)
			if err == nil {
				c.recorder.Event(ref, core.EventTypeWarning, "VulnerabilityFound", "image has vulnerability")
			}
			return nil, errors.New("image has vulnerability")
		}
	}

	return nil, nil
}
