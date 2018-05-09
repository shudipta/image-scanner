package workloadreview

import (
	api "github.com/soter/scanner/apis/scanner/v1alpha1"
	"github.com/soter/scanner/pkg/clair"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	apirequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/registry/rest"
)

type REST struct {
	scanner  *clair.Scanner
	plural   schema.GroupVersionResource
	singular string
}

var _ rest.Getter = &REST{}
var _ rest.GroupVersionKindProvider = &REST{}

func NewREST(scanner *clair.Scanner, plural schema.GroupVersionResource, singular string) *REST {
	return &REST{
		scanner:  scanner,
		plural:   plural,
		singular: singular,
	}
}

func (r *REST) GroupVersionKind(containingGV schema.GroupVersion) schema.GroupVersionKind {
	return api.SchemeGroupVersion.WithKind("WorkloadReview")
}

func (r *REST) Resource() (schema.GroupVersionResource, string) {
	return r.plural, r.singular
}

func (r *REST) New() runtime.Object {
	return &api.WorkloadReview{}
}

func (r *REST) Get(ctx apirequest.Context, name string, options *metav1.GetOptions) (runtime.Object, error) {
	namespace := apirequest.NamespaceValue(ctx)

	result, err := r.scanner.ScanWorkload(r.singular, name, namespace)
	if err != nil {
		return nil, err
	}
	return &api.WorkloadReview{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: apirequest.NamespaceValue(ctx),
		},
		Response: &api.WorkloadReviewResponse{
			Images: result,
		},
	}, nil
}
