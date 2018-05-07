package imagereview

import (
	api "github.com/soter/scanner/apis/scanner/v1alpha1"
	"github.com/soter/scanner/pkg/clair"
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

var _ rest.Creater = &REST{}
var _ rest.GroupVersionKindProvider = &REST{}

func NewREST(scanner *clair.Scanner, plural schema.GroupVersionResource, singular string) *REST {
	return &REST{
		scanner:  scanner,
		plural:   plural,
		singular: singular,
	}
}

func (r *REST) GroupVersionKind(containingGV schema.GroupVersion) schema.GroupVersionKind {
	return api.SchemeGroupVersion.WithKind("ImageReview")
}

func (r *REST) Resource() (schema.GroupVersionResource, string) {
	return r.plural, r.singular
}

func (r *REST) New() runtime.Object {
	return &api.ImageReview{}
}

func (r *REST) Create(ctx apirequest.Context, obj runtime.Object, _ rest.ValidateObjectFunc, _ bool) (runtime.Object, error) {
	req := obj.(*api.ImageReview)

	err := r.scanner.ScanImage(req.Request.Image, req.Request.ImagePullSecrets)
	if err != nil {
		return nil, err
	}
	return req, nil
}
