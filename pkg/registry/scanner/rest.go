package scanner

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/registry/rest"
)

type Storage interface {
	rest.Storage
	rest.GroupVersionKindProvider
	Resource() (plural schema.GroupVersionResource, singular string)
}
