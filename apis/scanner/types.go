package scanner

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type Vulnerability struct {
	Name          string
	NamespaceName string
	Description   string
	Link          string
	Severity      string
	//Metadata      map[string]interface{} `json:"Metadata,omitempty"`
	FixedBy string
	//FixedIn     []Feature `json:"FixedIn,omitempty"`
	FeatureName string
}

type Feature struct {
	Name          string
	NamespaceName string
	Version       string
	// +optional
	Vulnerabilities []Vulnerability
}

type ScanResult struct {
	Name string
	// +optional
	Features []Feature
}

type WorkloadReviewResponse struct {
	Images []ScanResult `json:"images,omitempty"`
}

// +genclient
// +genclient:skipVerbs=list,update,patch,delete,deleteCollection,watch
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// WorkloadReview describes a peer ping request/response.
type WorkloadReview struct {
	metav1.TypeMeta
	metav1.ObjectMeta
	// +optional
	Response *WorkloadReviewResponse
}

// +genclient
// +genclient:skipVerbs=list,update,patch,delete,deleteCollection,watch
// +genclient:nonNamespaced
// +k8s:openapi-gen=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ImageReview describes a peer ping request/response.
type ImageReview struct {
	metav1.TypeMeta
	metav1.ObjectMeta
	// +optional
	Request *ImageReviewRequest
	// +optional
	Response *ImageReviewResponse
}

type ImageReviewRequest struct {
	// Docker image name.
	// More info: https://kubernetes.io/docs/concepts/containers/images
	// This field is optional to allow higher level config management to default or override
	// container images in workload controllers like Deployments and StatefulSets.
	// +optional
	Image string

	Namespace string

	// ImagePullSecrets is an optional list of references to secrets in the same namespace to use for pulling any of the images used by this PodSpec.
	// If specified, these secrets will be passed to individual puller implementations for them to use. For example,
	// in the case of docker, only DockerConfig type secrets are honored.
	// More info: https://kubernetes.io/docs/concepts/containers/images#specifying-imagepullsecrets-on-a-pod
	// +optional
	// +patchMergeKey=name
	// +patchStrategy=merge
	ImagePullSecrets []string
}

type ImageReviewResponse struct {
	// +optional
	Features []Feature `json:"features,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type ImageReviewOptions struct {
	metav1.TypeMeta

	// Docker image name.
	// More info: https://kubernetes.io/docs/concepts/containers/images
	// This field is optional to allow higher level config management to default or override
	// container images in workload controllers like Deployments and StatefulSets.
	// +optional
	Image string

	Namespace string

	// ImagePullSecrets is an optional list of references to secrets in the same namespace to use for pulling any of the images used by this PodSpec.
	// If specified, these secrets will be passed to individual puller implementations for them to use. For example,
	// in the case of docker, only DockerConfig type secrets are honored.
	// More info: https://kubernetes.io/docs/concepts/containers/images#specifying-imagepullsecrets-on-a-pod
	// +optional
	// +patchMergeKey=name
	// +patchStrategy=merge
	ImagePullSecrets []string
}
