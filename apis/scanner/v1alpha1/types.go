package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Vulnerability represents vulnerability entity returned by Clair
type Vulnerability struct {
	Name          string `json:"Name,omitempty"`
	NamespaceName string `json:"NamespaceName,omitempty"`
	Description   string `json:"Description,omitempty"`
	Link          string `json:"Link,omitempty"`
	Severity      string `json:"Severity,omitempty"`
	//Metadata      map[string]interface{} `json:"Metadata,omitempty"`
	FixedBy string `json:"FixedBy,omitempty"`
	//FixedIn     []Feature `json:"FixedIn,omitempty"`
	FeatureName string `json:"featureName,omitempty"`
}

type Feature struct {
	Name          string `json:"Name,omitempty"`
	NamespaceName string `json:"NamespaceName,omitempty"`
	Version       string `json:"Version,omitempty"`
	// +optional
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
}

type ScanResult struct {
	Name string `json:"name,omitempty"`
	// +optional
	Features []Feature `json:"features,omitempty"`
}

type WorkloadReviewResponse struct {
	Images []ScanResult `json:"images,omitempty"`
}

const (
	ResourceKindWorkloadReview     = "WorkloadReview"
	ResourcePluralWorkloadReview   = "workloadreviews"
	ResourceSingularWorkloadReview = "workloadreview"
)

// +genclient
// +genclient:skipVerbs=list,create,update,patch,delete,deleteCollection,watch
// +k8s:openapi-gen=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// WorkloadReview describes a peer ping request/response.
type WorkloadReview struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +optional
	Response *WorkloadReviewResponse `json:"response,omitempty"`
}

const (
	ResourceKindImageReview     = "ImageReview"
	ResourcePluralImageReview   = "imagereviews"
	ResourceSingularImageReview = "imagereview"
)

// +genclient
// +genclient:skipVerbs=list,update,patch,delete,deleteCollection,watch
// +genclient:nonNamespaced
// +k8s:openapi-gen=true
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// ImageReview describes a peer ping request/response.
type ImageReview struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	// +optional
	Request *ImageReviewRequest `json:"request,omitempty"`
	// +optional
	Response *ImageReviewResponse `json:"response,omitempty"`
}

type ImageReviewRequest struct {
	// Docker image name.
	// More info: https://kubernetes.io/docs/concepts/containers/images
	// This field is optional to allow higher level config management to default or override
	// container images in workload controllers like Deployments and StatefulSets.
	// +optional
	Image string `json:"image,omitempty"`

	Namespace string `json:"namespace,omitempty"`

	// ImagePullSecrets is an optional list of references to secrets in the same namespace to use for pulling any of the images used by this PodSpec.
	// If specified, these secrets will be passed to individual puller implementations for them to use. For example,
	// in the case of docker, only DockerConfig type secrets are honored.
	// More info: https://kubernetes.io/docs/concepts/containers/images#specifying-imagepullsecrets-on-a-pod
	// +optional
	// +patchMergeKey=name
	// +patchStrategy=merge
	ImagePullSecrets []string `json:"imagePullSecrets,omitempty" patchStrategy:"merge" patchMergeKey:"name"`
}

type ImageReviewResponse struct {
	// +optional
	Features []Feature `json:"features,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
type ImageReviewOptions struct {
	metav1.TypeMeta `json:",inline"`

	// Docker image name.
	// More info: https://kubernetes.io/docs/concepts/containers/images
	// This field is optional to allow higher level config management to default or override
	// container images in workload controllers like Deployments and StatefulSets.
	// +optional
	Image string `json:"image,omitempty"`

	Namespace string `json:"namespace,omitempty"`

	// ImagePullSecrets is an optional list of references to secrets in the same namespace to use for pulling any of the images used by this PodSpec.
	// If specified, these secrets will be passed to individual puller implementations for them to use. For example,
	// in the case of docker, only DockerConfig type secrets are honored.
	// More info: https://kubernetes.io/docs/concepts/containers/images#specifying-imagepullsecrets-on-a-pod
	// +optional
	// +patchMergeKey=name
	// +patchStrategy=merge
	ImagePullSecrets []string `json:"imagePullSecrets,omitempty" patchStrategy:"merge" patchMergeKey:"name"`
}
