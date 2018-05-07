package framework

import (
	api "github.com/soter/scanner/apis/scanner/v1alpha1"
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func NewImageReview(name, image, secret string, labels map[string]string) *api.ImageReview {
	return &api.ImageReview{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: labels,
		},
		Request: &api.ImageReviewRequest{
			Image: image,
			ImagePullSecrets: []core.ObjectReference{
				{Name: secret},
			},
		},
	}
}
