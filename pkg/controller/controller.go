package controller

import (
	"github.com/coreos/clair/api/v3/clairpb"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/record"
)

type ScannerController struct {
	Config

	KubeClient kubernetes.Interface

	ClairAncestryServiceClient     clairpb.AncestryServiceClient
	ClairNotificationServiceClient clairpb.NotificationServiceClient

	recorder record.EventRecorder
}
