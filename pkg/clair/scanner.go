package clair

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/appscode/agecache"
	utilerrors "github.com/appscode/go/util/errors"
	wpi "github.com/appscode/kubernetes-webhook-util/apis/workload/v1"
	wcs "github.com/appscode/kubernetes-webhook-util/client/workload/v1"
	"github.com/appscode/kutil/tools/docker"
	"github.com/coreos/clair/api/v3/clairpb"
	manifestV1 "github.com/docker/distribution/manifest/schema1"
	manifestV2 "github.com/docker/distribution/manifest/schema2"
	dockertypes "github.com/docker/docker/api/types"
	"github.com/pkg/errors"
	api "github.com/soter/scanner/apis/scanner/v1alpha1"
	"github.com/soter/scanner/pkg/types"
	"google.golang.org/grpc"
	core "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"k8s.io/client-go/tools/reference"
	"k8s.io/kubernetes/pkg/credentialprovider"
)

type Scanner struct {
	kc       kubernetes.Interface
	wc       wcs.Interface
	recorder record.EventRecorder

	AncestryClient     clairpb.AncestryServiceClient
	NotificationClient clairpb.NotificationServiceClient
	severity           types.Severity
	failurePolicy      types.FailurePolicy
	cache              *agecache.Cache
}

func NewClient(addr string, certDir string) (clairpb.AncestryServiceClient, clairpb.NotificationServiceClient, error) {
	dialOption, err := DialOptionForTLSConfig(certDir)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to get dial option for tls")
	}
	conn, err := grpc.Dial(addr, dialOption)
	if err != nil {
		return nil, nil, err
	}
	return clairpb.NewAncestryServiceClient(conn),
		clairpb.NewNotificationServiceClient(conn),
		nil
}

func NewScanner(config *rest.Config, addr string, certDir string, severity types.Severity, failurePolicy types.FailurePolicy) (*Scanner, error) {
	kc, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	wc, err := wcs.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	cache := agecache.New(agecache.Config{
		Capacity: 64,
		MaxAge:   5 * time.Minute,
		MinAge:   10 * time.Minute,
		OnMiss: func(key interface{}) (interface{}, error) {
			namespace, name, err := cache.SplitMetaNamespaceKey(key.(string))
			if err != nil {
				return nil, err
			}
			return kc.CoreV1().Secrets(namespace).Get(name, metav1.GetOptions{})
		},
	})

	var opts []grpc.DialOption
	if certDir == "" {
		opts = append(opts, grpc.WithInsecure())
	} else {
		tlsOption, err := DialOptionForTLSConfig(certDir)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get dial option for tls")
		}
		opts = append(opts, tlsOption)
	}
	conn, err := grpc.Dial(addr, opts...)
	if err != nil {
		return nil, err
	}
	ctrl := &Scanner{
		kc:                 kc,
		wc:                 wc,
		AncestryClient:     clairpb.NewAncestryServiceClient(conn),
		NotificationClient: clairpb.NewNotificationServiceClient(conn),
		severity:           severity,
		failurePolicy:      failurePolicy,
		cache:              cache,
	}
	return ctrl, nil
}

func (c *Scanner) ScanCluster() error {
	var errs []error

	objects, err := c.wc.Workloads(metav1.NamespaceAll).List(metav1.ListOptions{})
	if err != nil {
		errs = append(errs, err)
	} else {
		for i := range objects.Items {
			w := objects.Items[i]
			if result, err := c.ScanWorkloadObject(&w); err != nil {
				return err
			} else {
				resp := api.WorkloadReviewResponse{Images: result}
				if resp.HasVulnerabilities(c.severity) {
					ref, err := reference.GetReference(scheme.Scheme, w.Object)
					if err == nil {
						c.recorder.Event(ref, core.EventTypeWarning, "VulnerabilityFound", "image has vulnerability")
					}
					errs = append(errs, errors.New("image has vulnerability"))
				}
			}
		}
	}

	return utilerrors.NewAggregate(errs)
}

func (c *Scanner) ScanWorkload(kindOrResource, name, namespace string) ([]api.ScanResult, error) {
	obj, err := wcs.NewObject(kindOrResource, name, namespace)
	if err != nil {
		return nil, err
	}
	w, err := c.wc.Workloads(namespace).Get(obj, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return c.ScanWorkloadObject(w)
}

func (c *Scanner) ScanWorkloadObject(w *wpi.Workload) ([]api.ScanResult, error) {
	var pullSecrets []core.Secret
	for _, ref := range w.Spec.Template.Spec.ImagePullSecrets {
		s, err := c.cache.Get(w.Namespace + "/" + ref.Name)
		if err != nil {
			return nil, err
		}
		secret := s.(*core.Secret)
		pullSecrets = append(pullSecrets, *secret)
	}
	return c.scanImages(w, pullSecrets)
}

func (c *Scanner) InitScanImage(image, namespace string, imagePullSecrets []string) error {
	var pullSecrets []core.Secret
	for _, name := range imagePullSecrets {
		s, err := c.cache.Get(namespace + "/" + name)
		if err != nil {
			return err
		}
		secret := s.(*core.Secret)
		pullSecrets = append(pullSecrets, *secret)
	}

	keyring, err := docker.MakeDockerKeyring(pullSecrets)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), Timeout)
	defer cancel()

	return c.postAncestry(ctx, keyring, image)
}

func (c *Scanner) ScanImage(image, namespace string, imagePullSecrets []string) (*api.ScanResult, error) {
	var pullSecrets []core.Secret
	for _, name := range imagePullSecrets {
		s, err := c.cache.Get(namespace + "/" + name)
		if err != nil {
			return nil, err
		}
		secret := s.(*core.Secret)
		pullSecrets = append(pullSecrets, *secret)
	}

	keyring, err := docker.MakeDockerKeyring(pullSecrets)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), Timeout)
	defer cancel()

	err = c.postAncestry(ctx, keyring, image)
	if err != nil {
		return nil, err
	}

	return c.getAncestry(ctx, image)
}

func (c *Scanner) scanImages(w *wpi.Workload, pullSecrets []core.Secret) ([]api.ScanResult, error) {
	keyring, err := docker.MakeDockerKeyring(pullSecrets)
	if err != nil {
		return nil, err
	}

	images := sets.NewString()
	for _, c := range w.Spec.Template.Spec.Containers {
		images.Insert(c.Image)
	}
	for _, c := range w.Spec.Template.Spec.InitContainers {
		images.Insert(c.Image)
	}

	ctx, cancel := context.WithTimeout(context.Background(), Timeout)
	defer cancel()

	results := make([]api.ScanResult, 0, images.Len())
	for _, image := range images.List() {
		err = c.postAncestry(ctx, keyring, image)
		if err != nil {
			return nil, err
		}

		result, err := c.getAncestry(ctx, image)
		if err != nil {
			return nil, err
		}
		results = append(results, *result)
	}
	return results, nil
}

func (c *Scanner) postAncestry(ctx context.Context, keyring credentialprovider.DockerKeyring, image string) error {
	ref, err := docker.ParseImageName(image)
	if err != nil {
		return err
	}
	_, auth, mf, err := docker.PullManifest(ref, keyring)
	if err != nil {
		if c.failurePolicy == types.FailurePolicyIgnore {
			return nil
		}
		return err
	}

	req, err := c.NewPostAncestryRequest(ref, auth, mf)
	if err != nil {
		return err
	}

	_, err = c.AncestryClient.PostAncestry(ctx, req)
	if err != nil {
		return errors.Wrapf(err, "failed to send layers for image %s to clair", ref)
	}
	return nil
}

func (c *Scanner) getAncestry(ctx context.Context, image string) (*api.ScanResult, error) {
	ref, err := docker.ParseImageName(image)
	if err != nil {
		return nil, err
	}
	req, err := c.AncestryClient.GetAncestry(ctx, &clairpb.GetAncestryRequest{
		AncestryName:        ref.String(),
		WithFeatures:        true,
		WithVulnerabilities: true,
	})
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get layers for image %s", image)
	}

	return &api.ScanResult{
		Name:     image,
		Features: getFeatures(req),
	}, nil
}

func (c *Scanner) NewPostAncestryRequest(ref docker.ImageRef, auth *dockertypes.AuthConfig, mf interface{}) (*clairpb.PostAncestryRequest, error) {
	headers := map[string]string{}
	if auth.Username != "" && auth.Password != "" {
		headers["Authorization"] = "Basic " + base64.StdEncoding.EncodeToString([]byte(auth.Username+":"+auth.Password))
	}

	req := &clairpb.PostAncestryRequest{
		AncestryName: ref.String(),
		Format:       "Docker",
	}
	switch manifest := mf.(type) {
	case *manifestV2.DeserializedManifest:
		layers := make([]*clairpb.PostAncestryRequest_PostLayer, len(manifest.Layers))
		for i, layer := range manifest.Layers {
			layers[i] = &clairpb.PostAncestryRequest_PostLayer{
				Hash:    manifest.Config.Digest.Hex() + layer.Digest.Hex(),
				Path:    fmt.Sprintf("%s/v2/%s/blobs/%s", auth.ServerAddress, ref.Repository, layer.Digest.String()),
				Headers: headers,
			}
		}
		req.Layers = layers
	case *manifestV1.SignedManifest:
		layers := make([]*clairpb.PostAncestryRequest_PostLayer, len(manifest.FSLayers))
		for i, layer := range manifest.FSLayers {
			layers[len(manifest.FSLayers)-1-i] = &clairpb.PostAncestryRequest_PostLayer{
				Hash:    layer.BlobSum.Hex(),
				Path:    fmt.Sprintf("%s/v2/%s/blobs/%s", auth.ServerAddress, ref.Repository, layer.BlobSum.String()),
				Headers: headers,
			}
		}
		req.Layers = layers
	default:
		return nil, errors.New("unknown manifest type")
	}
	if len(req.Layers) == 0 {
		return nil, errors.Errorf("failed to pull Layers for image %s", ref)
	}
	return req, nil
}

func getFeatures(resp *clairpb.GetAncestryResponse) []api.Feature {
	fs := make([]api.Feature, 0, len(resp.Ancestry.Features))
	for _, feature := range resp.Ancestry.Features {
		vuls := make([]api.Vulnerability, 0, len(feature.Vulnerabilities))
		for _, vul := range feature.Vulnerabilities {
			vuls = append(vuls, api.Vulnerability{
				Name:          vul.Name,
				NamespaceName: vul.NamespaceName,
				Description:   vul.Description,
				Link:          vul.Link,
				Severity:      vul.Severity,
				FixedBy:       vul.FixedBy,
				FeatureName:   feature.Name,
			})
		}

		fs = append(fs, api.Feature{
			Name:            feature.Name,
			NamespaceName:   feature.NamespaceName,
			Version:         feature.Version,
			Vulnerabilities: vuls,
		})
	}
	return fs
}
