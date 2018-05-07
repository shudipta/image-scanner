package server

import (
	"fmt"
	"strings"

	hooks "github.com/appscode/kubernetes-webhook-util/admission/v1beta1"
	wpi "github.com/appscode/kubernetes-webhook-util/apis/workload/v1"
	admissionreview "github.com/appscode/kubernetes-webhook-util/registry/admissionreview/v1beta1"
	"github.com/soter/scanner/apis/scanner/install"
	"github.com/soter/scanner/apis/scanner/v1alpha1"
	"github.com/soter/scanner/pkg/controller"
	"github.com/soter/scanner/pkg/registry/scanner"
	irregistry "github.com/soter/scanner/pkg/registry/scanner/imagereview"
	wrregistry "github.com/soter/scanner/pkg/registry/scanner/workloadreview"
	"github.com/soter/scanner/pkg/routes"
	admission "k8s.io/api/admission/v1beta1"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/apimachinery"
	"k8s.io/apimachinery/pkg/apimachinery/announced"
	"k8s.io/apimachinery/pkg/apimachinery/registered"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/version"
	"k8s.io/apiserver/pkg/registry/rest"
	genericapiserver "k8s.io/apiserver/pkg/server"
)

var (
	groupFactoryRegistry = make(announced.APIGroupFactoryRegistry)
	registry             = registered.NewOrDie("")
	Scheme               = runtime.NewScheme()
	Codecs               = serializer.NewCodecFactory(Scheme)
)

func init() {
	install.Install(groupFactoryRegistry, registry, Scheme)
	admission.AddToScheme(Scheme)

	// we need to add the options to empty v1
	// TODO fix the server code to avoid this
	metav1.AddToGroupVersion(Scheme, schema.GroupVersion{Version: "v1"})

	// TODO: keep the generic API server from wanting this
	unversioned := schema.GroupVersion{Group: "", Version: "v1"}
	Scheme.AddUnversionedTypes(unversioned,
		&metav1.Status{},
		&metav1.APIVersions{},
		&metav1.APIGroupList{},
		&metav1.APIGroup{},
		&metav1.APIResourceList{},
	)
}

type ScannerConfig struct {
	GenericConfig *genericapiserver.RecommendedConfig
	ScannerConfig *controller.Config
}

// ScannerServer contains state for a Kubernetes cluster master/api server.
type ScannerServer struct {
	GenericAPIServer *genericapiserver.GenericAPIServer
	Scanner          *controller.Controller
}

func (op *ScannerServer) Run(stopCh <-chan struct{}) error {
	go op.Scanner.ScanCluster()

	return op.GenericAPIServer.PrepareRun().Run(stopCh)
}

type completedConfig struct {
	GenericConfig genericapiserver.CompletedConfig
	ScannerConfig *controller.Config
}

type CompletedConfig struct {
	// Embed a private pointer that cannot be instantiated outside of this package.
	*completedConfig
}

// Complete fills in any fields not set that are required to have valid data. It's mutating the receiver.
func (c *ScannerConfig) Complete() CompletedConfig {
	completedCfg := completedConfig{
		c.GenericConfig.Complete(),
		c.ScannerConfig,
	}

	completedCfg.GenericConfig.Version = &version.Info{
		Major: "1",
		Minor: "1",
	}

	return CompletedConfig{&completedCfg}
}

// New returns a new instance of ScannerServer from the given config.
func (c completedConfig) New() (*ScannerServer, error) {
	genericServer, err := c.GenericConfig.New("soter-scanner", genericapiserver.EmptyDelegate) // completion is done in Complete, no need for a second time
	if err != nil {
		return nil, err
	}

	ctrl, err := c.ScannerConfig.New()
	if err != nil {
		return nil, err
	}

	routes.AuditLogWebhook{
		ClairNotificationServiceClient: c.ScannerConfig.Scanner.NotificationClient,
	}.Install(genericServer.Handler.NonGoRestfulMux)

	var admissionHooks = []hooks.AdmissionHook{
		ctrl.NewDeploymentWebhook(),
		ctrl.NewDaemonSetWebhook(),
		ctrl.NewStatefulSetWebhook(),
		ctrl.NewReplicationControllerWebhook(),
		ctrl.NewReplicaSetWebhook(),
		ctrl.NewJobWebhook(),
		ctrl.NewCronJobWebhook(),
	}

	s := &ScannerServer{
		GenericAPIServer: genericServer,
		Scanner:          ctrl,
	}

	for _, versionMap := range admissionHooksByGroupThenVersion(admissionHooks...) {

		accessor := meta.NewAccessor()
		versionInterfaces := &meta.VersionInterfaces{
			ObjectConvertor:  Scheme,
			MetadataAccessor: accessor,
		}

		interfacesFor := func(version schema.GroupVersion) (*meta.VersionInterfaces, error) {
			if version != admission.SchemeGroupVersion {
				return nil, fmt.Errorf("unexpected version %v", version)
			}
			return versionInterfaces, nil
		}
		restMapper := meta.NewDefaultRESTMapper([]schema.GroupVersion{admission.SchemeGroupVersion}, interfacesFor)
		// TODO we're going to need a later k8s.io/apiserver so that we can get discovery to list a different group version for
		// our endpoint which we'll use to back some custom storage which will consume the AdmissionReview type and give back the correct response
		apiGroupInfo := genericapiserver.APIGroupInfo{
			GroupMeta: apimachinery.GroupMeta{
				// filled in later
				//GroupVersion:  admissionVersion,
				//GroupVersions: []schema.GroupVersion{admissionVersion},

				SelfLinker:    runtime.SelfLinker(accessor),
				RESTMapper:    restMapper,
				InterfacesFor: interfacesFor,
				InterfacesByVersion: map[schema.GroupVersion]*meta.VersionInterfaces{
					admission.SchemeGroupVersion: versionInterfaces,
				},
			},
			VersionedResourcesStorageMap: map[string]map[string]rest.Storage{},
			// TODO unhardcode this.  It was hardcoded before, but we need to re-evaluate
			OptionsExternalVersion: &schema.GroupVersion{Version: "v1"},
			Scheme:                 Scheme,
			ParameterCodec:         metav1.ParameterCodec,
			NegotiatedSerializer:   Codecs,
		}

		for _, admissionHooks := range versionMap {
			for i := range admissionHooks {
				admissionHook := admissionHooks[i]
				admissionResource, singularResourceType := admissionHook.Resource()
				admissionVersion := admissionResource.GroupVersion()

				restMapper.AddSpecific(
					admission.SchemeGroupVersion.WithKind("AdmissionReview"),
					admissionResource,
					admissionVersion.WithResource(singularResourceType),
					meta.RESTScopeRoot)

				// just overwrite the groupversion with a random one.  We don't really care or know.
				apiGroupInfo.GroupMeta.GroupVersions = appendUniqueGroupVersion(apiGroupInfo.GroupMeta.GroupVersions, admissionVersion)

				admissionReview := admissionreview.NewREST(admissionHook.Admit)
				v1alpha1storage, ok := apiGroupInfo.VersionedResourcesStorageMap[admissionVersion.Version]
				if !ok {
					v1alpha1storage = map[string]rest.Storage{}
				}
				v1alpha1storage[admissionResource.Resource] = admissionReview
				apiGroupInfo.VersionedResourcesStorageMap[admissionVersion.Version] = v1alpha1storage
			}
		}

		// just prefer the first one in the list for consistency
		apiGroupInfo.GroupMeta.GroupVersion = apiGroupInfo.GroupMeta.GroupVersions[0]
		if err := s.GenericAPIServer.InstallAPIGroup(&apiGroupInfo); err != nil {
			return nil, err
		}
	}

	for i := range admissionHooks {
		admissionHook := admissionHooks[i]
		postStartName := postStartHookName(admissionHook)
		if len(postStartName) == 0 {
			continue
		}
		s.GenericAPIServer.AddPostStartHookOrDie(postStartName,
			func(context genericapiserver.PostStartHookContext) error {
				return admissionHook.Initialize(c.ScannerConfig.ClientConfig, context.StopCh)
			},
		)
	}

	{
		accessor := meta.NewAccessor()
		versionInterfaces := &meta.VersionInterfaces{
			ObjectConvertor:  Scheme,
			MetadataAccessor: accessor,
		}

		interfacesFor := func(version schema.GroupVersion) (*meta.VersionInterfaces, error) {
			if version != v1alpha1.SchemeGroupVersion {
				return nil, fmt.Errorf("unexpected version %v", version)
			}
			return versionInterfaces, nil
		}
		restMapper := meta.NewDefaultRESTMapper([]schema.GroupVersion{v1alpha1.SchemeGroupVersion}, interfacesFor)
		// TODO we're going to need a later k8s.io/apiserver so that we can get discovery to list a different group version for
		// our endpoint which we'll use to back some custom storage which will consume the AdmissionReview type and give back the correct response
		apiGroupInfo := genericapiserver.APIGroupInfo{
			GroupMeta: apimachinery.GroupMeta{
				// filled in later
				//GroupVersion:  admissionVersion,
				//GroupVersions: []schema.GroupVersion{admissionVersion},

				SelfLinker:    runtime.SelfLinker(accessor),
				RESTMapper:    restMapper,
				InterfacesFor: interfacesFor,
				InterfacesByVersion: map[schema.GroupVersion]*meta.VersionInterfaces{
					v1alpha1.SchemeGroupVersion: versionInterfaces,
				},
			},
			VersionedResourcesStorageMap: map[string]map[string]rest.Storage{},
			// TODO unhardcode this.  It was hardcoded before, but we need to re-evaluate
			OptionsExternalVersion: &schema.GroupVersion{Version: "v1"},
			Scheme:                 Scheme,
			ParameterCodec:         metav1.ParameterCodec,
			NegotiatedSerializer:   Codecs,
		}

		scanners := []scanner.Storage{
			wrregistry.NewREST(c.ScannerConfig.Scanner, v1alpha1.SchemeGroupVersion.WithResource(wpi.ResourcePods), wpi.ResourcePod),
			wrregistry.NewREST(c.ScannerConfig.Scanner, v1alpha1.SchemeGroupVersion.WithResource(wpi.ResourceDeployments), wpi.ResourceDeployment),
			wrregistry.NewREST(c.ScannerConfig.Scanner, v1alpha1.SchemeGroupVersion.WithResource(wpi.ResourceReplicaSets), wpi.ResourceReplicaSet),
			wrregistry.NewREST(c.ScannerConfig.Scanner, v1alpha1.SchemeGroupVersion.WithResource(wpi.ResourceReplicationControllers), wpi.ResourceReplicationController),
			wrregistry.NewREST(c.ScannerConfig.Scanner, v1alpha1.SchemeGroupVersion.WithResource(wpi.ResourceStatefulSets), wpi.ResourceStatefulSet),
			wrregistry.NewREST(c.ScannerConfig.Scanner, v1alpha1.SchemeGroupVersion.WithResource(wpi.ResourceDaemonSets), wpi.ResourceDaemonSet),
			wrregistry.NewREST(c.ScannerConfig.Scanner, v1alpha1.SchemeGroupVersion.WithResource(wpi.ResourceJobs), wpi.ResourceJob),
			wrregistry.NewREST(c.ScannerConfig.Scanner, v1alpha1.SchemeGroupVersion.WithResource(wpi.ResourceCronJobs), wpi.ResourceCronJob),
			wrregistry.NewREST(c.ScannerConfig.Scanner, v1alpha1.SchemeGroupVersion.WithResource(wpi.ResourceDeploymentConfigs), wpi.ResourceDeploymentConfig),

			irregistry.NewREST(c.ScannerConfig.Scanner, v1alpha1.SchemeGroupVersion.WithResource(v1alpha1.ResourcePluralImageReview), v1alpha1.ResourceSingularImageReview),
		}

		for i := range scanners {
			s := scanners[i]
			plural, singular := s.Resource()
			gv := plural.GroupVersion()
			gvk := s.GroupVersionKind(gv)

			var scope meta.RESTScope
			switch gvk.Kind {
			case v1alpha1.ResourceKindWorkloadReview:
				scope = meta.RESTScopeNamespace
			case v1alpha1.ResourceKindImageReview:
				scope = meta.RESTScopeRoot
			}
			restMapper.AddSpecific(
				s.GroupVersionKind(gv),
				plural,
				gv.WithResource(singular),
				scope)

			// just overwrite the groupversion with a random one.  We don't really care or know.
			apiGroupInfo.GroupMeta.GroupVersions = appendUniqueGroupVersion(apiGroupInfo.GroupMeta.GroupVersions, gv)

			v1alpha1storage, ok := apiGroupInfo.VersionedResourcesStorageMap[gv.Version]
			if !ok {
				v1alpha1storage = map[string]rest.Storage{}
			}
			v1alpha1storage[plural.Resource] = s
			apiGroupInfo.VersionedResourcesStorageMap[gv.Version] = v1alpha1storage
		}

		// just prefer the first one in the list for consistency
		apiGroupInfo.GroupMeta.GroupVersion = v1alpha1.SchemeGroupVersion // apiGroupInfo.GroupMeta.GroupVersions[0]
		if err := s.GenericAPIServer.InstallAPIGroup(&apiGroupInfo); err != nil {
			return nil, err
		}
	}

	return s, nil
}

func appendUniqueGroupVersion(slice []schema.GroupVersion, elems ...schema.GroupVersion) []schema.GroupVersion {
	m := map[schema.GroupVersion]bool{}
	for _, gv := range slice {
		m[gv] = true
	}
	for _, e := range elems {
		m[e] = true
	}
	out := make([]schema.GroupVersion, 0, len(m))
	for gv := range m {
		out = append(out, gv)
	}
	return out
}

func postStartHookName(hook hooks.AdmissionHook) string {
	var ns []string
	gvr, _ := hook.Resource()
	ns = append(ns, fmt.Sprintf("admit-%s.%s.%s", gvr.Resource, gvr.Version, gvr.Group))
	if len(ns) == 0 {
		return ""
	}
	return strings.Join(append(ns, "init"), "-")
}

func admissionHooksByGroupThenVersion(admissionHooks ...hooks.AdmissionHook) map[string]map[string][]hooks.AdmissionHook {
	ret := map[string]map[string][]hooks.AdmissionHook{}
	for i := range admissionHooks {
		hook := admissionHooks[i]
		gvr, _ := hook.Resource()
		group, ok := ret[gvr.Group]
		if !ok {
			group = map[string][]hooks.AdmissionHook{}
			ret[gvr.Group] = group
		}
		group[gvr.Version] = append(group[gvr.Version], hook)
	}
	return ret
}
