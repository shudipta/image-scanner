package server

import (
	"fmt"
	"strings"

	hooks "github.com/appscode/kubernetes-webhook-util/admission/v1beta1"
	admissionreview "github.com/appscode/kubernetes-webhook-util/registry/admissionreview/v1beta1"
	"github.com/soter/scanner/apis/scanner"
	"github.com/soter/scanner/apis/scanner/install"
	"github.com/soter/scanner/apis/scanner/v1alpha1"
	"github.com/soter/scanner/pkg/cache"
	"github.com/soter/scanner/pkg/controller"
	irregistry "github.com/soter/scanner/pkg/registry/scanner/imagereview"
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
	GenericConfig    *genericapiserver.RecommendedConfig
	ControllerConfig *controller.ControllerConfig
}

// ScannerServer contains state for a Kubernetes cluster master/api server.
type ScannerServer struct {
	GenericAPIServer *genericapiserver.GenericAPIServer
	Controller       *controller.ScannerController
}

func (op *ScannerServer) Run(stopCh <-chan struct{}) error {
	go cache.New(op.Controller).Run()

	return op.GenericAPIServer.PrepareRun().Run(stopCh)
}

type completedConfig struct {
	GenericConfig    genericapiserver.CompletedConfig
	ControllerConfig *controller.ControllerConfig
}

type CompletedConfig struct {
	// Embed a private pointer that cannot be instantiated outside of this package.
	*completedConfig
}

// Complete fills in any fields not set that are required to have valid data. It's mutating the receiver.
func (c *ScannerConfig) Complete() CompletedConfig {
	completedCfg := completedConfig{
		c.GenericConfig.Complete(),
		c.ControllerConfig,
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
	ctrl, err := c.ControllerConfig.New()
	if err != nil {
		return nil, err
	}
	c.ControllerConfig.AdmissionHooks = []hooks.AdmissionHook{
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
		Controller:       ctrl,
	}

	for _, versionMap := range admissionHooksByGroupThenVersion(c.ControllerConfig.AdmissionHooks...) {

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

	for i := range c.ControllerConfig.AdmissionHooks {
		admissionHook := c.ControllerConfig.AdmissionHooks[i]
		postStartName := postStartHookName(admissionHook)
		if len(postStartName) == 0 {
			continue
		}
		s.GenericAPIServer.AddPostStartHookOrDie(postStartName,
			func(context genericapiserver.PostStartHookContext) error {
				return admissionHook.Initialize(c.ControllerConfig.ClientConfig, context.StopCh)
			},
		)
	}

	{
		apiGroupInfo := genericapiserver.NewDefaultAPIGroupInfo(scanner.GroupName, registry, Scheme, metav1.ParameterCodec, Codecs)
		apiGroupInfo.GroupMeta.GroupVersion = v1alpha1.SchemeGroupVersion
		v1alpha1storage := map[string]rest.Storage{}
		v1alpha1storage[v1alpha1.ResourcePluralImageReview] = irregistry.NewREST(c.ControllerConfig.ClientConfig, s.Controller)
		apiGroupInfo.VersionedResourcesStorageMap["v1alpha1"] = v1alpha1storage

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
