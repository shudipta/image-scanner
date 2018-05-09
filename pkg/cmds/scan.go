package cmds

import (
	"fmt"

	workload "github.com/appscode/kubernetes-webhook-util/apis/workload/v1"
	"github.com/pkg/errors"
	cs "github.com/soter/scanner/client/clientset/versioned"
	"github.com/soter/scanner/pkg/cli"
	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/clientcmd"
)

func NewCmdScan(clientConfig clientcmd.ClientConfig) *cobra.Command {
	var (
		resourceKinds = sets.NewString(
			workload.ResourcePods, "po",
			workload.ResourceDeployments, "deploy",
			workload.ResourceReplicaSets, "rs",
			workload.ResourceReplicationControllers, "rc",
			workload.ResourceStatefulSets, "sts",
			workload.ResourceDaemonSets, "ds",
			workload.ResourceJobs,
			workload.ResourceCronJobs,
			workload.ResourceDeploymentConfigs,
			"image",
		)
		namespace = ""
		secrets   []string
	)
	scanCmd := &cobra.Command{
		Use:               "scan",
		Short:             "scans workloads and imagereviews",
		Long:              "scans workloads and imagereviews",
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("no resource kind is found")
			} else if len(args) > 2 {
				return fmt.Errorf("invalid command format")
			} else if !resourceKinds.Has(args[0]) {
				return fmt.Errorf("unknown resource kind: %s", args[0])
			}

			config, err := clientConfig.ClientConfig()
			if err != nil {
				return errors.Wrap(err, "Could not get Kubernetes config")
			}

			client := cs.NewForConfigOrDie(config)

			result, err := cli.ScanResult(client, args[0], args[1], namespace, secrets...)
			if err != nil {
				return err
			}
			fmt.Println(result)
			return nil
		},
	}

	scanCmd.Flags().StringVarP(&namespace, "namespace", "n", namespace, "namespace of imagePullSecrets for image that'll be scanned")
	scanCmd.Flags().StringSliceVar(&secrets, "secrets", secrets, "imagePullSecrets for image that'll be scanned")

	return scanCmd
}
