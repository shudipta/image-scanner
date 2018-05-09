package cmds

import (
	"flag"
	"log"
	"os"
	"strings"

	v "github.com/appscode/go/version"
	"github.com/appscode/kutil/tools/analytics"
	"github.com/jpillora/go-ogle-analytics"
	"github.com/soter/scanner/client/clientset/versioned/scheme"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	genericapiserver "k8s.io/apiserver/pkg/server"
	clientsetscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/kubernetes/pkg/api/legacyscheme"
)

const (
	gaTrackingCode = "UA-62096468-20"
)

func NewRootCmd() *cobra.Command {
	var (
		enableAnalytics = true
	)
	var rootCmd = &cobra.Command{
		Use:               "scanner",
		Short:             `Scanner by AppsCode - Docker Image Scanner`,
		DisableAutoGenTag: true,
		PersistentPreRun: func(c *cobra.Command, args []string) {
			c.Flags().VisitAll(func(flag *pflag.Flag) {
				log.Printf("FLAG: --%s=%q", flag.Name, flag.Value)
			})
			if enableAnalytics && gaTrackingCode != "" {
				if client, err := ga.NewClient(gaTrackingCode); err == nil {
					client.ClientID(analytics.ClientID())
					parts := strings.Split(c.CommandPath(), " ")
					client.Send(ga.NewEvent(parts[0], strings.Join(parts[1:], "/")).Label(v.Version.Version))
				}
			}
			scheme.AddToScheme(clientsetscheme.Scheme)
			scheme.AddToScheme(legacyscheme.Scheme)
		},
	}
	rootCmd.PersistentFlags().AddGoFlagSet(flag.CommandLine)
	// ref: https://github.com/kubernetes/kubernetes/issues/17162#issuecomment-225596212
	flag.CommandLine.Parse([]string{})
	rootCmd.PersistentFlags().BoolVar(&enableAnalytics, "enable-analytics", enableAnalytics, "Send usage events to Google Analytics")

	rootCmd.AddCommand(v.NewCmdVersion())
	stopCh := genericapiserver.SetupSignalHandler()
	rootCmd.AddCommand(NewCmdRun(os.Stdout, os.Stderr, stopCh))

	rootCmd.AddCommand(NewCmdScan())

	return rootCmd
}
