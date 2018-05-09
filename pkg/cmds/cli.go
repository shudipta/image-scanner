package cmds

import (
	"flag"
	"log"
	"strings"

	"github.com/appscode/go/analytics"
	v "github.com/appscode/go/version"
	"github.com/appscode/kutil/tools/plugin_installer"
	"github.com/jpillora/go-ogle-analytics"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func NewCmdCli(version string, plugin bool) *cobra.Command {
	var (
		enableAnalytics = true
	)
	rootCmd := &cobra.Command{
		Use:               "scanner-cli [command]",
		Short:             `scanner-cli by AppsCode - CLI to Docker image scanner`,
		DisableAutoGenTag: true,
		PersistentPreRun: func(c *cobra.Command, args []string) {
			c.Flags().VisitAll(func(flag *pflag.Flag) {
				log.Printf("FLAG: --%s=%q", flag.Name, flag.Value)
			})
			if enableAnalytics && gaTrackingCode != "" {
				if client, err := ga.NewClient(gaTrackingCode); err == nil {
					client.ClientID(analytics.ClientID())
					parts := strings.Split(c.CommandPath(), " ")
					client.Send(ga.NewEvent(parts[0], strings.Join(parts[1:], "/")).Label(version))
				}
			}
			if plugin {
				plugin_installer.LoadFlags(c.LocalFlags())
				plugin_installer.LoadFromEnv(c.Flags(), "analytics", "KUBECTL_PLUGINS_LOCAL_FLAG_")
			}
		},
	}

	flags := rootCmd.PersistentFlags()
	clientConfig := plugin_installer.BindGlobalFlags(flags, plugin)
	flags.BoolVar(&enableAnalytics, "analytics", enableAnalytics, "Send analytical events to Google Guard")
	// ref: https://github.com/kubernetes/kubernetes/issues/17162#issuecomment-225596212
	flag.CommandLine.Parse([]string{})
	flag.Set("stderrthreshold", "ERROR")

	rootCmd.AddCommand(NewCmdScan(clientConfig))
	rootCmd.AddCommand(plugin_installer.NewCmdInstall(rootCmd))
	rootCmd.AddCommand(v.NewCmdVersion())
	return rootCmd
}
