package main

import (
	"os"
	"runtime"

	"github.com/appscode/go/log"
	logs "github.com/appscode/go/log/golog"
	"github.com/soter/scanner/pkg/cmds"
	_ "k8s.io/client-go/kubernetes/fake"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
)

func main() {
	logs.InitLogs()
	defer logs.FlushLogs()

	if len(os.Getenv("GOMAXPROCS")) == 0 {
		runtime.GOMAXPROCS(runtime.NumCPU())
	}

	if err := cmds.NewCmdScanner().Execute(); err != nil {
		log.Fatalln("Error in Scanner Main:", err)
	}
	log.Infoln("Exiting Scanner Main")
	os.Exit(0)
}
