package routes

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"

	"github.com/appscode/go/log"
	"github.com/coreos/clair/api/v3/clairpb"
	"github.com/soter/scanner/pkg/clair-api"
	"github.com/tamalsaha/go-oneliners"
	"k8s.io/apiserver/pkg/server/mux"
)

const (
	AppName = "log-audit"
)

var mu sync.Mutex

// AuditLogWebhook installs the default prometheus metrics handler
type AuditLogWebhook struct {
	ClairNotificationServiceClient clairpb.NotificationServiceClient
}

// Install adds the AuditLogWebhook handler
func (m AuditLogWebhook) Install(c *mux.PathRecorderMux) {
	c.Handle("/audit-log", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp, err := ioutil.ReadAll(r.Body)

		type notification struct {
			Name string
		}
		var notificationEnvelop struct{ Notification notification }

		err = json.Unmarshal(resp, &notificationEnvelop)
		if err != nil {
			log.Fatalln(err)
		}

		fmt.Println("notication =", notificationEnvelop.Notification.Name)

		//clairAddress := "192.168.99.100:30060"
		//dialOption, err := clair_api.DialOptionForTLSConfig()
		//if err != nil {
		//	fmt.Printf("failed to get dial option for tls:", err)
		//	log.Fatalf("failed to get dial option for tls:", err)
		//}
		//m.ClairNotificationServiceClient, err = clair_api.NewClairNotificationServiceClient(clairAddress)
		//if err != nil {
		//	fmt.Printf("failed to connect for Notification Service:", err)
		//	log.Fatalf("failed to connect for Notification Service:", err)
		//}

		err = clair_api.MarkNotificationAsRead(m.ClairNotificationServiceClient, notificationEnvelop.Notification.Name)
		if err != nil {
			fmt.Println("failed to mark notification as read:", err)
			log.Fatalln("failed to mark notification as read:", err)
		}

		notificationResp, err := clair_api.GetNotification(m.ClairNotificationServiceClient, notificationEnvelop.Notification.Name)
		if err != nil {
			fmt.Println("failed to get notification:", err)
			log.Fatalln("failed to get notification:", err)
		}

		oneliners.PrettyJson(notificationResp, "notification")
	}))
}
