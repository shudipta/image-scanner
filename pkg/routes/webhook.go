package routes

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"
	"time"

	"github.com/appscode/go/log"
	//"github.com/coreos/clair/api/v3/clairpb"
	"k8s.io/apiserver/pkg/server/mux"
	"github.com/soter/scanner/pkg/controller"
)

const (
	AppName = "log-audit"
)

var mu sync.Mutex

// AuditLogWebhook installs the default prometheus metrics handler
type AuditLogWebhook struct {
	//ClairNotificationServiceClient clairpb.NotificationServiceClient
	Scanner *controller.Controller
}

// Install adds the AuditLogWebhook handler
func (m AuditLogWebhook) Install(c *mux.PathRecorderMux) {
	c.Handle("/clair", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			fmt.Println("wrong method")
		}

		resp, err := ioutil.ReadAll(r.Body)
		if err != nil {
			fmt.Printf("failed to read request body: %v\n", err)
		}

		type notification struct {
			Name string
		}
		var notificationEnvelop struct{ Notification notification }
		err = json.Unmarshal(resp, &notificationEnvelop)
		if err != nil {
			log.Fatalln(err)
		}

		fmt.Println("=======================\nnotication =", notificationEnvelop.Notification.Name, "\n=====================")

		_, cancel := context.WithTimeout(context.Background(), time.Minute*5)
		defer cancel()
		//
		//req1 := &clairpb.GetNotificationRequest{
		//	Name:  notificationEnvelop.Notification.Name,
		//	Limit: 10,
		//}
		//notificationResp, err := m.ClairNotificationServiceClient.GetNotification(ctx, req1)
		//if err != nil {
		//	fmt.Println("============================\nfailed to get notification:", err, "\n==========================")
		//}
		////ctx, cancel := context.WithTimeout(context.Background(), time.Minute*5)
		////defer cancel()
		////notificationResp, err := clair.GetNotification(m.ClairNotificationServiceClient, notificationEnvelop.Notification.Name)
		////if err != nil {
		////	fmt.Println("============================\nfailed to get notification:", err, "\n==========================")
		////	//log.Fatalln("failed to get notification:", err)
		////}
		//oneliners.PrettyJson(notificationResp, "notification")

		//req2 := &clairpb.MarkNotificationAsReadRequest{
		//	Name: notificationEnvelop.Notification.Name,
		//}
		//_, err = m.Scanner.MarkNotificationAsRead(ctx, req2)
		//if err != nil {
		//	fmt.Println("======================\nfailed to mark notification as read:", err, "\n=======================")
		//}


		//err = clair.MarkNotificationAsRead(m.ClairNotificationServiceClient, notificationEnvelop.Notification.Name)
		//if err != nil {
		//	fmt.Println("======================\nfailed to mark notification as read:", err, "\n=======================")
		//	//log.Fatalln("failed to mark notification as read:", err)
		//}
	}))
}
