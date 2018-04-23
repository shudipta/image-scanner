package routes

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"
	"context"

	"github.com/appscode/go/log"
	"k8s.io/apiserver/pkg/server/mux"
	"github.com/coreos/clair/api/v3/clairpb"
	"google.golang.org/grpc"
	"time"
	"github.com/tamalsaha/go-oneliners"
)

const (
	AppName = "log-audit"
)

var mu sync.Mutex

// AuditLogWebhook installs the default prometheus metrics handler
type AuditLogWebhook struct{}

// Install adds the AuditLogWebhook handler
func (m AuditLogWebhook) Install(c *mux.PathRecorderMux) {
	c.Handle("/audit-log", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp, err := ioutil.ReadAll(r.Body)

		type notification struct {
			Name string
		}
		var notificationEnvelop struct{Notification notification}

		err = json.Unmarshal(resp, &notificationEnvelop)
		if err != nil {
			log.Fatalln(err)
		}

		fmt.Println("notication =", notificationEnvelop.Notification.Name)


		clairAddress := "192.168.99.100:30060"
		clairClient, err := clairClientSetup(clairAddress)
		if err != nil {
			fmt.Println("failed to connect:", err)
			log.Fatalln("failed to connect:", err)
		}

		err = markNotificationAsRead(clairClient, notificationEnvelop.Notification.Name)
		if err != nil {
			fmt.Println("failed to mark notification as read:", err)
			log.Fatalln("failed to mark notification as read:", err)
		}

		notificationResp, err := getNotification(clairClient, notificationEnvelop.Notification.Name)
		if err != nil {
			fmt.Println("failed to get notification:", err)
			log.Fatalln("failed to get notification:", err)
		}

		oneliners.PrettyJson(notificationResp, "notification")
	}))
}

func clairClientSetup(clairAddress string) (clairpb.NotificationServiceClient, error) {
	conn, err := grpc.Dial(clairAddress, grpc.WithInsecure())
	if err != nil {
		return nil, err
	}

	c := clairpb.NewNotificationServiceClient(conn)
	return c, nil
}

func markNotificationAsRead(clairClient clairpb.NotificationServiceClient, notificationName string) error {
	req := &clairpb.MarkNotificationAsReadRequest{
		Name: notificationName,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	_, err := clairClient.MarkNotificationAsRead(ctx, req)
	if err != nil {
		return err
	}

	return nil
}

func getNotification(
	clairClient clairpb.NotificationServiceClient,
	notificationName string) (*clairpb.GetNotificationResponse, error) {

	req := &clairpb.GetNotificationRequest{
		Name: notificationName,
		Limit: 10,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	return clairClient.GetNotification(ctx, req)
}
