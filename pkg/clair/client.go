package clair

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"time"

	"github.com/coreos/clair/api/v3/clairpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	Timeout = 5 * time.Minute
)

func DialOptionForTLSConfig(certDir string) (grpc.DialOption, error) {
	certificate, err := tls.LoadX509KeyPair(
		filepath.Join(certDir, "client.crt"),
		filepath.Join(certDir, "client.key"),
	)

	certPool := x509.NewCertPool()
	pemCert, err := ioutil.ReadFile(filepath.Join(certDir, "ca.crt"))
	if err != nil {
		return nil, fmt.Errorf("failed to read ca cert: %s", err)
	}
	fmt.Println(string(pemCert))

	ok := certPool.AppendCertsFromPEM(pemCert)
	if !ok {
		return nil, fmt.Errorf("failed to append certs")
	}

	transportCreds := credentials.NewTLS(&tls.Config{
		//ServerName:   "example.com",
		Certificates: []tls.Certificate{certificate},
		RootCAs:      certPool,
	})

	dialOption := grpc.WithTransportCredentials(transportCreds)

	return dialOption, nil
}

func NewClairAncestryServiceClient(clairAddress string, dialOption grpc.DialOption) (clairpb.AncestryServiceClient, error) {
	conn, err := grpc.Dial(clairAddress, dialOption)
	if err != nil {
		return nil, err
	}

	c := clairpb.NewAncestryServiceClient(conn)
	return c, nil
}

func NewClairNotificationServiceClient(clairAddress string, dialOption grpc.DialOption) (clairpb.NotificationServiceClient, error) {
	conn, err := grpc.Dial(clairAddress, dialOption)
	if err != nil {
		return nil, err
	}

	c := clairpb.NewNotificationServiceClient(conn)
	return c, nil
}

func MarkNotificationAsRead(clairClient clairpb.NotificationServiceClient, notificationName string) error {
	req := &clairpb.MarkNotificationAsReadRequest{
		Name: notificationName,
	}
	ctx, cancel := context.WithTimeout(context.Background(), Timeout)
	defer cancel()
	_, err := clairClient.MarkNotificationAsRead(ctx, req)
	if err != nil {
		return err
	}

	return nil
}

func GetNotification(
	clairClient clairpb.NotificationServiceClient,
	notificationName string) (*clairpb.GetNotificationResponse, error) {

	req := &clairpb.GetNotificationRequest{
		Name:  notificationName,
		Limit: 10,
	}
	ctx, cancel := context.WithTimeout(context.Background(), Timeout)
	defer cancel()
	return clairClient.GetNotification(ctx, req)
}
