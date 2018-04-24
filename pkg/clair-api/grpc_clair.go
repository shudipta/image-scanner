package clair_api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/coreos/clair/api/v3/clairpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func DialOptionForTLSConfig() (grpc.DialOption, error) {
	certificate, err := tls.LoadX509KeyPair(
		"/var/clairapi-client-cert/client.crt",
		"/var/clairapi-client-cert/client.key",
	)

	certPool := x509.NewCertPool()
	pemCert, err := ioutil.ReadFile("/var/clairapi-client-cert/ca.crt")
	if err != nil {
		return nil, fmt.Errorf("failed to read ca cert: %s", err)
	}

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

func SendLayer(postAncestryRequest *clairpb.PostAncestryRequest, clairClient clairpb.AncestryServiceClient) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	_, err := clairClient.PostAncestry(ctx, postAncestryRequest)

	return err
}

func GetLayer(
	repo string, clairClient clairpb.AncestryServiceClient) (*clairpb.GetAncestryResponse, error) {
	getAncestryRequest := &clairpb.GetAncestryRequest{
		AncestryName:        repo,
		WithFeatures:        true,
		WithVulnerabilities: true,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	return clairClient.GetAncestry(ctx, getAncestryRequest)
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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	return clairClient.GetNotification(ctx, req)
}
