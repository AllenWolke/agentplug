package bootstrap

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestKafkaDependencyRejectsTCPOnlyAndBlocksBootstrap(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	config := RuntimeConfig{Environment: "development", HTTPAddr: ":8080", InternalAddr: ":8081", DBDriver: "pgx", EventBusMode: "disabled"}
	boot := NewBootstrap(config, NewKafkaDependency([]string{listener.Addr().String()}))
	if err := boot.Start(context.Background()); err == nil || boot.Ready() {
		t.Fatal("a listening TCP port without Kafka metadata must not start workers")
	}
}

func TestKafkaDependencyHonorsCancellationAndRejectsMissingBrokers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := NewKafkaDependency([]string{"127.0.0.1:1"}).Check(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation must stop startup: %v", err)
	}
	if err := NewKafkaDependency(nil).Check(context.Background()); err == nil {
		t.Fatal("missing Kafka brokers must not pass readiness")
	}
}
