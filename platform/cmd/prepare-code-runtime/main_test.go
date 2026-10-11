package main

import (
	"net/netip"
	"testing"
)

func TestChoosePlatformPrivateIPIsDistinctAndUsable(t *testing.T) {
	tests := []struct {
		name       string
		subnet     string
		controller string
		want       string
	}{
		{name: "skip controller at first candidate", subnet: "172.30.76.0/24", controller: "172.30.76.2", want: "172.30.76.3"},
		{name: "choose first candidate when controller follows", subnet: "172.30.76.0/24", controller: "172.30.76.3", want: "172.30.76.2"},
		{name: "smallest supported private subnet", subnet: "192.168.8.0/28", controller: "192.168.8.14", want: "192.168.8.2"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			prefix := netip.MustParsePrefix(tc.subnet)
			controller := netip.MustParseAddr(tc.controller)
			got, err := choosePlatformPrivateIP(prefix, controller)
			if err != nil {
				t.Fatalf("choose platform address: %v", err)
			}
			if got.String() != tc.want {
				t.Fatalf("platform address = %s, want %s", got, tc.want)
			}
			if !got.Is4() || !got.IsPrivate() || !prefix.Contains(got) || got == controller ||
				got == prefix.Addr() || got == prefix.Addr().Next() {
				t.Fatalf("platform address is not distinct and usable: %s", got)
			}
		})
	}
}

func TestChoosePlatformPrivateIPRejectsInvalidControllerOrSubnet(t *testing.T) {
	tests := []struct {
		name       string
		subnet     string
		controller string
	}{
		{name: "controller is gateway", subnet: "172.30.76.0/24", controller: "172.30.76.1"},
		{name: "controller is network", subnet: "172.30.76.0/24", controller: "172.30.76.0"},
		{name: "controller is broadcast", subnet: "172.30.76.0/24", controller: "172.30.76.255"},
		{name: "controller outside subnet", subnet: "172.30.76.0/24", controller: "172.30.77.2"},
		{name: "public subnet", subnet: "8.8.8.0/24", controller: "8.8.8.2"},
		{name: "noncanonical prefix", subnet: "172.30.76.1/24", controller: "172.30.76.2"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := choosePlatformPrivateIP(netip.MustParsePrefix(tc.subnet), netip.MustParseAddr(tc.controller))
			if err == nil {
				t.Fatal("invalid controller/subnet unexpectedly accepted")
			}
		})
	}
}
