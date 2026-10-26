package socks5

import (
	"bytes"
	"net/netip"
	"testing"
)

func TestUDPProtocolRoundTripAndRejectsFragments(t *testing.T) {
	source := netip.MustParseAddrPort("10.1.2.3:5353")
	payload := []byte("answer")
	packet, err := encodeUDPResponse(source, payload, make([]byte, 0, 64))
	if err != nil {
		t.Fatal(err)
	}
	target, decoded, err := parseUDPRequest(packet)
	if err != nil {
		t.Fatal(err)
	}
	if target.host != "10.1.2.3" || target.port != 5353 || !bytes.Equal(decoded, payload) {
		t.Fatalf("unexpected decode: %#v %q", target, decoded)
	}
	packet[2] = 1
	if _, _, err := parseUDPRequest(packet); err == nil {
		t.Fatal("fragment was accepted")
	}
}

func TestUDPResponseRejectsDatagramAboveIPv4Limit(t *testing.T) {
	source := netip.MustParseAddrPort("10.1.2.3:5353")
	payload := make([]byte, maxIPv4UDPPayload-9)
	if _, err := encodeUDPResponse(source, payload, make([]byte, maxIPv4UDPPayload+1)); err == nil {
		t.Fatal("oversized UDP response was accepted")
	}
}

func TestAddressReaderRejectsIPv6(t *testing.T) {
	value := append(make([]byte, 16), 0, 80)
	reader := bytes.NewReader(value)
	if _, err := readAddress(reader, addressIPv6); err == nil {
		t.Fatal("IPv6 target was accepted")
	}
}
