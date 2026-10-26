package univpn

import (
	"encoding/binary"
	"testing"
)

func syntheticNetConfig() []byte {
	body := make([]byte, netConfigBodySize)
	copy(body[0:4], []byte{10, 255, 250, 42})
	copy(body[4:8], []byte{255, 255, 255, 0})
	binary.BigEndian.PutUint32(body[0x08:0x0c], 2)
	binary.BigEndian.PutUint32(body[0x14:0x18], 1)
	binary.BigEndian.PutUint32(body[0x18:0x1c], 12)
	binary.LittleEndian.PutUint32(body[0x1c:0x20], 1)
	binary.BigEndian.PutUint32(body[0xb8:0xbc], 1)
	copy(body[0xbc:0xc0], []byte{10, 19, 20, 0})
	copy(body[0xc0:0xc4], []byte{255, 255, 255, 0})
	return body
}

func TestParseNetConfigUsesCountsAndMasks(t *testing.T) {
	cfg, err := ParseNetConfig(syntheticNetConfig())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.VIP.String() != "10.255.250.42" || cfg.VIPPrefix.String() != "10.255.250.42/24" || len(cfg.Routes) != 1 || cfg.Routes[0].Prefix.String() != "10.19.20.0/24" {
		t.Fatalf("unexpected config: %#v", cfg)
	}
	bad := syntheticNetConfig()
	binary.BigEndian.PutUint32(bad[0x18:0x1c], 24)
	if _, err := ParseNetConfig(bad); err == nil {
		t.Fatal("expected route byte mismatch rejection")
	}
	bad = syntheticNetConfig()
	for i := range 4 {
		bad[0xc0+i] = 0
	}
	if _, err := ParseNetConfig(bad); err == nil {
		t.Fatal("expected default route rejection")
	}
	bad = syntheticNetConfig()
	binary.BigEndian.PutUint32(bad[0x08:0x0c], 3)
	if _, err := ParseNetConfig(bad); err == nil {
		t.Fatal("expected unknown fixed flag rejection")
	}
	bad = syntheticNetConfig()
	binary.BigEndian.PutUint32(bad[0x1c:0x20], 1)
	if _, err := ParseNetConfig(bad); err == nil {
		t.Fatal("expected wrong-endian alloc field rejection")
	}
}
