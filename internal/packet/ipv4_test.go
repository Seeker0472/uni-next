package packet

import (
	"encoding/binary"
	"testing"
)

func packet(length int, ihl byte) []byte {
	value := make([]byte, length)
	value[0] = 0x40 | ihl
	binary.BigEndian.PutUint16(value[2:4], uint16(length))
	return value
}

func TestValidateIPv4SupportsOptionsAndFragments(t *testing.T) {
	value := packet(28, 6)
	value[6] = 0x20
	if err := ValidateIPv4(value, 1300, true); err != nil {
		t.Fatal(err)
	}
}

func TestValidateIPv4RejectsLengthAndMTUViolations(t *testing.T) {
	bad := packet(20, 5)
	binary.BigEndian.PutUint16(bad[2:4], 19)
	if err := ValidateIPv4(bad, 1300, false); err == nil {
		t.Fatal("expected total length failure")
	}
	large := packet(1301, 5)
	if err := ValidateIPv4(large, 1300, true); err == nil {
		t.Fatal("expected outbound MTU failure")
	}
	if err := ValidateIPv4(large, 1300, false); err != nil {
		t.Fatalf("receive path must not equate frame limit with TUN MTU: %v", err)
	}
}
