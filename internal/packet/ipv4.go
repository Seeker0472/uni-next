package packet

import (
	"encoding/binary"
	"errors"
)

func ValidateIPv4(value []byte, mtu int, outbound bool) error {
	if len(value) < 20 {
		return errors.New("IPv4 packet is shorter than the minimum header")
	}
	if value[0]>>4 != 4 {
		return errors.New("only IPv4 packets are supported")
	}
	headerLength := int(value[0]&0x0f) * 4
	if headerLength < 20 || headerLength > len(value) {
		return errors.New("invalid IPv4 header length")
	}
	totalLength := int(binary.BigEndian.Uint16(value[2:4]))
	if totalLength != len(value) {
		return errors.New("IPv4 total length does not match frame body")
	}
	if outbound && totalLength > mtu {
		return errors.New("outbound IPv4 packet exceeds configured tunnel MTU")
	}
	return nil
}
