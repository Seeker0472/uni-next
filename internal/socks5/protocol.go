package socks5

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
)

const (
	version5            = 5
	methodNoAuth        = 0
	methodUserPassword  = 2
	methodNoAcceptable  = 0xff
	commandConnect      = 1
	commandBind         = 2
	commandUDPAssociate = 3
	addressIPv4         = 1
	addressDomain       = 3
	addressIPv6         = 4
	maxIPv4UDPPayload   = 65507
)

type address struct {
	host string
	port uint16
}

func readMethods(reader io.Reader) ([]byte, error) {
	var header [2]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, err
	}
	if header[0] != version5 || header[1] == 0 {
		return nil, errors.New("invalid SOCKS method request")
	}
	methods := make([]byte, int(header[1]))
	_, err := io.ReadFull(reader, methods)
	return methods, err
}

func writeMethod(writer io.Writer, method byte) error {
	return writeFull(writer, []byte{version5, method})
}

func readUserPassword(reader io.Reader) (string, []byte, error) {
	var header [2]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return "", nil, err
	}
	if header[0] != 1 || header[1] == 0 {
		return "", nil, errors.New("invalid RFC 1929 authentication")
	}
	username := make([]byte, int(header[1]))
	if _, err := io.ReadFull(reader, username); err != nil {
		return "", nil, err
	}
	var length [1]byte
	if _, err := io.ReadFull(reader, length[:]); err != nil {
		return "", nil, err
	}
	if length[0] == 0 {
		return "", nil, errors.New("empty RFC 1929 password")
	}
	password := make([]byte, int(length[0]))
	if _, err := io.ReadFull(reader, password); err != nil {
		return "", nil, err
	}
	return string(username), password, nil
}

func writeUserPasswordStatus(writer io.Writer, ok bool) error {
	status := byte(1)
	if ok {
		status = 0
	}
	return writeFull(writer, []byte{1, status})
}

func readRequest(reader io.Reader) (byte, address, error) {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return 0, address{}, err
	}
	if header[0] != version5 || header[2] != 0 {
		return 0, address{}, errors.New("invalid SOCKS request header")
	}
	target, err := readAddress(reader, header[3])
	return header[1], target, err
}

func readAddress(reader io.Reader, kind byte) (address, error) {
	var host string
	switch kind {
	case addressIPv4:
		var raw [4]byte
		if _, err := io.ReadFull(reader, raw[:]); err != nil {
			return address{}, err
		}
		host = netip.AddrFrom4(raw).String()
	case addressDomain:
		var length [1]byte
		if _, err := io.ReadFull(reader, length[:]); err != nil {
			return address{}, err
		}
		if length[0] == 0 {
			return address{}, errors.New("empty SOCKS domain")
		}
		raw := make([]byte, int(length[0]))
		if _, err := io.ReadFull(reader, raw); err != nil {
			return address{}, err
		}
		host = string(raw)
	case addressIPv6:
		return address{}, errors.New("IPv6 SOCKS targets are unsupported")
	default:
		return address{}, errors.New("unsupported SOCKS address type")
	}
	var port [2]byte
	if _, err := io.ReadFull(reader, port[:]); err != nil {
		return address{}, err
	}
	return address{host: host, port: binary.BigEndian.Uint16(port[:])}, nil
}

func writeReply(writer io.Writer, reply byte, bound netip.AddrPort) error {
	if !bound.IsValid() || !bound.Addr().Is4() {
		bound = netip.AddrPortFrom(netip.IPv4Unspecified(), 0)
	}
	packet := make([]byte, 10)
	packet[0] = version5
	packet[1] = reply
	packet[2] = 0
	packet[3] = addressIPv4
	copy(packet[4:8], bound.Addr().AsSlice())
	binary.BigEndian.PutUint16(packet[8:10], bound.Port())
	return writeFull(writer, packet)
}

func parseUDPRequest(packet []byte) (address, []byte, error) {
	if len(packet) < 4 || packet[0] != 0 || packet[1] != 0 {
		return address{}, nil, errors.New("invalid SOCKS UDP reserved field")
	}
	if packet[2] != 0 {
		return address{}, nil, errors.New("fragmented SOCKS UDP packets are unsupported")
	}
	reader := bytesReader(packet[4:])
	target, err := readAddress(&reader, packet[3])
	if err != nil {
		return address{}, nil, err
	}
	return target, packet[len(packet)-reader.remaining():], nil
}

func encodeUDPResponse(source netip.AddrPort, payload []byte, buffer []byte) ([]byte, error) {
	if !source.IsValid() || !source.Addr().Is4() {
		return nil, errors.New("invalid UDP response source")
	}
	needed := 10 + len(payload)
	if needed > maxIPv4UDPPayload {
		return nil, errors.New("UDP response exceeds IPv4 datagram limit")
	}
	if cap(buffer) < needed {
		return nil, fmt.Errorf("UDP response exceeds buffer")
	}
	packet := buffer[:needed]
	packet[0] = 0
	packet[1] = 0
	packet[2] = 0
	packet[3] = addressIPv4
	copy(packet[4:8], source.Addr().AsSlice())
	binary.BigEndian.PutUint16(packet[8:10], source.Port())
	copy(packet[10:], payload)
	return packet, nil
}

type bytesReader []byte

func (r *bytesReader) Read(value []byte) (int, error) {
	if len(*r) == 0 {
		return 0, io.EOF
	}
	count := copy(value, *r)
	*r = (*r)[count:]
	return count, nil
}
func (r *bytesReader) remaining() int { return len(*r) }

func writeFull(writer io.Writer, value []byte) error {
	for len(value) > 0 {
		count, err := writer.Write(value)
		if err != nil {
			return err
		}
		if count == 0 {
			return io.ErrUnexpectedEOF
		}
		value = value[count:]
	}
	return nil
}

func contains(values []byte, target byte) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func addrPort(value net.Addr) (netip.AddrPort, bool) {
	switch typed := value.(type) {
	case *net.TCPAddr:
		return typed.AddrPort(), true
	case *net.UDPAddr:
		return typed.AddrPort(), true
	default:
		parsed, err := netip.ParseAddrPort(value.String())
		return parsed, err == nil
	}
}
