package univpn

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const HeaderSize = 16

var magic = [4]byte{0xfe, 0xfc, 0xef, 0xbe}
var version = [4]byte{0xc1, 0x92, 0xa4, 0xd6}

type SessionID [4]byte

type Frame struct {
	Session SessionID
	Type    uint16
	Body    []byte
}

type Codec struct{ MaxBody int }

func NewCodec() Codec { return Codec{MaxBody: 65535} }

func (c Codec) Read(reader io.Reader, expected *SessionID) (Frame, error) {
	return c.read(reader, expected, nil)
}

func (c Codec) ReadInto(reader io.Reader, expected *SessionID, scratch []byte) (Frame, error) {
	return c.read(reader, expected, scratch)
}

func (c Codec) read(reader io.Reader, expected *SessionID, scratch []byte) (Frame, error) {
	var header [HeaderSize]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return Frame{}, err
	}
	if !equal4(header[0:4], magic) || !equal4(header[4:8], version) {
		return Frame{}, errors.New("invalid CSP magic or version")
	}
	var session SessionID
	copy(session[:], header[8:12])
	if expected != nil && session != *expected {
		return Frame{}, errors.New("CSP session ID mismatch")
	}
	kind := binary.BigEndian.Uint16(header[12:14])
	length := int(binary.BigEndian.Uint16(header[14:16]))
	if kind == 6 && header[14] == 0x14 && header[15] == 0x00 {
		length = 20
	}
	if length < 0 || length > c.MaxBody {
		return Frame{}, fmt.Errorf("CSP body length %d exceeds limit", length)
	}
	var body []byte
	if cap(scratch) >= length {
		body = scratch[:length]
	} else {
		body = make([]byte, length)
	}
	if _, err := io.ReadFull(reader, body); err != nil {
		return Frame{}, err
	}
	return Frame{Session: session, Type: kind, Body: body}, nil
}

func (c Codec) Write(writer io.Writer, frame Frame) error {
	if len(frame.Body) > c.MaxBody || len(frame.Body) > 0xffff {
		return fmt.Errorf("CSP body length %d exceeds limit", len(frame.Body))
	}
	var storage [HeaderSize]byte
	header, err := EncodeHeader(storage[:], frame.Session, frame.Type, len(frame.Body))
	if err != nil {
		return err
	}
	if err := writeFull(writer, header); err != nil {
		return err
	}
	return writeFull(writer, frame.Body)
}

func EncodeHeader(buffer []byte, session SessionID, kind uint16, bodyLength int) ([]byte, error) {
	if bodyLength < 0 || bodyLength > 0xffff {
		return nil, errors.New("CSP body exceeds uint16")
	}
	if cap(buffer) < HeaderSize {
		return nil, errors.New("provided CSP header buffer is too small")
	}
	header := buffer[:HeaderSize]
	copy(header[:4], magic[:])
	copy(header[4:8], version[:])
	copy(header[8:12], session[:])
	binary.BigEndian.PutUint16(header[12:14], kind)
	binary.BigEndian.PutUint16(header[14:16], uint16(bodyLength))
	return header, nil
}

func EncodeInto(buffer []byte, session SessionID, kind uint16, body []byte) ([]byte, error) {
	needed := HeaderSize + len(body)
	if cap(buffer) < needed {
		return nil, errors.New("provided CSP buffer is too small")
	}
	packet := buffer[:needed]
	if _, err := EncodeHeader(packet[:HeaderSize], session, kind, len(body)); err != nil {
		return nil, err
	}
	copy(packet[HeaderSize:], body)
	return packet, nil
}

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

func equal4(value []byte, expected [4]byte) bool {
	return len(value) == 4 && value[0] == expected[0] && value[1] == expected[1] && value[2] == expected[2] && value[3] == expected[3]
}
