package cnem

import (
	"bytes"
	"io"
	"testing"
)

type byteReader struct{ value []byte }

func (r *byteReader) Read(target []byte) (int, error) {
	if len(r.value) == 0 {
		return 0, io.EOF
	}
	target[0] = r.value[0]
	r.value = r.value[1:]
	return 1, nil
}

func TestCodecHandlesBytewiseReadsAndConsecutiveFrames(t *testing.T) {
	codec := NewCodec()
	sid := SessionID{1, 2, 3, 4}
	var stream bytes.Buffer
	if err := codec.Write(&stream, Frame{Session: sid, Type: 3, Body: []byte{1, 2, 3}}); err != nil {
		t.Fatal(err)
	}
	if err := codec.Write(&stream, Frame{Session: sid, Type: 7}); err != nil {
		t.Fatal(err)
	}
	reader := &byteReader{value: stream.Bytes()}
	first, err := codec.Read(reader, &sid)
	if err != nil {
		t.Fatal(err)
	}
	second, err := codec.Read(reader, &sid)
	if err != nil {
		t.Fatal(err)
	}
	if first.Type != 3 || !bytes.Equal(first.Body, []byte{1, 2, 3}) || second.Type != 7 || len(second.Body) != 0 {
		t.Fatalf("unexpected frames: %#v %#v", first, second)
	}
}

func TestCodecAcceptsOnlyKnownACLLengthException(t *testing.T) {
	header := []byte{0xfe, 0xfc, 0xef, 0xbe, 0xc1, 0x92, 0xa4, 0xd6, 1, 2, 3, 4, 0, 6, 0x14, 0}
	packet := append(header, make([]byte, 20)...)
	sid := SessionID{1, 2, 3, 4}
	frame, err := NewCodec().Read(bytes.NewReader(packet), &sid)
	if err != nil {
		t.Fatal(err)
	}
	if len(frame.Body) != 20 {
		t.Fatalf("length=%d", len(frame.Body))
	}
	packet[13] = 3
	if _, err := NewCodec().Read(bytes.NewReader(packet), &sid); err == nil {
		t.Fatal("same length bytes on another type must not use ACL exception")
	}
}

func TestCodecRejectsSessionMismatchAndTruncation(t *testing.T) {
	codec := NewCodec()
	sid := SessionID{1}
	var stream bytes.Buffer
	if err := codec.Write(&stream, Frame{Session: sid, Type: 2, Body: []byte{1, 2}}); err != nil {
		t.Fatal(err)
	}
	wrong := SessionID{2}
	if _, err := codec.Read(bytes.NewReader(stream.Bytes()), &wrong); err == nil {
		t.Fatal("expected session mismatch")
	}
	if _, err := codec.Read(bytes.NewReader(stream.Bytes()[:17]), &sid); err == nil {
		t.Fatal("expected truncated frame failure")
	}
}

func TestCodecWritesEachFrameInOneWrite(t *testing.T) {
	writer := &countingWriter{}
	frame := Frame{Session: SessionID{1, 2, 3, 4}, Type: 0x1d, Body: make([]byte, 324)}
	if err := NewCodec().Write(writer, frame); err != nil {
		t.Fatal(err)
	}
	if writer.writes != 1 {
		t.Fatalf("frame was delivered in %d writes; the verified gateway requires one", writer.writes)
	}
	decoded, err := NewCodec().Read(bytes.NewReader(writer.buffer.Bytes()), &frame.Session)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Type != frame.Type || len(decoded.Body) != len(frame.Body) {
		t.Fatalf("unexpected decoded frame: %#v", decoded)
	}
}

type countingWriter struct {
	writes int
	buffer bytes.Buffer
}

func (w *countingWriter) Write(value []byte) (int, error) {
	w.writes++
	return w.buffer.Write(value)
}

func TestCodecRejectsBodyAboveConfiguredLimit(t *testing.T) {
	var stream bytes.Buffer
	if err := NewCodec().Write(&stream, Frame{Type: 2, Body: make([]byte, 33)}); err != nil {
		t.Fatal(err)
	}
	codec := Codec{MaxBody: 32}
	if _, err := codec.Read(&stream, nil); err == nil {
		t.Fatal("oversized declared body was accepted")
	}
}
