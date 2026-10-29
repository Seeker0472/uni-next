package cnem

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/seeker/uni-next/internal/apperr"
)

const authResponseSize = 166

type Authentication struct {
	Session SessionID
	Token   string
}

type Identity struct {
	Username string
	Password []byte
	MAC      string
}

func (c *Client) Authenticate(ctx context.Context, identity Identity) (Authentication, error) {
	connection, err := c.dial(ctx)
	if err != nil {
		return Authentication{}, err
	}
	defer connection.Close()
	if err := applyDeadline(connection, ctx, c.authTimeout); err != nil {
		return Authentication{}, err
	}
	request, err := buildAuthRequest(c.host, identity)
	if err != nil {
		return Authentication{}, apperr.Wrap(apperr.CodeConfig, "authentication", apperr.RetryNever, "invalid authentication identity", err)
	}
	defer clear(request)
	if err := writeFull(connection, request); err != nil {
		return Authentication{}, transient("authentication", "write authentication request", err)
	}
	var response [authResponseSize]byte
	if _, err := io.ReadFull(connection, response[:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return Authentication{}, apperr.Wrap(apperr.CodeUnsupported, "authentication", apperr.RetryNever, "gateway returned an unrecognized authentication response", err)
		}
		return Authentication{}, transient("authentication", "read authentication response", err)
	}
	return parseAuthResponse(response[:])
}

func buildAuthRequest(host string, identity Identity) ([]byte, error) {
	mac, err := formatProtocolMAC(identity.MAC)
	if err != nil {
		return nil, err
	}
	query := "SelectLanguage=0&UserName=" + url.QueryEscape(identity.Username) + "&Password=" + url.QueryEscape(string(identity.Password)) + "&MacAddress=" + url.QueryEscape(mac) + "&SVN_Seco_AaA=1&"
	request := "GET /netextension/netextensionlogin.html?" + query + " HTTP/1.1\r\n" +
		"Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/msword, application/vnd.ms-excel, application/vnd.ms-powerpoint, */*\r\n" +
		"Accept-Language: zh-cn\r\nAccept-Encoding: gzip, deflate\r\n" +
		"User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; NT 5.1; SV1; .NET CLR 2.0.50727)OS=Linux64\r\n" +
		"Host: " + host + "\r\n\r\n"
	return []byte(request), nil
}

func parseAuthResponse(response []byte) (Authentication, error) {
	if len(response) != authResponseSize || string(response[:4]) != "\xf0\xf0\xf0\xf0" {
		return Authentication{}, apperr.New(apperr.CodeUnsupported, "authentication", apperr.RetryNever, "gateway returned an unrecognized authentication response")
	}
	var session SessionID
	copy(session[:], response[4:8])
	if session != SessionID([4]byte{response[0x2c], response[0x2d], response[0x2e], response[0x2f]}) {
		return Authentication{}, apperr.New(apperr.CodeUnsupported, "authentication", apperr.RetryNever, "authentication session copies do not match")
	}
	if !allZero(response[0x08:0x2c]) ||
		!allZero(response[0x30:0x34]) ||
		!bytes.Equal(response[0x34:0x40], []byte{0, 1, 0, 0, 0, 0, 0, 6, 0, 0, 0, 16}) ||
		!allZero(response[0x40:0x4c]) ||
		!bytes.Equal(response[0x4c:0x54], []byte{0, 0, 0, 1, 0, 0, 0, 0xff}) ||
		!allZero(response[0x56:0x58]) {
		return Authentication{}, apperr.New(apperr.CodeUnsupported, "authentication", apperr.RetryNever, "gateway returned an unrecognized authentication layout")
	}
	length := int(response[0x54])<<8 | int(response[0x55])
	if length <= 0 || 0x58+length > 0xa4 {
		return Authentication{}, apperr.New(apperr.CodeUnsupported, "authentication", apperr.RetryNever, "authentication token length is invalid")
	}
	tokenBytes := response[0x58 : 0x58+length]
	decoded, err := base64.StdEncoding.DecodeString(string(tokenBytes))
	if err != nil || len(decoded) != 32 {
		return Authentication{}, apperr.New(apperr.CodeUnsupported, "authentication", apperr.RetryNever, "authentication token has an invalid encoding")
	}
	for _, value := range response[0x58+length : 0xa4] {
		if value != 0 {
			return Authentication{}, apperr.New(apperr.CodeUnsupported, "authentication", apperr.RetryNever, "authentication padding is invalid")
		}
	}
	if response[0xa4] != '\r' || response[0xa5] != '\n' {
		return Authentication{}, apperr.New(apperr.CodeUnsupported, "authentication", apperr.RetryNever, "authentication terminator is invalid")
	}
	return Authentication{Session: session, Token: string(tokenBytes)}, nil
}

func allZero(value []byte) bool {
	for _, element := range value {
		if element != 0 {
			return false
		}
	}
	return true
}

func formatProtocolMAC(raw string) (string, error) {
	mac, err := net.ParseMAC(raw)
	if err != nil || len(mac) != 6 {
		return "", errors.New("MAC must contain six bytes")
	}
	return fmt.Sprintf("%02X%02X-%02X%02X-%02X%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]), nil
}

func applyDeadline(connection net.Conn, ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	return connection.SetDeadline(deadline)
}

func sanitizeHost(host string) string { return strings.TrimSpace(host) }
