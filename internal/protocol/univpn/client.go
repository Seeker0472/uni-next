// Package univpn implements the verified Huawei Linux base CNEM profile.
package univpn

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/seeker/uni-next/internal/apperr"
	"github.com/seeker/uni-next/internal/config"
)

type DialFunc func(context.Context) (net.Conn, error)

type Client struct {
	dial           DialFunc
	host           string
	codec          Codec
	authTimeout    time.Duration
	controlTimeout time.Duration
	logoutTimeout  time.Duration
}

type Negotiated struct {
	Connection net.Conn
	Network    NetConfig
	UDPPort    uint16
}

func NewClient(cfg config.Config, dial DialFunc) *Client {
	return &Client{dial: dial, host: sanitizeHost(cfg.Server.Host), codec: NewCodec(), authTimeout: cfg.Timeouts.Auth.Duration, controlTimeout: cfg.Timeouts.ControlStep.Duration, logoutTimeout: cfg.Timeouts.Logout.Duration}
}

func (c *Client) FirstConnect(ctx context.Context) error {
	connection, err := c.dial(ctx)
	if err != nil {
		return err
	}
	defer connection.Close()
	if err := applyDeadline(connection, ctx, c.controlTimeout); err != nil {
		return err
	}
	body := make([]byte, 324)
	copy(body[0:64], []byte("Linux64"))
	if len(c.host) > 127 {
		return apperr.New(apperr.CodeConfig, "first_connect", apperr.RetryNever, "gateway host is too long for current profile")
	}
	copy(body[64:192], []byte(c.host))
	binary.BigEndian.PutUint32(body[320:324], 0x00010000)
	if err := c.codec.Write(connection, Frame{Type: 0x1d, Body: body}); err != nil {
		return transient("first_connect", "write first-connect request", err)
	}
	response, err := c.codec.Read(connection, nil)
	if err != nil {
		return transient("first_connect", "read first-connect response", err)
	}
	if response.Session != (SessionID{0, 0xff, 0xff, 0xff}) || response.Type != 0x1d || len(response.Body) != 776 {
		return apperr.New(apperr.CodeUnsupported, "first_connect", apperr.RetryNever, "gateway returned an unsupported site-selection response")
	}
	for _, value := range response.Body {
		if value != 0 {
			return apperr.New(apperr.CodeUnsupported, "first_connect", apperr.RetryNever, "non-empty site selection is unsupported")
		}
	}
	return nil
}

func (c *Client) Negotiate(ctx context.Context, authentication Authentication) (_ Negotiated, returnErr error) {
	connection, err := c.dial(ctx)
	if err != nil {
		return Negotiated{}, err
	}
	defer func() {
		if returnErr != nil {
			connection.Close()
		}
	}()
	if err := applyDeadline(connection, ctx, c.controlTimeout); err != nil {
		return Negotiated{}, err
	}
	exchange := func(kind uint16, body []byte, expectedLength int) (Frame, error) {
		if err := c.codec.Write(connection, Frame{Session: authentication.Session, Type: kind, Body: body}); err != nil {
			return Frame{}, transient("cnem", fmt.Sprintf("write type %#x", kind), err)
		}
		response, err := c.codec.Read(connection, &authentication.Session)
		if err != nil {
			return Frame{}, transient("cnem", fmt.Sprintf("read type %#x", kind), err)
		}
		if response.Type == 8 {
			return Frame{}, apperr.New(apperr.CodeKickout, "cnem", apperr.RetryKickout, "gateway terminated the session")
		}
		if response.Type != kind || len(response.Body) != expectedLength {
			return Frame{}, apperr.New(apperr.CodeUnsupported, "cnem", apperr.RetryNever, fmt.Sprintf("unexpected response to type %#x", kind))
		}
		return response, nil
	}
	acl, err := exchange(6, []byte{0, 0, 0, 0}, 20)
	if err != nil {
		return Negotiated{}, err
	}
	expectedACL := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1}
	if !bytes.Equal(acl.Body, expectedACL) {
		return Negotiated{}, apperr.New(apperr.CodeUnsupported, "cnem", apperr.RetryNever, "gateway returned an unsupported ACL acknowledgement")
	}
	networkFrame, err := exchange(3, nil, netConfigBodySize)
	if err != nil {
		return Negotiated{}, err
	}
	networkConfig, err := ParseNetConfig(networkFrame.Body)
	if err != nil {
		return Negotiated{}, apperr.Wrap(apperr.CodeUnsupported, "netcfg", apperr.RetryNever, "invalid network configuration", err)
	}
	keyFrame, err := exchange(0x0d, []byte{0, 0, 0, 4}, 20)
	if err != nil {
		return Negotiated{}, err
	}
	if binary.BigEndian.Uint32(keyFrame.Body[:4]) != 3 {
		return Negotiated{}, apperr.New(apperr.CodeUnsupported, "cnem", apperr.RetryNever, "unsupported UDP key status")
	}
	clear(keyFrame.Body)
	portFrame, err := exchange(0x1a, []byte{0, 0, 0, 4}, 4)
	if err != nil {
		return Negotiated{}, err
	}
	udpPort := binary.BigEndian.Uint16(portFrame.Body[:2])
	if udpPort == 0 {
		return Negotiated{}, apperr.New(apperr.CodeUnsupported, "cnem", apperr.RetryNever, "gateway returned an invalid UDP port")
	}
	if portFrame.Body[2] != 0 || portFrame.Body[3] != 0 {
		return Negotiated{}, apperr.New(apperr.CodeUnsupported, "cnem", apperr.RetryNever, "gateway returned an unsupported UDP port response")
	}
	if err := c.codec.Write(connection, Frame{Session: authentication.Session, Type: 0x10}); err != nil {
		return Negotiated{}, transient("cnem", "switch to SSL data tunnel", err)
	}
	if err := connection.SetDeadline(time.Time{}); err != nil {
		return Negotiated{}, transient("cnem", "clear control deadline", err)
	}
	return Negotiated{Connection: connection, Network: networkConfig, UDPPort: udpPort}, nil
}

func (c *Client) Logout(ctx context.Context, auth Authentication, userID []byte) error {
	connection, err := c.dial(ctx)
	if err != nil {
		return err
	}
	defer connection.Close()
	if err := applyDeadline(connection, ctx, c.logoutTimeout); err != nil {
		return err
	}
	request := "GET /logout.html?VTID=0&SelectLanguage=2& HTTP/1.1\r\n" +
		"Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/msword, application/vnd.ms-excel, application/vnd.ms-powerpoint, */*\r\n" +
		"Accept-Language: zh-cn\r\nAccept-Encoding: gzip, deflate\r\n" +
		"User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; NT 5.1; SV1; .NET CLR 2.0.50727)OS=Linux64\r\n" +
		"Host: " + c.host + "\r\n" +
		"Cookie: UserID=" + url.QueryEscape(string(userID)) + "&SVN_SessionID=" + url.QueryEscape(auth.Token) + ";\r\n\r\n"
	if err := writeFull(connection, []byte(request)); err != nil {
		return transient("logout", "write logout request", err)
	}
	reader := bufio.NewReaderSize(connection, 1025)
	lineBytes, err := reader.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		return apperr.New(apperr.CodeUnsupported, "logout", apperr.RetryNever, "logout status line is too long")
	}
	if err != nil {
		return transient("logout", "read logout status", err)
	}
	if len(lineBytes) > 1024 {
		return apperr.New(apperr.CodeUnsupported, "logout", apperr.RetryNever, "logout status line is too long")
	}
	parts := strings.Fields(string(lineBytes))
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "HTTP/1.") {
		return apperr.New(apperr.CodeUnsupported, "logout", apperr.RetryNever, "gateway returned an invalid logout status line")
	}
	var statusCode int
	if _, err := fmt.Sscanf(parts[1], "%d", &statusCode); err != nil {
		return apperr.New(apperr.CodeUnsupported, "logout", apperr.RetryNever, "gateway returned an invalid logout status code")
	}
	if statusCode != 302 {
		return apperr.New(apperr.CodeUnsupported, "logout", apperr.RetryNever, "gateway did not acknowledge logout with HTTP 302")
	}
	return nil
}

func transient(stage, message string, err error) error {
	return apperr.Wrap(apperr.CodeTransient, stage, apperr.RetryNetwork, message, err)
}
