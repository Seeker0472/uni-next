package univpn

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func syntheticAuthResponse() []byte {
	response := make([]byte, 166)
	copy(response[:4], []byte{0xf0, 0xf0, 0xf0, 0xf0})
	copy(response[4:8], []byte{1, 2, 3, 4})
	copy(response[0x2c:0x30], response[4:8])
	response[0x34] = 0
	response[0x35] = 1
	response[0x38+3] = 6
	response[0x3c+3] = 16
	response[0x4c+3] = 1
	response[0x50+3] = 0xff
	token := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	response[0x54] = 0
	response[0x55] = byte(len(token))
	copy(response[0x58:], token)
	response[0xa4] = '\r'
	response[0xa5] = '\n'
	return response
}

func TestParseAuthResponseIncludesPaddingAndOpaqueSession(t *testing.T) {
	value, err := parseAuthResponse(syntheticAuthResponse())
	if err != nil {
		t.Fatal(err)
	}
	if value.Session != (SessionID{1, 2, 3, 4}) || len(value.Token) != 44 {
		t.Fatalf("unexpected authentication: %#v", value)
	}
	bad := syntheticAuthResponse()
	bad[0x84] = 1
	if _, err := parseAuthResponse(bad); err == nil {
		t.Fatal("expected non-zero padding rejection")
	}
	layout := syntheticAuthResponse()
	layout[0x38] = 1
	if _, err := parseAuthResponse(layout); err == nil {
		t.Fatal("expected unknown success layout rejection")
	}
}

func TestBuildAuthRequestEscapesValuesAndFormatsMAC(t *testing.T) {
	request, err := buildAuthRequest("192.0.2.1", Identity{Username: "user+domain &x", Password: []byte("p&a ss+%"), MAC: "02:11:22:33:44:55"})
	if err != nil {
		t.Fatal(err)
	}
	text := string(request)
	for _, expected := range []string{"UserName=user%2Bdomain+%26x", "Password=p%26a+ss%2B%25", "MacAddress=0211-2233-4455", "SVN_Seco_AaA=1& HTTP/1.1"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("request missing %q", expected)
		}
	}
	if strings.Contains(text, "p&a ss+%") {
		t.Fatal("raw password appeared in request query")
	}
}
