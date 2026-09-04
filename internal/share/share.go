package share

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/url"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const (
	saltLength = 16
	ivLength   = 12
	iterations = 10000
	keyLength  = 32
)

type profile struct {
	Name              string `json:"name"`
	SSHAddr           string `json:"sshAddr"`
	User              string `json:"user"`
	AuthType          string `json:"authType"`
	TunnelType        string `json:"tunnelType"`
	ProxyAddr         string `json:"proxyAddr"`
	CustomHost        string `json:"customHost"`
	ServerName        string `json:"serverName"`
	CustomPath        string `json:"customPath"`
	EnableCustomPath  bool   `json:"enableCustomPath"`
	ProxyAuthRequired bool   `json:"proxyAuthRequired"`
	ProxyAuthToken    string `json:"proxyAuthToken"`
}

type envelope struct {
	Version int    `json:"v"`
	Gzip    int    `json:"g"`
	Salt    string `json:"s"`
	IV      string `json:"i"`
	Data    string `json:"c"`
}

// Generate creates the encrypted Stun URI and a plaintext protocol URI.
func Generate(transport, host, port, path, target, token, serverName, name, pin string, insecure bool) (stunURI, usedPIN, directURI string, err error) {
	serverAddress := netHostPort(host, port)
	if name == "" {
		name = "H2Tunnel - " + serverAddress
	}
	if target == "" {
		target = "127.0.0.1:22"
	}
	transport = normalizeTransport(transport)
	payload, err := json.Marshal(profile{
		Name:              name,
		SSHAddr:           target,
		User:              "root",
		AuthType:          "password",
		TunnelType:        transport,
		ProxyAddr:         serverAddress,
		CustomHost:        serverName,
		ServerName:        serverName,
		CustomPath:        path,
		EnableCustomPath:  path != "" && path != "/tunnel",
		ProxyAuthRequired: token != "",
		ProxyAuthToken:    token,
	})
	if err != nil {
		return "", "", "", err
	}
	stunURI, usedPIN, err = encrypt(payload, pin)
	if err != nil {
		return "", "", "", err
	}
	u := &url.URL{Scheme: transport, Host: serverAddress, Path: path}
	query := u.Query()
	if target != "127.0.0.1:22" {
		query.Set("target", target)
	}
	if token != "" {
		query.Set("token", token)
	}
	if serverName != "" {
		query.Set("sni", serverName)
	}
	if insecure {
		query.Set("insecure", "1")
	}
	u.RawQuery = query.Encode()
	return stunURI, usedPIN, u.String(), nil
}

func encrypt(plain []byte, pin string) (string, string, error) {
	if pin == "" {
		value, err := rand.Int(rand.Reader, big.NewInt(1000000))
		if err != nil {
			return "", "", err
		}
		pin = fmt.Sprintf("%06d", value.Int64())
	}
	raw := plain
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(plain); err == nil {
		_ = writer.Close()
		if compressed.Len() < len(plain) {
			raw = compressed.Bytes()
		}
	} else {
		_ = writer.Close()
	}
	salt := make([]byte, saltLength)
	iv := make([]byte, ivLength)
	if _, err := rand.Read(salt); err != nil {
		return "", pin, err
	}
	if _, err := rand.Read(iv); err != nil {
		return "", pin, err
	}
	key := pbkdf2.Key([]byte(pin), salt, iterations, keyLength, sha256.New)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", pin, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", pin, err
	}
	encoded, err := json.Marshal(envelope{
		Version: 1,
		Gzip:    boolInt(len(raw) < len(plain)),
		Salt:    base64.StdEncoding.EncodeToString(salt),
		IV:      base64.StdEncoding.EncodeToString(iv),
		Data:    base64.StdEncoding.EncodeToString(gcm.Seal(nil, iv, raw, nil)),
	})
	if err != nil {
		return "", pin, err
	}
	return "stun://" + base64.StdEncoding.EncodeToString(encoded), pin, nil
}

func normalizeTransport(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "h2", "h2c", "h3", "wt", "masque", "grpc":
		return strings.ToLower(strings.TrimSpace(value))
	default:
		return "h2"
	}
}

func netHostPort(host, port string) string {
	if host == "" || host == "0.0.0.0" || host == ":" {
		host = "YOUR_SERVER_IP"
	}
	return host + ":" + port
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
