package h2tunnel

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// generateSelfSignedCert 生成自签名 TLS 证书（供本隧道工具自签场景使用）
func generateSelfSignedCert(customDomain string) (tls.Certificate, string, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("failed to generate ECDSA private key: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("failed to generate serial number: %w", err)
	}

	// 真实公网证书标准：提前 1 天生效，有效期约 390 天 (合规 CA/B Forum 397 天上限)
	notBefore := time.Now().Add(-24 * time.Hour)
	notAfter := notBefore.Add(390 * 24 * time.Hour)

	cn := "localhost"
	if customDomain != "" && customDomain != "tunnel.local" {
		cn = customDomain
	}

	// Use a neutral SAN. Do NOT impersonate third-party domains (e.g. amazonaws.com)
	// — that only invites phishing / MITM confusion; SNI disguise is handled separately
	// via configuration, not the certificate subject.
	dnsNames := []string{cn, "*." + cn}

	pubKeyBytes := elliptic.Marshal(privKey.Curve, privKey.PublicKey.X, privKey.PublicKey.Y)
	skid := sha1.Sum(pubKeyBytes)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Country:            []string{"US"},
			Province:           []string{"Washington"},
			Locality:           []string{"Seattle"},
			Organization:       []string{"h2tunnel"},
			OrganizationalUnit: []string{"Self-Signed"},
			CommonName:         cn,
		},
		Issuer: pkix.Name{
			Country:            []string{"US"},
			Organization:       []string{"h2tunnel"},
			OrganizationalUnit: []string{"Self-Signed"},
			CommonName:         cn,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		SubjectKeyId:          skid[:],
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("failed to create certificate: %w", err)
	}

	// 计算并格式化 SHA-256 指纹 (AA:BB:CC:...)
	sha256Sum := sha256.Sum256(derBytes)
	var fpBuilder strings.Builder
	for i, b := range sha256Sum {
		if i > 0 {
			fpBuilder.WriteString(":")
		}
		fmt.Fprintf(&fpBuilder, "%02X", b)
	}
	fingerprint := fpBuilder.String()

	tlsCert := tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  privKey,
	}

	return tlsCert, fingerprint, nil
}
