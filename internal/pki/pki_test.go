package pki

import (
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"
)

func TestFullPKIChainAndVerify(t *testing.T) {
	rootPEM, rootKey, rootSum, err := GenerateRootCA(CertOptions{
		Subject: SubjectOptions{
			CommonName:   "LabCert Test Root CA",
			Organization: "Homelab",
			Country:      "US",
		},
		KeyAlgorithm: "ECDSA-P384",
		ValidityDays: 3650,
		PathLen:      1,
	})
	if err != nil {
		t.Fatalf("GenerateRootCA failed: %v", err)
	}
	if !rootSum.IsCA || rootSum.KeyAlgorithm != "ECDSA" || rootSum.KeyBits != 384 {
		t.Fatalf("unexpected root summary: %+v", rootSum)
	}

	interPEM, interKey, interSum, err := GenerateIntermediateCA(CertOptions{
		Subject: SubjectOptions{
			CommonName:   "LabCert Test Intermediate CA",
			Organization: "Homelab",
		},
		KeyAlgorithm: "ECDSA-P256",
		ValidityDays: 1825,
		PathLen:      0,
	}, rootPEM, rootKey)
	if err != nil {
		t.Fatalf("GenerateIntermediateCA failed: %v", err)
	}
	if !interSum.IsCA || interSum.PathLen != 0 {
		t.Fatalf("unexpected intermediate summary: %+v", interSum)
	}

	leafPEM, leafKey, leafSum, err := GenerateLeafCert(CertOptions{
		Subject: SubjectOptions{
			CommonName:   "proxmox.home.arpa",
			Organization: "Homelab",
		},
		KeyAlgorithm: "RSA-2048",
		ValidityDays: 365,
		DNSNames:     []string{"proxmox.home.arpa", "*.proxmox.home.arpa"},
		IPAddresses:  []string{"192.168.1.10"},
		KeyUsages:    []string{"digitalSignature", "keyEncipherment"},
		ExtKeyUsages: []string{"serverAuth", "clientAuth"},
	}, interPEM, interKey)
	if err != nil {
		t.Fatalf("GenerateLeafCert failed: %v", err)
	}
	if leafSum.IsCA || len(leafSum.DNSNames) != 2 || len(leafSum.IPAddresses) != 1 {
		t.Fatalf("unexpected leaf summary: %+v", leafSum)
	}

	ok, msg := VerifyAgainstCAs(leafPEM, []string{rootPEM}, []string{interPEM})
	if !ok {
		t.Fatalf("expected leaf cert to verify against chain, got: %s", msg)
	}

	p12, err := ExportPKCS12(leafPEM, leafKey, []string{interPEM, rootPEM}, "secret123")
	if err != nil || len(p12) == 0 {
		t.Fatalf("ExportPKCS12 failed: %v", err)
	}
}

func TestCSRGenerateSignAndInspect(t *testing.T) {
	rootPEM, rootKey, _, err := GenerateRootCA(CertOptions{
		Subject:      SubjectOptions{CommonName: "Root CA"},
		KeyAlgorithm: "Ed25519",
		ValidityDays: 365,
		PathLen:      1,
	})
	if err != nil {
		t.Fatalf("GenerateRootCA failed: %v", err)
	}

	csrPEM, _, csrSum, err := GenerateCSR(CertOptions{
		Subject:      SubjectOptions{CommonName: "nas.home.arpa"},
		KeyAlgorithm: "ECDSA-P256",
		DNSNames:     []string{"nas.home.arpa"},
		IPAddresses:  []string{"10.0.0.5"},
	})
	if err != nil {
		t.Fatalf("GenerateCSR failed: %v", err)
	}
	if csrSum.CommonName != "nas.home.arpa" {
		t.Fatalf("unexpected CSR CN: %s", csrSum.CommonName)
	}

	inspCSR, err := InspectPEM(csrPEM)
	if err != nil || inspCSR.Type != "csr" || !inspCSR.Valid {
		t.Fatalf("InspectPEM(csr) failed: %+v, err=%v", inspCSR, err)
	}

	signedPEM, _, err := SignCSR(csrPEM, rootPEM, rootKey, 90, false, -1, nil, []string{"serverAuth"})
	if err != nil {
		t.Fatalf("SignCSR failed: %v", err)
	}

	inspCert, err := InspectPEM(signedPEM)
	if err != nil || inspCert.Type != "certificate" || len(inspCert.Items) != 1 {
		t.Fatalf("InspectPEM(cert) failed: %+v, err=%v", inspCert, err)
	}

	ok, msg := VerifyAgainstCAs(signedPEM, []string{rootPEM}, nil)
	if !ok {
		t.Fatalf("signed CSR cert failed verification: %s", msg)
	}
}

func TestValidationErrors(t *testing.T) {
	if _, _, _, err := GenerateRootCA(CertOptions{Subject: SubjectOptions{CommonName: ""}}); err == nil {
		t.Fatal("expected error for empty CommonName")
	}
	if _, _, _, err := GenerateRootCA(CertOptions{Subject: SubjectOptions{CommonName: "Test", Country: "USA"}}); err == nil {
		t.Fatal("expected error for 3-letter country code")
	}
	rootPEM, rootKey, _, err := GenerateRootCA(CertOptions{Subject: SubjectOptions{CommonName: "CA"}, PathLen: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := GenerateLeafCert(CertOptions{
		Subject:     SubjectOptions{CommonName: "bad.local"},
		IPAddresses: []string{"not-an-ip"},
	}, rootPEM, rootKey); err == nil {
		t.Fatal("expected error for invalid IP SAN")
	}
}

func TestSecurityHardeningPKI(t *testing.T) {
	rootPEM, rootKey, _, err := GenerateRootCA(CertOptions{
		Subject:      SubjectOptions{CommonName: "Hardening Root CA"},
		KeyAlgorithm: "ECDSA-P256",
		ValidityDays: 365,
		PathLen:      1,
	})
	if err != nil {
		t.Fatal(err)
	}

	// #11: ECDSA leaf cert should NOT receive KeyEncipherment even if requested
	leafPEM, leafKey, leafSum, err := GenerateLeafCert(CertOptions{
		Subject:      SubjectOptions{CommonName: "ecdsa.home.arpa"},
		KeyAlgorithm: "ECDSA-P256",
		ValidityDays: 397,
		KeyUsages:    []string{"digitalSignature", "keyEncipherment"},
		ExtKeyUsages: []string{"serverAuth"},
	}, rootPEM, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, ku := range leafSum.KeyUsages {
		if ku == "Key Encipherment" {
			t.Fatal("ECDSA leaf certificate should not include Key Encipherment")
		}
	}

	// #7: PKCS#12 rejects empty or short password
	if _, err := ExportPKCS12(leafPEM, leafKey, []string{rootPEM}, ""); err == nil {
		t.Fatal("expected ExportPKCS12 to reject empty password")
	}
	if _, err := ExportPKCS12(leafPEM, leafKey, []string{rootPEM}, "short"); err == nil {
		t.Fatal("expected ExportPKCS12 to reject <8 char password")
	}

	// #11: CRL generation includes revoked leaf certificate
	crlPEM, err := GenerateCRL(rootPEM, rootKey, []RevokedEntry{
		{CertPEM: leafPEM, RevokedAt: time.Now().UTC(), Reason: 1},
	}, 30)
	if err != nil {
		t.Fatalf("GenerateCRL failed: %v", err)
	}
	block, _ := pem.Decode([]byte(crlPEM))
	if block == nil || block.Type != "X509 CRL" {
		t.Fatal("expected valid X509 CRL PEM block")
	}
	rl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil || len(rl.RevokedCertificateEntries) != 1 {
		t.Fatalf("expected 1 revoked entry in CRL, got err=%v len=%d", err, len(rl.RevokedCertificateEntries))
	}

	// #12: InspectPEM enforces 1 MiB limit
	huge := strings.Repeat("A", MaxPEMInputBytes+10)
	if _, err := InspectPEM(huge); err == nil {
		t.Fatal("expected InspectPEM to reject input > 1 MiB")
	}
}
