package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strings"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// SubjectOptions holds X.509 Distinguished Name fields.
type SubjectOptions struct {
	CommonName         string `json:"commonName"`
	Organization       string `json:"organization"`
	OrganizationalUnit string `json:"organizationalUnit"`
	Country            string `json:"country"`
	State              string `json:"state"`
	Locality           string `json:"locality"`
}

// CertOptions configures generation of a CA, Intermediate CA, Leaf Cert, or CSR.
type CertOptions struct {
	Name           string         `json:"name"`
	Subject        SubjectOptions `json:"subject"`
	KeyAlgorithm   string         `json:"keyAlgorithm"`
	ValidityDays   int            `json:"validityDays"`
	PathLen        int            `json:"pathLen"`
	DNSNames       []string       `json:"dnsNames"`
	IPAddresses    []string       `json:"ipAddresses"`
	EmailAddresses []string       `json:"emailAddresses"`
	URIs           []string       `json:"uris"`
	KeyUsages      []string       `json:"keyUsages"`
	ExtKeyUsages   []string       `json:"extKeyUsages"`
	IssuerID       string         `json:"issuerId"`
}

// CertSummary contains parsed metadata about a certificate or CSR for UI display.
type CertSummary struct {
	CommonName         string         `json:"commonName"`
	Subject            string         `json:"subject"`
	SubjectFields      SubjectOptions `json:"subjectFields"`
	Issuer             string         `json:"issuer"`
	SerialHex          string    `json:"serialHex"`
	NotBefore          time.Time `json:"notBefore"`
	NotAfter           time.Time `json:"notAfter"`
	IsCA               bool      `json:"isCA"`
	PathLen            int       `json:"pathLen"`
	KeyAlgorithm       string    `json:"keyAlgorithm"`
	KeyBits            int       `json:"keyBits"`
	SignatureAlgorithm string    `json:"signatureAlgorithm"`
	DNSNames           []string  `json:"dnsNames"`
	IPAddresses        []string  `json:"ipAddresses"`
	EmailAddresses     []string  `json:"emailAddresses"`
	URIs               []string  `json:"uris"`
	KeyUsages          []string  `json:"keyUsages"`
	ExtKeyUsages       []string  `json:"extKeyUsages"`
	SHA256Fingerprint  string    `json:"sha256Fingerprint"`
	SubjectKeyID       string    `json:"subjectKeyId"`
	AuthorityKeyID     string    `json:"authorityKeyId"`
}

// InspectResult represents the parsed inspection output for a PEM input.
type InspectResult struct {
	Type    string        `json:"type"` // "certificate" or "csr"
	Items   []CertSummary `json:"items"`
	Valid   bool          `json:"valid"`
	Warning string        `json:"warning,omitempty"`
}

func toPkixName(s SubjectOptions) (pkix.Name, error) {
	cn := strings.TrimSpace(s.CommonName)
	if cn == "" {
		return pkix.Name{}, errors.New("Common Name (CN) is required")
	}
	name := pkix.Name{CommonName: cn}
	if v := strings.TrimSpace(s.Organization); v != "" {
		name.Organization = []string{v}
	}
	if v := strings.TrimSpace(s.OrganizationalUnit); v != "" {
		name.OrganizationalUnit = []string{v}
	}
	if v := strings.TrimSpace(s.Country); v != "" {
		if len(v) != 2 {
			return pkix.Name{}, errors.New("Country code must be a 2-letter ISO code (e.g. US)")
		}
		name.Country = []string{strings.ToUpper(v)}
	}
	if v := strings.TrimSpace(s.State); v != "" {
		name.Province = []string{v}
	}
	if v := strings.TrimSpace(s.Locality); v != "" {
		name.Locality = []string{v}
	}
	return name, nil
}

func generateKey(algo string) (crypto.Signer, string, error) {
	var priv crypto.Signer
	var err error

	switch strings.ToUpper(strings.TrimSpace(algo)) {
	case "", "ECDSA-P256":
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "ECDSA-P384":
		priv, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "ED25519":
		_, priv, err = ed25519.GenerateKey(rand.Reader)
	case "RSA-2048":
		priv, err = rsa.GenerateKey(rand.Reader, 2048)
	case "RSA-3072":
		priv, err = rsa.GenerateKey(rand.Reader, 3072)
	case "RSA-4096":
		priv, err = rsa.GenerateKey(rand.Reader, 4096)
	default:
		return nil, "", fmt.Errorf("unsupported key algorithm %q", algo)
	}
	if err != nil {
		return nil, "", fmt.Errorf("generating key: %w", err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, "", fmt.Errorf("marshaling private key: %w", err)
	}
	keyPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}))
	return priv, keyPEM, nil
}

func parsePrivateKeyPEM(keyPEM string) (crypto.Signer, error) {
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return nil, errors.New("failed to decode private key PEM")
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		signer, ok := k.(crypto.Signer)
		if !ok {
			return nil, errors.New("parsed key does not implement crypto.Signer")
		}
		return signer, nil
	}
	if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	return nil, errors.New("unsupported private key format")
}

func parseCertPEM(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("failed to decode certificate PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, err
	}
	if serial.Sign() <= 0 {
		serial.SetInt64(1)
	}
	return serial, nil
}

func computeSKI(pub crypto.PublicKey) ([]byte, error) {
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	h := sha1.Sum(spki)
	return h[:], nil
}

func parseSANs(dns []string, ips []string, emails []string, uris []string) ([]string, []net.IP, []string, []*url.URL, error) {
	var outDNS []string
	for _, d := range dns {
		d = strings.TrimSpace(d)
		if d != "" {
			outDNS = append(outDNS, d)
		}
	}

	var outIPs []net.IP
	for _, raw := range ips {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		ip := net.ParseIP(raw)
		if ip == nil {
			return nil, nil, nil, nil, fmt.Errorf("invalid IP address %q", raw)
		}
		outIPs = append(outIPs, ip)
	}

	var outEmails []string
	for _, e := range emails {
		e = strings.TrimSpace(e)
		if e != "" {
			outEmails = append(outEmails, e)
		}
	}

	var outURIs []*url.URL
	for _, raw := range uris {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil || u.Scheme == "" {
			return nil, nil, nil, nil, fmt.Errorf("invalid URI %q", raw)
		}
		outURIs = append(outURIs, u)
	}

	return outDNS, outIPs, outEmails, outURIs, nil
}

func parseKeyUsage(usages []string, isCA bool) x509.KeyUsage {
	if isCA {
		return x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature
	}
	var ku x509.KeyUsage
	for _, u := range usages {
		switch strings.ToLower(strings.TrimSpace(u)) {
		case "digitalsignature":
			ku |= x509.KeyUsageDigitalSignature
		case "keyencipherment":
			ku |= x509.KeyUsageKeyEncipherment
		case "contentcommitment", "nonrepudiation":
			ku |= x509.KeyUsageContentCommitment
		case "keyagreement":
			ku |= x509.KeyUsageKeyAgreement
		case "dataencipherment":
			ku |= x509.KeyUsageDataEncipherment
		}
	}
	if ku == 0 {
		ku = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	}
	return ku
}

func parseExtKeyUsage(usages []string) []x509.ExtKeyUsage {
	var ekus []x509.ExtKeyUsage
	for _, u := range usages {
		switch strings.ToLower(strings.TrimSpace(u)) {
		case "serverauth":
			ekus = append(ekus, x509.ExtKeyUsageServerAuth)
		case "clientauth":
			ekus = append(ekus, x509.ExtKeyUsageClientAuth)
		case "codesigning":
			ekus = append(ekus, x509.ExtKeyUsageCodeSigning)
		case "emailprotection":
			ekus = append(ekus, x509.ExtKeyUsageEmailProtection)
		case "ocspsigning":
			ekus = append(ekus, x509.ExtKeyUsageOCSPSigning)
		case "timestamping":
			ekus = append(ekus, x509.ExtKeyUsageTimeStamping)
		}
	}
	return ekus
}

func keyInfo(pub crypto.PublicKey) (string, int) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return "RSA", k.N.BitLen()
	case *ecdsa.PublicKey:
		return "ECDSA", k.Curve.Params().BitSize
	case ed25519.PublicKey:
		return "Ed25519", 256
	default:
		return "Unknown", 0
	}
}

func formatKeyUsages(ku x509.KeyUsage) []string {
	var out []string
	if ku&x509.KeyUsageDigitalSignature != 0 {
		out = append(out, "Digital Signature")
	}
	if ku&x509.KeyUsageContentCommitment != 0 {
		out = append(out, "Content Commitment")
	}
	if ku&x509.KeyUsageKeyEncipherment != 0 {
		out = append(out, "Key Encipherment")
	}
	if ku&x509.KeyUsageDataEncipherment != 0 {
		out = append(out, "Data Encipherment")
	}
	if ku&x509.KeyUsageKeyAgreement != 0 {
		out = append(out, "Key Agreement")
	}
	if ku&x509.KeyUsageCertSign != 0 {
		out = append(out, "Certificate Sign")
	}
	if ku&x509.KeyUsageCRLSign != 0 {
		out = append(out, "CRL Sign")
	}
	return out
}

func formatExtKeyUsages(ekus []x509.ExtKeyUsage) []string {
	var out []string
	for _, e := range ekus {
		switch e {
		case x509.ExtKeyUsageServerAuth:
			out = append(out, "Server Auth")
		case x509.ExtKeyUsageClientAuth:
			out = append(out, "Client Auth")
		case x509.ExtKeyUsageCodeSigning:
			out = append(out, "Code Signing")
		case x509.ExtKeyUsageEmailProtection:
			out = append(out, "Email Protection")
		case x509.ExtKeyUsageOCSPSigning:
			out = append(out, "OCSP Signing")
		case x509.ExtKeyUsageTimeStamping:
			out = append(out, "Time Stamping")
		}
	}
	return out
}

func formatColonHex(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = fmt.Sprintf("%02X", v)
	}
	return strings.Join(parts, ":")
}

func firstOrEmpty(s []string) string {
	if len(s) > 0 {
		return s[0]
	}
	return ""
}

func subjectOptionsFromPkix(n pkix.Name) SubjectOptions {
	return SubjectOptions{
		CommonName:         n.CommonName,
		Organization:       firstOrEmpty(n.Organization),
		OrganizationalUnit: firstOrEmpty(n.OrganizationalUnit),
		Country:            firstOrEmpty(n.Country),
		State:              firstOrEmpty(n.Province),
		Locality:           firstOrEmpty(n.Locality),
	}
}

// SummarizeCertificate extracts a CertSummary from an *x509.Certificate.
func SummarizeCertificate(cert *x509.Certificate) CertSummary {
	alg, bits := keyInfo(cert.PublicKey)
	fp := sha256.Sum256(cert.Raw)
	ips := make([]string, len(cert.IPAddresses))
	for i, ip := range cert.IPAddresses {
		ips[i] = ip.String()
	}
	uris := make([]string, len(cert.URIs))
	for i, u := range cert.URIs {
		uris[i] = u.String()
	}
	pathLen := -1
	if cert.IsCA && (cert.MaxPathLen > 0 || cert.MaxPathLenZero) {
		pathLen = cert.MaxPathLen
	}
	return CertSummary{
		CommonName:         cert.Subject.CommonName,
		Subject:            cert.Subject.String(),
		SubjectFields:      subjectOptionsFromPkix(cert.Subject),
		Issuer:             cert.Issuer.String(),
		SerialHex:          strings.ToUpper(hex.EncodeToString(cert.SerialNumber.Bytes())),
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		IsCA:               cert.IsCA,
		PathLen:            pathLen,
		KeyAlgorithm:       alg,
		KeyBits:            bits,
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		DNSNames:           cert.DNSNames,
		IPAddresses:        ips,
		EmailAddresses:     cert.EmailAddresses,
		URIs:               uris,
		KeyUsages:          formatKeyUsages(cert.KeyUsage),
		ExtKeyUsages:       formatExtKeyUsageList(cert.ExtKeyUsage),
		SHA256Fingerprint:  formatColonHex(fp[:]),
		SubjectKeyID:       formatColonHex(cert.SubjectKeyId),
		AuthorityKeyID:     formatColonHex(cert.AuthorityKeyId),
	}
}

func formatExtKeyUsageList(ekus []x509.ExtKeyUsage) []string {
	return formatExtKeyUsages(ekus)
}

// SummarizeCSR extracts a CertSummary from an *x509.CertificateRequest.
func SummarizeCSR(csr *x509.CertificateRequest) CertSummary {
	alg, bits := keyInfo(csr.PublicKey)
	fp := sha256.Sum256(csr.Raw)
	ips := make([]string, len(csr.IPAddresses))
	for i, ip := range csr.IPAddresses {
		ips[i] = ip.String()
	}
	uris := make([]string, len(csr.URIs))
	for i, u := range csr.URIs {
		uris[i] = u.String()
	}
	return CertSummary{
		CommonName:         csr.Subject.CommonName,
		Subject:            csr.Subject.String(),
		SubjectFields:      subjectOptionsFromPkix(csr.Subject),
		KeyAlgorithm:       alg,
		KeyBits:            bits,
		SignatureAlgorithm: csr.SignatureAlgorithm.String(),
		DNSNames:           csr.DNSNames,
		IPAddresses:        ips,
		EmailAddresses:     csr.EmailAddresses,
		URIs:               uris,
		SHA256Fingerprint:  formatColonHex(fp[:]),
	}
}

// GenerateRootCA creates a self-signed Root CA certificate and private key.
func GenerateRootCA(opts CertOptions) (string, string, CertSummary, error) {
	subject, err := toPkixName(opts.Subject)
	if err != nil {
		return "", "", CertSummary{}, err
	}
	if opts.ValidityDays <= 0 {
		opts.ValidityDays = 3650
	}

	priv, keyPEM, err := generateKey(opts.KeyAlgorithm)
	if err != nil {
		return "", "", CertSummary{}, err
	}
	serial, err := randomSerial()
	if err != nil {
		return "", "", CertSummary{}, err
	}
	ski, err := computeSKI(priv.Public())
	if err != nil {
		return "", "", CertSummary{}, err
	}

	now := time.Now().UTC().Add(-5 * time.Minute)
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		NotBefore:             now,
		NotAfter:              now.AddDate(0, 0, opts.ValidityDays),
		KeyUsage:              parseKeyUsage(nil, true),
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          ski,
		AuthorityKeyId:        ski,
	}
	if opts.PathLen >= 0 {
		tmpl.MaxPathLen = opts.PathLen
		tmpl.MaxPathLenZero = opts.PathLen == 0
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	if err != nil {
		return "", "", CertSummary{}, fmt.Errorf("creating Root CA: %w", err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return "", "", CertSummary{}, err
	}
	return certPEM, keyPEM, SummarizeCertificate(cert), nil
}

// GenerateIntermediateCA creates an Intermediate CA signed by the given issuer CA.
func GenerateIntermediateCA(opts CertOptions, issuerCertPEM, issuerKeyPEM string) (string, string, CertSummary, error) {
	issuerCert, err := parseCertPEM(issuerCertPEM)
	if err != nil {
		return "", "", CertSummary{}, fmt.Errorf("parsing issuer cert: %w", err)
	}
	if !issuerCert.IsCA {
		return "", "", CertSummary{}, errors.New("selected issuer is not a Certificate Authority")
	}
	issuerKey, err := parsePrivateKeyPEM(issuerKeyPEM)
	if err != nil {
		return "", "", CertSummary{}, fmt.Errorf("parsing issuer key: %w", err)
	}

	subject, err := toPkixName(opts.Subject)
	if err != nil {
		return "", "", CertSummary{}, err
	}
	if opts.ValidityDays <= 0 {
		opts.ValidityDays = 1825
	}

	priv, keyPEM, err := generateKey(opts.KeyAlgorithm)
	if err != nil {
		return "", "", CertSummary{}, err
	}
	serial, err := randomSerial()
	if err != nil {
		return "", "", CertSummary{}, err
	}
	ski, err := computeSKI(priv.Public())
	if err != nil {
		return "", "", CertSummary{}, err
	}

	now := time.Now().UTC().Add(-5 * time.Minute)
	notAfter := now.AddDate(0, 0, opts.ValidityDays)
	if notAfter.After(issuerCert.NotAfter) {
		notAfter = issuerCert.NotAfter
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		NotBefore:             now,
		NotAfter:              notAfter,
		KeyUsage:              parseKeyUsage(nil, true),
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          ski,
		AuthorityKeyId:        issuerCert.SubjectKeyId,
	}
	if opts.PathLen >= 0 {
		tmpl.MaxPathLen = opts.PathLen
		tmpl.MaxPathLenZero = opts.PathLen == 0
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuerCert, priv.Public(), issuerKey)
	if err != nil {
		return "", "", CertSummary{}, fmt.Errorf("creating Intermediate CA: %w", err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return "", "", CertSummary{}, err
	}
	return certPEM, keyPEM, SummarizeCertificate(cert), nil
}

// GenerateLeafCert issues an end-entity TLS certificate signed by the given issuer CA.
func GenerateLeafCert(opts CertOptions, issuerCertPEM, issuerKeyPEM string) (string, string, CertSummary, error) {
	issuerCert, err := parseCertPEM(issuerCertPEM)
	if err != nil {
		return "", "", CertSummary{}, fmt.Errorf("parsing issuer cert: %w", err)
	}
	if !issuerCert.IsCA {
		return "", "", CertSummary{}, errors.New("selected issuer is not a Certificate Authority")
	}
	issuerKey, err := parsePrivateKeyPEM(issuerKeyPEM)
	if err != nil {
		return "", "", CertSummary{}, fmt.Errorf("parsing issuer key: %w", err)
	}

	subject, err := toPkixName(opts.Subject)
	if err != nil {
		return "", "", CertSummary{}, err
	}
	dns, ips, emails, uris, err := parseSANs(opts.DNSNames, opts.IPAddresses, opts.EmailAddresses, opts.URIs)
	if err != nil {
		return "", "", CertSummary{}, err
	}
	if opts.ValidityDays <= 0 {
		opts.ValidityDays = 365
	}

	priv, keyPEM, err := generateKey(opts.KeyAlgorithm)
	if err != nil {
		return "", "", CertSummary{}, err
	}
	serial, err := randomSerial()
	if err != nil {
		return "", "", CertSummary{}, err
	}
	ski, err := computeSKI(priv.Public())
	if err != nil {
		return "", "", CertSummary{}, err
	}

	ekus := parseExtKeyUsage(opts.ExtKeyUsages)
	if len(ekus) == 0 {
		ekus = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}

	now := time.Now().UTC().Add(-5 * time.Minute)
	notAfter := now.AddDate(0, 0, opts.ValidityDays)
	if notAfter.After(issuerCert.NotAfter) {
		notAfter = issuerCert.NotAfter
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		NotBefore:             now,
		NotAfter:              notAfter,
		KeyUsage:              parseKeyUsage(opts.KeyUsages, false),
		ExtKeyUsage:           ekus,
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              dns,
		IPAddresses:           ips,
		EmailAddresses:        emails,
		URIs:                  uris,
		SubjectKeyId:          ski,
		AuthorityKeyId:        issuerCert.SubjectKeyId,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuerCert, priv.Public(), issuerKey)
	if err != nil {
		return "", "", CertSummary{}, fmt.Errorf("creating certificate: %w", err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return "", "", CertSummary{}, err
	}
	return certPEM, keyPEM, SummarizeCertificate(cert), nil
}

// GenerateCSR creates a PKCS#10 Certificate Signing Request and its private key.
func GenerateCSR(opts CertOptions) (string, string, CertSummary, error) {
	subject, err := toPkixName(opts.Subject)
	if err != nil {
		return "", "", CertSummary{}, err
	}
	dns, ips, emails, uris, err := parseSANs(opts.DNSNames, opts.IPAddresses, opts.EmailAddresses, opts.URIs)
	if err != nil {
		return "", "", CertSummary{}, err
	}
	priv, keyPEM, err := generateKey(opts.KeyAlgorithm)
	if err != nil {
		return "", "", CertSummary{}, err
	}

	tmpl := &x509.CertificateRequest{
		Subject:        subject,
		DNSNames:       dns,
		IPAddresses:    ips,
		EmailAddresses: emails,
		URIs:           uris,
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, priv)
	if err != nil {
		return "", "", CertSummary{}, fmt.Errorf("creating CSR: %w", err)
	}
	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return "", "", CertSummary{}, err
	}
	return csrPEM, keyPEM, SummarizeCSR(csr), nil
}

// SignCSR validates a PKCS#10 CSR and signs a certificate with the given issuer CA.
func SignCSR(csrPEM, issuerCertPEM, issuerKeyPEM string, validityDays int, isCA bool, pathLen int, keyUsages, extKeyUsages []string) (string, CertSummary, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil || (block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST") {
		return "", CertSummary{}, errors.New("failed to decode CSR PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return "", CertSummary{}, fmt.Errorf("parsing CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return "", CertSummary{}, fmt.Errorf("invalid CSR signature: %w", err)
	}

	issuerCert, err := parseCertPEM(issuerCertPEM)
	if err != nil {
		return "", CertSummary{}, fmt.Errorf("parsing issuer cert: %w", err)
	}
	if !issuerCert.IsCA {
		return "", CertSummary{}, errors.New("selected issuer is not a Certificate Authority")
	}
	issuerKey, err := parsePrivateKeyPEM(issuerKeyPEM)
	if err != nil {
		return "", CertSummary{}, fmt.Errorf("parsing issuer key: %w", err)
	}

	if validityDays <= 0 {
		validityDays = 365
	}
	serial, err := randomSerial()
	if err != nil {
		return "", CertSummary{}, err
	}
	ski, err := computeSKI(csr.PublicKey)
	if err != nil {
		return "", CertSummary{}, err
	}

	now := time.Now().UTC().Add(-5 * time.Minute)
	notAfter := now.AddDate(0, 0, validityDays)
	if notAfter.After(issuerCert.NotAfter) {
		notAfter = issuerCert.NotAfter
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               csr.Subject,
		NotBefore:             now,
		NotAfter:              notAfter,
		KeyUsage:              parseKeyUsage(keyUsages, isCA),
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		DNSNames:              csr.DNSNames,
		IPAddresses:           csr.IPAddresses,
		EmailAddresses:        csr.EmailAddresses,
		URIs:                  csr.URIs,
		SubjectKeyId:          ski,
		AuthorityKeyId:        issuerCert.SubjectKeyId,
	}
	if isCA && pathLen >= 0 {
		tmpl.MaxPathLen = pathLen
		tmpl.MaxPathLenZero = pathLen == 0
	}
	if !isCA {
		ekus := parseExtKeyUsage(extKeyUsages)
		if len(ekus) == 0 {
			ekus = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		}
		tmpl.ExtKeyUsage = ekus
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuerCert, csr.PublicKey, issuerKey)
	if err != nil {
		return "", CertSummary{}, fmt.Errorf("signing CSR: %w", err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return "", CertSummary{}, err
	}
	return certPEM, SummarizeCertificate(cert), nil
}

// InspectPEM parses one or more certificates or a CSR from PEM text.
func InspectPEM(pemText string) (InspectResult, error) {
	rest := []byte(strings.TrimSpace(pemText))
	if len(rest) == 0 {
		return InspectResult{}, errors.New("PEM input is empty")
	}

	var certs []CertSummary
	var csrs []CertSummary
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch block.Type {
		case "CERTIFICATE":
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return InspectResult{}, fmt.Errorf("parsing certificate: %w", err)
			}
			certs = append(certs, SummarizeCertificate(cert))
		case "CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST":
			csr, err := x509.ParseCertificateRequest(block.Bytes)
			if err != nil {
				return InspectResult{}, fmt.Errorf("parsing CSR: %w", err)
			}
			if err := csr.CheckSignature(); err != nil {
				return InspectResult{
					Type:    "csr",
					Items:   []CertSummary{SummarizeCSR(csr)},
					Valid:   false,
					Warning: "CSR signature verification failed: " + err.Error(),
				}, nil
			}
			csrs = append(csrs, SummarizeCSR(csr))
		}
	}

	if len(certs) > 0 {
		return InspectResult{Type: "certificate", Items: certs, Valid: true}, nil
	}
	if len(csrs) > 0 {
		return InspectResult{Type: "csr", Items: csrs, Valid: true}, nil
	}
	return InspectResult{}, errors.New("no valid X.509 certificate or CSR found in PEM input")
}

// VerifyAgainstCAs verifies a leaf certificate PEM against root and intermediate CA PEMs.
func VerifyAgainstCAs(certPEM string, rootsPEM, intermediatesPEM []string) (bool, string) {
	cert, err := parseCertPEM(certPEM)
	if err != nil {
		return false, err.Error()
	}
	roots := x509.NewCertPool()
	for _, r := range rootsPEM {
		roots.AppendCertsFromPEM([]byte(r))
	}
	inters := x509.NewCertPool()
	for _, i := range intermediatesPEM {
		inters.AppendCertsFromPEM([]byte(i))
	}
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inters,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	chains, err := cert.Verify(opts)
	if err != nil {
		return false, err.Error()
	}
	return true, fmt.Sprintf("Verified (%d valid trust chain)", len(chains))
}

// ExportPKCS12 bundles a certificate, its private key, and optional CA chain into a .p12/.pfx archive.
func ExportPKCS12(certPEM, keyPEM string, caCertsPEM []string, password string) ([]byte, error) {
	cert, err := parseCertPEM(certPEM)
	if err != nil {
		return nil, err
	}
	priv, err := parsePrivateKeyPEM(keyPEM)
	if err != nil {
		return nil, err
	}
	var cas []*x509.Certificate
	for _, pemStr := range caCertsPEM {
		ca, err := parseCertPEM(pemStr)
		if err != nil {
			return nil, fmt.Errorf("parsing CA cert for PKCS#12: %w", err)
		}
		cas = append(cas, ca)
	}
	return pkcs12.Modern.Encode(priv, cert, cas, password)
}
