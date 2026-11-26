package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"LabCert/internal/pki"
	"LabCert/internal/vault"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// App is the Wails application backend bound to the frontend.
type App struct {
	ctx   context.Context
	vault *vault.Manager
}

// NewApp creates a new App instance.
func NewApp() *App {
	return &App{
		vault: vault.NewManager(),
	}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

// VaultStatus describes the current state of the encrypted vault.
type VaultStatus struct {
	Unlocked bool   `json:"unlocked"`
	Exists   bool   `json:"exists"`
	Path     string `json:"path"`
}

// ItemPEMs holds public PEM representations of a vault item.
type ItemPEMs struct {
	CertPEM      string `json:"certPem"`
	FullChainPEM string `json:"fullChainPem"`
	CSRPEM       string `json:"csrPem"`
	HasKey       bool   `json:"hasKey"`
}

// SignCSRRequest configures signing an external or stored CSR.
type SignCSRRequest struct {
	Name         string   `json:"name"`
	CSRPEM       string   `json:"csrPem"`
	IssuerID     string   `json:"issuerId"`
	ValidityDays int      `json:"validityDays"`
	IsCA         bool     `json:"isCA"`
	PathLen      int      `json:"pathLen"`
	KeyUsages    []string `json:"keyUsages"`
	ExtKeyUsages []string `json:"extKeyUsages"`
	StoredCSRID  string   `json:"storedCsrId"`
}

// VerifyResult represents trust chain verification against vault CAs.
type VerifyResult struct {
	Valid   bool   `json:"valid"`
	Message string `json:"message"`
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

type appConfig struct {
	LastVaultPath string `json:"lastVaultPath"`
}

func configFilePath() (string, error) {
	cfgDir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(cfgDir, "LabCert", "config.json"), nil
}

func loadLastVaultPath() string {
	p, err := configFilePath()
	if err != nil {
		return ""
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	var cfg appConfig
	if err := json.Unmarshal(b, &cfg); err != nil {
		return ""
	}
	return strings.TrimSpace(cfg.LastVaultPath)
}

func saveLastVaultPath(vaultPath string) {
	p, err := configFilePath()
	if err != nil || strings.TrimSpace(vaultPath) == "" {
		return
	}
	_ = os.MkdirAll(filepath.Dir(p), 0700)
	b, err := json.MarshalIndent(appConfig{LastVaultPath: vaultPath}, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(p, b, 0600)
}

func (a *App) resolvePath(path string) (string, error) {
	if strings.TrimSpace(path) != "" {
		return path, nil
	}
	if p := a.vault.Path(); p != "" {
		return p, nil
	}
	if last := loadLastVaultPath(); last != "" {
		return last, nil
	}
	return vault.DefaultVaultPath()
}

// CheckVaultPath reports whether a vault file exists at the given path.
func (a *App) CheckVaultPath(path string) bool {
	return vault.VaultExists(strings.TrimSpace(path))
}

// GetVaultStatus returns the current vault lock state and file path.
func (a *App) GetVaultStatus() (VaultStatus, error) {
	p, err := a.resolvePath("")
	if err != nil {
		return VaultStatus{}, err
	}
	return VaultStatus{
		Unlocked: a.vault.IsUnlocked(),
		Exists:   vault.VaultExists(p),
		Path:     p,
	}, nil
}

// CreateVault creates a new password-encrypted vault.
func (a *App) CreateVault(path, password string) error {
	p, err := a.resolvePath(path)
	if err != nil {
		return err
	}
	if err := a.vault.CreateVault(p, password); err != nil {
		return err
	}
	saveLastVaultPath(p)
	return nil
}

// UnlockVault decrypts an existing vault with the user's password.
func (a *App) UnlockVault(path, password string) error {
	p, err := a.resolvePath(path)
	if err != nil {
		return err
	}
	if err := a.vault.Unlock(p, password); err != nil {
		return err
	}
	saveLastVaultPath(p)
	return nil
}

// LockVault locks the vault and clears decrypted keys from memory.
func (a *App) LockVault() {
	a.vault.Lock()
}

// VerifyMasterPassword checks whether password matches the unlocked vault's master password.
func (a *App) VerifyMasterPassword(password string) error {
	return a.vault.VerifyPassword(password)
}

// ChangeVaultPassword verifies currentPassword and re-encrypts the unlocked vault with newPassword.
func (a *App) ChangeVaultPassword(currentPassword, newPassword string) error {
	return a.vault.ChangePassword(currentPassword, newPassword)
}

// ExportVaultBackup saves an encrypted copy of the current vault file via native dialog.
func (a *App) ExportVaultBackup() (string, error) {
	if a.ctx == nil {
		return "", errors.New("application context not initialized")
	}
	if !a.vault.IsUnlocked() {
		return "", errors.New("vault is locked")
	}
	srcPath := a.vault.Path()
	raw, err := os.ReadFile(srcPath)
	if err != nil {
		return "", fmt.Errorf("reading vault for backup: %w", err)
	}
	defaultName := fmt.Sprintf("labcert-backup-%s.labcert", time.Now().Format("2006-01-02"))
	target, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
		Title:           "Export Encrypted Vault Backup",
		DefaultFilename: defaultName,
		Filters:         []runtime.FileFilter{{DisplayName: "LabCert Vault (*.labcert)", Pattern: "*.labcert"}},
	})
	if err != nil || target == "" {
		return "", err
	}
	if err := os.WriteFile(target, raw, 0600); err != nil {
		return "", err
	}
	return target, nil
}

// ChooseVaultFile opens a native file dialog to select or create a .labcert vault file.
func (a *App) ChooseVaultFile(createNew bool) (string, error) {
	if a.ctx == nil {
		return "", errors.New("application context not initialized")
	}
	filters := []runtime.FileFilter{{DisplayName: "LabCert Vault (*.labcert)", Pattern: "*.labcert"}}
	if createNew {
		return runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
			Title:           "Create New LabCert Vault",
			DefaultFilename: "vault.labcert",
			Filters:         filters,
		})
	}
	return runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title:   "Open LabCert Vault",
		Filters: filters,
	})
}

// ListItems returns all stored PKI items (without private keys).
func (a *App) ListItems() ([]vault.VaultItemSummary, error) {
	return a.vault.ListSummaries()
}

func summarizeToVaultSummary(it vault.VaultItem) vault.VaultItemSummary {
	return vault.VaultItemSummary{
		ID:           it.ID,
		Kind:         it.Kind,
		Name:         it.Name,
		IssuerID:     it.IssuerID,
		CreatedAt:    it.CreatedAt,
		HasKey:       it.KeyPEM != "",
		HasCert:      it.CertPEM != "",
		HasCSR:       it.CSRPEM != "",
		Revoked:      it.Revoked,
		RevokedAt:    it.RevokedAt,
		RevokeReason: it.RevokeReason,
		Summary:      it.Summary,
	}
}

// CreateRootCA generates a self-signed Root CA and stores it in the encrypted vault.
func (a *App) CreateRootCA(opts pki.CertOptions) (vault.VaultItemSummary, error) {
	if !a.vault.IsUnlocked() {
		return vault.VaultItemSummary{}, errors.New("vault is locked")
	}
	certPEM, keyPEM, summary, err := pki.GenerateRootCA(opts)
	if err != nil {
		return vault.VaultItemSummary{}, err
	}
	name := strings.TrimSpace(opts.Name)
	if name == "" {
		name = summary.CommonName
	}
	item := vault.VaultItem{
		ID:        newID(),
		Kind:      vault.KindRootCA,
		Name:      name,
		CreatedAt: time.Now().UTC(),
		CertPEM:   certPEM,
		KeyPEM:    keyPEM,
		Summary:   summary,
	}
	if err := a.vault.AddItem(item); err != nil {
		return vault.VaultItemSummary{}, err
	}
	return summarizeToVaultSummary(item), nil
}

// CreateIntermediateCA generates an Intermediate CA signed by an existing CA in the vault.
func (a *App) CreateIntermediateCA(opts pki.CertOptions) (vault.VaultItemSummary, error) {
	if !a.vault.IsUnlocked() {
		return vault.VaultItemSummary{}, errors.New("vault is locked")
	}
	issuer, err := a.vault.GetItem(opts.IssuerID)
	if err != nil {
		return vault.VaultItemSummary{}, fmt.Errorf("loading issuer CA: %w", err)
	}
	if issuer.KeyPEM == "" || issuer.CertPEM == "" {
		return vault.VaultItemSummary{}, errors.New("selected issuer does not have both a certificate and private key")
	}
	certPEM, keyPEM, summary, err := pki.GenerateIntermediateCA(opts, issuer.CertPEM, issuer.KeyPEM)
	if err != nil {
		return vault.VaultItemSummary{}, err
	}
	name := strings.TrimSpace(opts.Name)
	if name == "" {
		name = summary.CommonName
	}
	item := vault.VaultItem{
		ID:        newID(),
		Kind:      vault.KindIntermediateCA,
		Name:      name,
		IssuerID:  issuer.ID,
		CreatedAt: time.Now().UTC(),
		CertPEM:   certPEM,
		KeyPEM:    keyPEM,
		Summary:   summary,
	}
	if err := a.vault.AddItem(item); err != nil {
		return vault.VaultItemSummary{}, err
	}
	return summarizeToVaultSummary(item), nil
}

// CreateLeafCert generates a ready-to-use TLS certificate signed by an existing CA.
func (a *App) CreateLeafCert(opts pki.CertOptions) (vault.VaultItemSummary, error) {
	if !a.vault.IsUnlocked() {
		return vault.VaultItemSummary{}, errors.New("vault is locked")
	}
	issuer, err := a.vault.GetItem(opts.IssuerID)
	if err != nil {
		return vault.VaultItemSummary{}, fmt.Errorf("loading issuer CA: %w", err)
	}
	if issuer.KeyPEM == "" || issuer.CertPEM == "" {
		return vault.VaultItemSummary{}, errors.New("selected issuer does not have both a certificate and private key")
	}
	certPEM, keyPEM, summary, err := pki.GenerateLeafCert(opts, issuer.CertPEM, issuer.KeyPEM)
	if err != nil {
		return vault.VaultItemSummary{}, err
	}
	name := strings.TrimSpace(opts.Name)
	if name == "" {
		name = summary.CommonName
	}
	item := vault.VaultItem{
		ID:        newID(),
		Kind:      vault.KindLeafCert,
		Name:      name,
		IssuerID:  issuer.ID,
		CreatedAt: time.Now().UTC(),
		CertPEM:   certPEM,
		KeyPEM:    keyPEM,
		Summary:   summary,
	}
	if err := a.vault.AddItem(item); err != nil {
		return vault.VaultItemSummary{}, err
	}
	return summarizeToVaultSummary(item), nil
}

// CreateCSR generates a PKCS#10 CSR and stores it with its encrypted private key.
func (a *App) CreateCSR(opts pki.CertOptions) (vault.VaultItemSummary, error) {
	if !a.vault.IsUnlocked() {
		return vault.VaultItemSummary{}, errors.New("vault is locked")
	}
	csrPEM, keyPEM, summary, err := pki.GenerateCSR(opts)
	if err != nil {
		return vault.VaultItemSummary{}, err
	}
	name := strings.TrimSpace(opts.Name)
	if name == "" {
		name = summary.CommonName
	}
	item := vault.VaultItem{
		ID:        newID(),
		Kind:      vault.KindCSR,
		Name:      name,
		CreatedAt: time.Now().UTC(),
		CSRPEM:    csrPEM,
		KeyPEM:    keyPEM,
		Summary:   summary,
	}
	if err := a.vault.AddItem(item); err != nil {
		return vault.VaultItemSummary{}, err
	}
	return summarizeToVaultSummary(item), nil
}

// SignCSR signs a CSR using an existing CA in the vault.
func (a *App) SignCSR(req SignCSRRequest) (vault.VaultItemSummary, error) {
	if !a.vault.IsUnlocked() {
		return vault.VaultItemSummary{}, errors.New("vault is locked")
	}
	issuer, err := a.vault.GetItem(req.IssuerID)
	if err != nil {
		return vault.VaultItemSummary{}, fmt.Errorf("loading issuer CA: %w", err)
	}
	if issuer.KeyPEM == "" || issuer.CertPEM == "" {
		return vault.VaultItemSummary{}, errors.New("selected issuer does not have both a certificate and private key")
	}

	csrPEM := req.CSRPEM
	var existingKeyPEM string
	if req.StoredCSRID != "" {
		stored, err := a.vault.GetItem(req.StoredCSRID)
		if err != nil {
			return vault.VaultItemSummary{}, err
		}
		if csrPEM == "" {
			csrPEM = stored.CSRPEM
		}
		existingKeyPEM = stored.KeyPEM
	}

	certPEM, summary, err := pki.SignCSR(csrPEM, issuer.CertPEM, issuer.KeyPEM, req.ValidityDays, req.IsCA, req.PathLen, req.KeyUsages, req.ExtKeyUsages)
	if err != nil {
		return vault.VaultItemSummary{}, err
	}
	kind := vault.KindLeafCert
	if req.IsCA {
		kind = vault.KindIntermediateCA
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = summary.CommonName
	}
	item := vault.VaultItem{
		ID:        newID(),
		Kind:      kind,
		Name:      name,
		IssuerID:  issuer.ID,
		CreatedAt: time.Now().UTC(),
		CertPEM:   certPEM,
		CSRPEM:    csrPEM,
		KeyPEM:    existingKeyPEM,
		Summary:   summary,
	}
	if err := a.vault.AddItem(item); err != nil {
		return vault.VaultItemSummary{}, err
	}
	return summarizeToVaultSummary(item), nil
}

// DeleteItem removes an item from the vault. Deleting a CA requires masterPassword.
func (a *App) DeleteItem(id, masterPassword string) error {
	item, err := a.vault.GetItem(id)
	if err != nil {
		return err
	}
	if item.Kind == vault.KindRootCA || item.Kind == vault.KindIntermediateCA {
		if err := a.vault.VerifyPassword(masterPassword); err != nil {
			return err
		}
	}
	return a.vault.DeleteItem(id)
}

// RevokeItem marks a certificate as revoked inside the vault.
func (a *App) RevokeItem(id string, reason int) error {
	return a.vault.RevokeItem(id, reason)
}

// ExportCRL generates and saves a signed X.509 CRL for all revoked certs issued by caID.
func (a *App) ExportCRL(caID string, validDays int) (string, error) {
	if a.ctx == nil {
		return "", errors.New("application context not initialized")
	}
	ca, err := a.vault.GetItem(caID)
	if err != nil {
		return "", err
	}
	if ca.CertPEM == "" || ca.KeyPEM == "" {
		return "", errors.New("selected CA does not have both a certificate and private key")
	}
	all, err := a.vault.AllItems()
	if err != nil {
		return "", err
	}
	var revoked []pki.RevokedEntry
	for _, it := range all {
		if it.IssuerID == caID && it.Revoked && it.CertPEM != "" {
			var revTime time.Time
			if it.RevokedAt != nil {
				revTime = *it.RevokedAt
			}
			revoked = append(revoked, pki.RevokedEntry{
				CertPEM:   it.CertPEM,
				RevokedAt: revTime,
				Reason:    it.RevokeReason,
			})
		}
	}
	crlPEM, err := pki.GenerateCRL(ca.CertPEM, ca.KeyPEM, revoked, validDays)
	if err != nil {
		return "", err
	}
	defaultName := sanitizeFilename(ca.Name) + ".crl.pem"
	target, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
		Title:           "Export Certificate Revocation List",
		DefaultFilename: defaultName,
		Filters:         []runtime.FileFilter{{DisplayName: "CRL PEM (*.crl.pem, *.crl, *.pem)", Pattern: "*.crl.pem;*.crl;*.pem"}},
	})
	if err != nil || target == "" {
		return "", err
	}
	if err := os.WriteFile(target, []byte(crlPEM), 0644); err != nil {
		return "", err
	}
	return target, nil
}

func (a *App) buildChain(item vault.VaultItem) (fullChain string, caChain []string) {
	all, err := a.vault.AllItems()
	if err != nil {
		return item.CertPEM, nil
	}
	byID := make(map[string]vault.VaultItem, len(all))
	for _, it := range all {
		byID[it.ID] = it
	}

	var parts []string
	if item.CertPEM != "" {
		parts = append(parts, strings.TrimSpace(item.CertPEM))
	}
	visited := map[string]bool{item.ID: true}
	currID := item.IssuerID
	for currID != "" && !visited[currID] {
		visited[currID] = true
		parent, ok := byID[currID]
		if !ok || parent.CertPEM == "" {
			break
		}
		trimmed := strings.TrimSpace(parent.CertPEM)
		parts = append(parts, trimmed)
		caChain = append(caChain, trimmed)
		currID = parent.IssuerID
	}
	return strings.Join(parts, "\n") + "\n", caChain
}

// GetItemPEM returns public PEM blocks (certificate, full chain, CSR) for an item.
func (a *App) GetItemPEM(id string) (ItemPEMs, error) {
	item, err := a.vault.GetItem(id)
	if err != nil {
		return ItemPEMs{}, err
	}
	fullChain, _ := a.buildChain(item)
	return ItemPEMs{
		CertPEM:      item.CertPEM,
		FullChainPEM: fullChain,
		CSRPEM:       item.CSRPEM,
		HasKey:       item.KeyPEM != "",
	}, nil
}

// RevealPrivateKey verifies masterPassword and returns the decrypted private key PEM.
func (a *App) RevealPrivateKey(id, masterPassword string) (string, error) {
	if err := a.vault.VerifyPassword(masterPassword); err != nil {
		return "", err
	}
	item, err := a.vault.GetItem(id)
	if err != nil {
		return "", err
	}
	if item.KeyPEM == "" {
		return "", errors.New("this item does not have a stored private key")
	}
	return item.KeyPEM, nil
}

// CopyPrivateKeyTemporarily copies a private key to the OS clipboard and clears it after 30 seconds.
func (a *App) CopyPrivateKeyTemporarily(id, masterPassword string) error {
	if a.ctx == nil {
		return errors.New("application context not initialized")
	}
	keyPEM, err := a.RevealPrivateKey(id, masterPassword)
	if err != nil {
		return err
	}
	if err := runtime.ClipboardSetText(a.ctx, keyPEM); err != nil {
		return err
	}
	ctx := a.ctx
	go func(secret string) {
		time.Sleep(30 * time.Second)
		if current, err := runtime.ClipboardGetText(ctx); err == nil && current == secret {
			_ = runtime.ClipboardSetText(ctx, "")
		}
	}(keyPEM)
	return nil
}

func sanitizeFilename(name string) string {
	r := strings.NewReplacer("*", "wildcard", " ", "_", "/", "_", "\\", "_", ":", "_")
	out := r.Replace(strings.TrimSpace(name))
	if out == "" {
		return "certificate"
	}
	return out
}

// ExportArtifact saves a certificate, fullchain, private key, CSR, or PKCS#12 file via native dialog.
// Sensitive exports ("key" and "p12") require masterPassword verification.
func (a *App) ExportArtifact(id, format, p12Password, masterPassword string) (string, error) {
	if a.ctx == nil {
		return "", errors.New("application context not initialized")
	}
	if format == "key" || format == "p12" {
		if err := a.vault.VerifyPassword(masterPassword); err != nil {
			return "", err
		}
	}
	item, err := a.vault.GetItem(id)
	if err != nil {
		return "", err
	}

	base := sanitizeFilename(item.Name)
	var defaultName string
	var filter runtime.FileFilter
	var content []byte

	switch format {
	case "cert":
		if item.CertPEM == "" {
			return "", errors.New("no certificate available for this item")
		}
		defaultName = base + ".crt"
		filter = runtime.FileFilter{DisplayName: "Certificate (*.crt, *.pem)", Pattern: "*.crt;*.pem"}
		content = []byte(item.CertPEM)
	case "fullchain":
		if item.CertPEM == "" {
			return "", errors.New("no certificate available for this item")
		}
		defaultName = base + ".fullchain.pem"
		filter = runtime.FileFilter{DisplayName: "Full Chain PEM (*.pem)", Pattern: "*.pem;*.crt"}
		full, _ := a.buildChain(item)
		content = []byte(full)
	case "key":
		if item.KeyPEM == "" {
			return "", errors.New("no private key available for this item")
		}
		defaultName = base + ".key"
		filter = runtime.FileFilter{DisplayName: "Private Key (*.key, *.pem)", Pattern: "*.key;*.pem"}
		content = []byte(item.KeyPEM)
	case "csr":
		if item.CSRPEM == "" {
			return "", errors.New("no CSR available for this item")
		}
		defaultName = base + ".csr"
		filter = runtime.FileFilter{DisplayName: "Certificate Request (*.csr)", Pattern: "*.csr;*.pem"}
		content = []byte(item.CSRPEM)
	case "p12":
		if item.CertPEM == "" || item.KeyPEM == "" {
			return "", errors.New("PKCS#12 export requires both a certificate and a private key")
		}
		defaultName = base + ".p12"
		filter = runtime.FileFilter{DisplayName: "PKCS#12 Bundle (*.p12, *.pfx)", Pattern: "*.p12;*.pfx"}
		_, caChain := a.buildChain(item)
		content, err = pki.ExportPKCS12(item.CertPEM, item.KeyPEM, caChain, p12Password)
		if err != nil {
			return "", err
		}
	default:
		return "", fmt.Errorf("unknown export format %q", format)
	}

	target, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
		Title:           "Export " + defaultName,
		DefaultFilename: defaultName,
		Filters:         []runtime.FileFilter{filter},
	})
	if err != nil || target == "" {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		return "", err
	}
	mode := os.FileMode(0644)
	if format == "key" || format == "p12" {
		mode = 0600
	}
	if err := os.WriteFile(target, content, mode); err != nil {
		return "", err
	}
	return target, nil
}

// InspectPEM parses a PEM certificate or CSR and returns detailed metadata.
func (a *App) InspectPEM(pemText string) (pki.InspectResult, error) {
	return pki.InspectPEM(pemText)
}

// VerifyCertificate verifies a certificate PEM against CAs stored in the unlocked vault.
func (a *App) VerifyCertificate(certPEM string) (VerifyResult, error) {
	if !a.vault.IsUnlocked() {
		return VerifyResult{Valid: false, Message: "Unlock vault to verify against stored CAs"}, nil
	}
	items, err := a.vault.AllItems()
	if err != nil {
		return VerifyResult{}, err
	}
	var roots, inters []string
	for _, it := range items {
		switch it.Kind {
		case vault.KindRootCA:
			if it.CertPEM != "" {
				roots = append(roots, it.CertPEM)
			}
		case vault.KindIntermediateCA:
			if it.CertPEM != "" {
				inters = append(inters, it.CertPEM)
			}
		}
	}
	ok, msg := pki.VerifyAgainstCAs(certPEM, roots, inters)
	return VerifyResult{Valid: ok, Message: msg}, nil
}

// OpenPEMFile opens a file dialog to read a PEM file into the UI.
func (a *App) OpenPEMFile() (string, error) {
	if a.ctx == nil {
		return "", errors.New("application context not initialized")
	}
	path, err := runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "Open Certificate or CSR File",
		Filters: []runtime.FileFilter{
			{DisplayName: "PEM / Cert / CSR (*.pem, *.crt, *.cer, *.csr)", Pattern: "*.pem;*.crt;*.cer;*.csr"},
			{DisplayName: "All Files (*.*)", Pattern: "*.*"},
		},
	})
	if err != nil || path == "" {
		return "", err
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if info.Size() > pki.MaxPEMInputBytes {
		return "", errors.New("file exceeds 1 MiB PEM size limit")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
