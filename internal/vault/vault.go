package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"LabCert/internal/pki"
	"golang.org/x/crypto/argon2"
)

const (
	vaultVersionV1 = 1
	vaultVersionV2 = 2

	defaultArgonTime    = 3
	defaultArgonMemory  = 64 * 1024
	defaultArgonThreads = 4

	minArgonTime    = 1
	maxArgonTime    = 10
	minArgonMemory  = 19 * 1024   // 19 MiB (OWASP minimum)
	maxArgonMemory  = 1024 * 1024 // 1 GiB upper safety bound
	minArgonThreads = 1
	maxArgonThreads = 16

	minPasswordLen = 12
	keyLen         = 32
	saltLen        = 16
	nonceLen       = 12
)

// ItemKind identifies the type of stored PKI artifact.
type ItemKind string

const (
	KindRootCA         ItemKind = "root_ca"
	KindIntermediateCA ItemKind = "intermediate_ca"
	KindLeafCert       ItemKind = "leaf_cert"
	KindCSR            ItemKind = "csr"
)

// VaultItem represents an encrypted PKI entry stored in the LabCert vault.
type VaultItem struct {
	ID           string          `json:"id"`
	Kind         ItemKind        `json:"kind"`
	Name         string          `json:"name"`
	IssuerID     string          `json:"issuerId,omitempty"`
	CreatedAt    time.Time       `json:"createdAt"`
	CertPEM      string          `json:"certPem,omitempty"`
	CSRPEM       string          `json:"csrPem,omitempty"`
	KeyPEM       string          `json:"keyPem,omitempty"`
	Revoked      bool            `json:"revoked,omitempty"`
	RevokedAt    *time.Time      `json:"revokedAt,omitempty"`
	RevokeReason int             `json:"revokeReason,omitempty"`
	Summary      pki.CertSummary `json:"summary"`
}

// VaultItemSummary is a safe-for-UI projection that omits the private key.
type VaultItemSummary struct {
	ID           string          `json:"id"`
	Kind         ItemKind        `json:"kind"`
	Name         string          `json:"name"`
	IssuerID     string          `json:"issuerId,omitempty"`
	CreatedAt    time.Time       `json:"createdAt"`
	HasKey       bool            `json:"hasKey"`
	HasCert      bool            `json:"hasCert"`
	HasCSR       bool            `json:"hasCsr"`
	Revoked      bool            `json:"revoked,omitempty"`
	RevokedAt    *time.Time      `json:"revokedAt,omitempty"`
	RevokeReason int             `json:"revokeReason,omitempty"`
	Summary      pki.CertSummary `json:"summary"`
}

type vaultData struct {
	Items []VaultItem `json:"items"`
}

type encryptedVaultFile struct {
	Version      int    `json:"version"`
	KDF          string `json:"kdf"`
	Salt         string `json:"salt"`
	ArgonTime    uint32 `json:"argonTime"`
	ArgonMemory  uint32 `json:"argonMemory"`
	ArgonThreads uint8  `json:"argonThreads"`
	Nonce        string `json:"nonce"`
	Ciphertext   string `json:"ciphertext"`
}

// Manager manages an Argon2id + AES-256-GCM encrypted PKI vault on disk.
type Manager struct {
	mu           sync.RWMutex
	path         string
	key          []byte
	salt         []byte
	argonTime    uint32
	argonMemory  uint32
	argonThreads uint8
	unlocked     bool
	data         vaultData
}

// NewManager creates a new locked vault manager.
func NewManager() *Manager {
	return &Manager{}
}

// DefaultVaultPath returns the cross-platform default vault file path.
func DefaultVaultPath() (string, error) {
	cfgDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolving user config dir: %w", err)
	}
	return filepath.Join(cfgDir, "LabCert", "vault.labcert"), nil
}

// VaultExists reports whether a vault file exists at the given path.
func VaultExists(path string) bool {
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

func buildHeaderAAD(version int, kdf, saltB64 string, t, mem uint32, threads uint8) []byte {
	return []byte(fmt.Sprintf("v=%d|kdf=%s|salt=%s|t=%d|m=%d|p=%d", version, kdf, saltB64, t, mem, threads))
}

func validateKDFParams(t, mem uint32, threads uint8) error {
	if t < minArgonTime || t > maxArgonTime {
		return fmt.Errorf("invalid vault KDF time parameter (%d)", t)
	}
	if mem < minArgonMemory || mem > maxArgonMemory {
		return fmt.Errorf("invalid vault KDF memory parameter (%d KiB)", mem)
	}
	if threads < minArgonThreads || threads > maxArgonThreads {
		return fmt.Errorf("invalid vault KDF threads parameter (%d)", threads)
	}
	return nil
}

// CreateVault initializes a new password-protected encrypted vault at path.
// It refuses to overwrite an existing file at path.
func (m *Manager) CreateVault(path, password string) error {
	if len(password) < minPasswordLen {
		return fmt.Errorf("password must be at least %d characters", minPasswordLen)
	}
	if VaultExists(path) {
		return errors.New("a vault already exists at this path; choose a new filename or open the existing vault")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("creating vault directory: %w", err)
	}

	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	key := argon2.IDKey([]byte(password), salt, defaultArgonTime, defaultArgonMemory, defaultArgonThreads, keyLen)

	m.mu.Lock()
	defer m.mu.Unlock()

	m.zeroKeyLocked()
	m.path = path
	m.salt = salt
	m.key = key
	m.argonTime = defaultArgonTime
	m.argonMemory = defaultArgonMemory
	m.argonThreads = defaultArgonThreads
	m.unlocked = true
	m.data = vaultData{Items: []VaultItem{}}

	return m.saveLocked()
}

// Unlock decrypts and loads an existing vault from path using password.
func (m *Manager) Unlock(path, password string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading vault: %w", err)
	}

	var env encryptedVaultFile
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("invalid vault format: %w", err)
	}
	if (env.Version != vaultVersionV1 && env.Version != vaultVersionV2) || env.KDF != "argon2id" {
		return fmt.Errorf("unsupported vault version (%d) or KDF (%s)", env.Version, env.KDF)
	}
	if err := validateKDFParams(env.ArgonTime, env.ArgonMemory, env.ArgonThreads); err != nil {
		return err
	}

	salt, err := base64.StdEncoding.DecodeString(env.Salt)
	if err != nil || len(salt) != saltLen {
		return errors.New("invalid vault salt")
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil || len(nonce) != nonceLen {
		return errors.New("invalid vault nonce")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil || len(ciphertext) == 0 {
		return errors.New("invalid vault ciphertext")
	}

	key := argon2.IDKey([]byte(password), salt, env.ArgonTime, env.ArgonMemory, env.ArgonThreads, keyLen)
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	var aad []byte
	if env.Version == vaultVersionV2 {
		aad = buildHeaderAAD(env.Version, env.KDF, env.Salt, env.ArgonTime, env.ArgonMemory, env.ArgonThreads)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		for i := range key {
			key[i] = 0
		}
		return errors.New("incorrect password or corrupted vault")
	}

	var loaded vaultData
	if err := json.Unmarshal(plaintext, &loaded); err != nil {
		return fmt.Errorf("corrupted vault payload: %w", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.zeroKeyLocked()
	m.path = path
	m.salt = salt
	m.key = key
	m.argonTime = env.ArgonTime
	m.argonMemory = env.ArgonMemory
	m.argonThreads = env.ArgonThreads
	m.unlocked = true
	m.data = loaded
	return nil
}

// VerifyPassword checks whether candidate matches the unlocked vault's master password.
func (m *Manager) VerifyPassword(candidate string) error {
	m.mu.RLock()
	if !m.unlocked {
		m.mu.RUnlock()
		return errors.New("vault is locked")
	}
	salt := append([]byte(nil), m.salt...)
	t, mem, threads := m.argonTime, m.argonMemory, m.argonThreads
	expected := append([]byte(nil), m.key...)
	m.mu.RUnlock()

	derived := argon2.IDKey([]byte(candidate), salt, t, mem, threads, keyLen)
	defer func() {
		for i := range derived {
			derived[i] = 0
		}
		for i := range expected {
			expected[i] = 0
		}
	}()

	if subtle.ConstantTimeCompare(derived, expected) != 1 {
		return errors.New("incorrect master password")
	}
	return nil
}

// Lock clears the decrypted key and items from memory.
func (m *Manager) Lock() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.zeroKeyLocked()
	m.unlocked = false
	m.data = vaultData{}
}

// IsUnlocked reports whether the vault is currently unlocked.
func (m *Manager) IsUnlocked() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.unlocked
}

// Path returns the currently loaded vault path.
func (m *Manager) Path() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.path
}

// ChangePassword verifies currentPassword and re-encrypts the vault with newPassword.
func (m *Manager) ChangePassword(currentPassword, newPassword string) error {
	if len(newPassword) < minPasswordLen {
		return fmt.Errorf("new password must be at least %d characters", minPasswordLen)
	}
	if err := m.VerifyPassword(currentPassword); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.unlocked {
		return errors.New("vault is locked")
	}

	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	key := argon2.IDKey([]byte(newPassword), salt, defaultArgonTime, defaultArgonMemory, defaultArgonThreads, keyLen)

	m.zeroKeyLocked()
	m.salt = salt
	m.key = key
	m.argonTime = defaultArgonTime
	m.argonMemory = defaultArgonMemory
	m.argonThreads = defaultArgonThreads
	return m.saveLocked()
}

// AddItem appends an item and persists the encrypted vault.
func (m *Manager) AddItem(item VaultItem) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.unlocked {
		return errors.New("vault is locked")
	}
	m.data.Items = append([]VaultItem{item}, m.data.Items...)
	return m.saveLocked()
}

// UpdateItem replaces an item by ID and persists the encrypted vault.
func (m *Manager) UpdateItem(item VaultItem) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.unlocked {
		return errors.New("vault is locked")
	}
	for i := range m.data.Items {
		if m.data.Items[i].ID == item.ID {
			m.data.Items[i] = item
			return m.saveLocked()
		}
	}
	return errors.New("item not found")
}

// RevokeItem marks a certificate item as revoked and persists the vault.
func (m *Manager) RevokeItem(id string, reason int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.unlocked {
		return errors.New("vault is locked")
	}
	for i := range m.data.Items {
		if m.data.Items[i].ID == id {
			if m.data.Items[i].CertPEM == "" {
				return errors.New("only certificates can be revoked")
			}
			now := time.Now().UTC()
			m.data.Items[i].Revoked = true
			m.data.Items[i].RevokedAt = &now
			m.data.Items[i].RevokeReason = reason
			return m.saveLocked()
		}
	}
	return errors.New("item not found")
}

// DeleteItem removes an item by ID and persists the encrypted vault.
func (m *Manager) DeleteItem(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.unlocked {
		return errors.New("vault is locked")
	}
	for i := range m.data.Items {
		if m.data.Items[i].ID == id {
			m.data.Items = append(m.data.Items[:i], m.data.Items[i+1:]...)
			return m.saveLocked()
		}
	}
	return errors.New("item not found")
}

// GetItem returns a copy of a VaultItem by ID.
func (m *Manager) GetItem(id string) (VaultItem, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.unlocked {
		return VaultItem{}, errors.New("vault is locked")
	}
	for _, it := range m.data.Items {
		if it.ID == id {
			return it, nil
		}
	}
	return VaultItem{}, errors.New("item not found")
}

// ListSummaries returns UI-safe summaries (without private keys).
func (m *Manager) ListSummaries() ([]VaultItemSummary, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.unlocked {
		return nil, errors.New("vault is locked")
	}
	out := make([]VaultItemSummary, len(m.data.Items))
	for i, it := range m.data.Items {
		out[i] = VaultItemSummary{
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
	return out, nil
}

// AllItems returns all stored items (for internal chain resolution).
func (m *Manager) AllItems() ([]VaultItem, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.unlocked {
		return nil, errors.New("vault is locked")
	}
	cp := make([]VaultItem, len(m.data.Items))
	copy(cp, m.data.Items)
	return cp, nil
}

func (m *Manager) zeroKeyLocked() {
	for i := range m.key {
		m.key[i] = 0
	}
	m.key = nil
}

func (m *Manager) saveLocked() error {
	plaintext, err := json.Marshal(m.data)
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(m.key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}

	saltB64 := base64.StdEncoding.EncodeToString(m.salt)
	aad := buildHeaderAAD(vaultVersionV2, "argon2id", saltB64, m.argonTime, m.argonMemory, m.argonThreads)
	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)

	env := encryptedVaultFile{
		Version:      vaultVersionV2,
		KDF:          "argon2id",
		Salt:         saltB64,
		ArgonTime:    m.argonTime,
		ArgonMemory:  m.argonMemory,
		ArgonThreads: m.argonThreads,
		Nonce:        base64.StdEncoding.EncodeToString(nonce),
		Ciphertext:   base64.StdEncoding.EncodeToString(ciphertext),
	}
	encoded, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}

	// Write to temp file and fsync before replacing
	tmpPath := m.path + ".tmp"
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if _, err := f.Write(encoded); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}

	// Keep a rolling .bak copy of the previous good vault
	if prev, err := os.ReadFile(m.path); err == nil && len(prev) > 0 {
		_ = os.WriteFile(m.path+".bak", prev, 0600)
	}

	return os.Rename(tmpPath, m.path)
}
