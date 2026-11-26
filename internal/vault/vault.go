package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
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
	vaultVersion = 1
	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 4
	keyLen       = 32
	saltLen      = 16
	nonceLen     = 12
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
	ID        string          `json:"id"`
	Kind      ItemKind        `json:"kind"`
	Name      string          `json:"name"`
	IssuerID  string          `json:"issuerId,omitempty"`
	CreatedAt time.Time       `json:"createdAt"`
	CertPEM   string          `json:"certPem,omitempty"`
	CSRPEM    string          `json:"csrPem,omitempty"`
	KeyPEM    string          `json:"keyPem,omitempty"`
	Summary   pki.CertSummary `json:"summary"`
}

// VaultItemSummary is a safe-for-UI projection that omits the private key.
type VaultItemSummary struct {
	ID        string          `json:"id"`
	Kind      ItemKind        `json:"kind"`
	Name      string          `json:"name"`
	IssuerID  string          `json:"issuerId,omitempty"`
	CreatedAt time.Time       `json:"createdAt"`
	HasKey    bool            `json:"hasKey"`
	HasCert   bool            `json:"hasCert"`
	HasCSR    bool            `json:"hasCsr"`
	Summary   pki.CertSummary `json:"summary"`
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
	mu       sync.RWMutex
	path     string
	key      []byte
	salt     []byte
	unlocked bool
	data     vaultData
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

// CreateVault initializes a new password-protected encrypted vault at path.
func (m *Manager) CreateVault(path, password string) error {
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("creating vault directory: %w", err)
	}

	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, keyLen)

	m.mu.Lock()
	defer m.mu.Unlock()

	m.zeroKeyLocked()
	m.path = path
	m.salt = salt
	m.key = key
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
	if env.Version != vaultVersion || env.KDF != "argon2id" {
		return fmt.Errorf("unsupported vault version (%d) or KDF (%s)", env.Version, env.KDF)
	}

	salt, err := base64.StdEncoding.DecodeString(env.Salt)
	if err != nil {
		return fmt.Errorf("decoding salt: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return fmt.Errorf("decoding nonce: %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		return fmt.Errorf("decoding ciphertext: %w", err)
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

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
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
	m.unlocked = true
	m.data = loaded
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

// ChangePassword re-encrypts the vault with a new password.
func (m *Manager) ChangePassword(newPassword string) error {
	if len(newPassword) < 8 {
		return errors.New("new password must be at least 8 characters")
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
	key := argon2.IDKey([]byte(newPassword), salt, argonTime, argonMemory, argonThreads, keyLen)

	m.zeroKeyLocked()
	m.salt = salt
	m.key = key
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
			ID:        it.ID,
			Kind:      it.Kind,
			Name:      it.Name,
			IssuerID:  it.IssuerID,
			CreatedAt: it.CreatedAt,
			HasKey:    it.KeyPEM != "",
			HasCert:   it.CertPEM != "",
			HasCSR:    it.CSRPEM != "",
			Summary:   it.Summary,
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
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	env := encryptedVaultFile{
		Version:      vaultVersion,
		KDF:          "argon2id",
		Salt:         base64.StdEncoding.EncodeToString(m.salt),
		ArgonTime:    argonTime,
		ArgonMemory:  argonMemory,
		ArgonThreads: argonThreads,
		Nonce:        base64.StdEncoding.EncodeToString(nonce),
		Ciphertext:   base64.StdEncoding.EncodeToString(ciphertext),
	}
	encoded, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}
	tmpPath := m.path + ".tmp"
	if err := os.WriteFile(tmpPath, encoded, 0600); err != nil {
		return err
	}
	return os.Rename(tmpPath, m.path)
}
