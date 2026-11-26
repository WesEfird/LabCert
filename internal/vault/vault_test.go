package vault

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"LabCert/internal/pki"
)

func TestVaultEncryptionLifecycle(t *testing.T) {
	dir := t.TempDir()
	vaultPath := filepath.Join(dir, "test.labcert")

	mgr := NewManager()
	if err := mgr.CreateVault(vaultPath, "too-short"); err == nil {
		t.Fatal("expected error for password < 12 chars")
	}

	if err := mgr.CreateVault(vaultPath, "correct-horse-battery"); err != nil {
		t.Fatalf("CreateVault failed: %v", err)
	}
	if !mgr.IsUnlocked() || !VaultExists(vaultPath) {
		t.Fatal("expected vault to exist and be unlocked")
	}

	// #1: Refuse to overwrite existing vault
	if err := mgr.CreateVault(vaultPath, "another-strong-password"); err == nil {
		t.Fatal("expected CreateVault to refuse overwriting an existing vault")
	}

	certPEM, keyPEM, sum, err := pki.GenerateRootCA(pki.CertOptions{
		Subject: pki.SubjectOptions{CommonName: "Vault Test CA"},
	})
	if err != nil {
		t.Fatalf("GenerateRootCA failed: %v", err)
	}

	err = mgr.AddItem(VaultItem{
		ID:        "ca-1",
		Kind:      KindRootCA,
		Name:      "Vault Test CA",
		CreatedAt: time.Now().UTC(),
		CertPEM:   certPEM,
		KeyPEM:    keyPEM,
		Summary:   sum,
	})
	if err != nil {
		t.Fatalf("AddItem failed: %v", err)
	}

	// #10: Rolling .bak file should exist after second write
	if !VaultExists(vaultPath + ".bak") {
		t.Fatal("expected rolling .bak backup file to exist after update")
	}

	mgr.Lock()
	if mgr.IsUnlocked() {
		t.Fatal("expected vault to be locked")
	}

	mgr2 := NewManager()
	if err := mgr2.Unlock(vaultPath, "wrong-password"); err == nil {
		t.Fatal("expected error unlocking with wrong password")
	}
	if err := mgr2.Unlock(vaultPath, "correct-horse-battery"); err != nil {
		t.Fatalf("Unlock with right password failed: %v", err)
	}

	// #9: ChangePassword requires current password
	if err := mgr2.ChangePassword("wrong-current-pw", "new-strong-password-99"); err == nil {
		t.Fatal("expected ChangePassword to fail with wrong current password")
	}
	if err := mgr2.ChangePassword("correct-horse-battery", "new-strong-password-99"); err != nil {
		t.Fatalf("ChangePassword failed: %v", err)
	}

	// #11: RevokeItem
	if err := mgr2.RevokeItem("ca-1", 1); err != nil {
		t.Fatalf("RevokeItem failed: %v", err)
	}
	summaries, err := mgr2.ListSummaries()
	if err != nil || len(summaries) != 1 || !summaries[0].Revoked {
		t.Fatalf("expected revoked summary, got: %+v, err=%v", summaries, err)
	}

	mgr2.Lock()
	if err := mgr2.Unlock(vaultPath, "correct-horse-battery"); err == nil {
		t.Fatal("old password should no longer unlock vault")
	}
	if err := mgr2.Unlock(vaultPath, "new-strong-password-99"); err != nil {
		t.Fatalf("new password failed to unlock vault: %v", err)
	}

	if err := mgr2.DeleteItem("ca-1"); err != nil {
		t.Fatalf("DeleteItem failed: %v", err)
	}
	afterDelete, err := mgr2.ListSummaries()
	if err != nil || len(afterDelete) != 0 {
		t.Fatalf("expected 0 items after delete, got %d", len(afterDelete))
	}
}

func TestVaultRejectsMalformedParamsAndTamperedHeader(t *testing.T) {
	dir := t.TempDir()
	vaultPath := filepath.Join(dir, "bad.labcert")

	// #4: Zero threads / huge memory / bad nonce must return error, never panic
	malformedCases := []encryptedVaultFile{
		{Version: 2, KDF: "argon2id", Salt: "AAAAAAAAAAAAAAAAAAAAAA==", ArgonTime: 0, ArgonMemory: 65536, ArgonThreads: 4, Nonce: "AAAAAAAAAAAAAAAA", Ciphertext: "AAAA"},
		{Version: 2, KDF: "argon2id", Salt: "AAAAAAAAAAAAAAAAAAAAAA==", ArgonTime: 3, ArgonMemory: 2_000_000, ArgonThreads: 4, Nonce: "AAAAAAAAAAAAAAAA", Ciphertext: "AAAA"},
		{Version: 2, KDF: "argon2id", Salt: "AAAAAAAAAAAAAAAAAAAAAA==", ArgonTime: 3, ArgonMemory: 65536, ArgonThreads: 0, Nonce: "AAAAAAAAAAAAAAAA", Ciphertext: "AAAA"},
		{Version: 2, KDF: "argon2id", Salt: "AAAAAAAAAAAAAAAAAAAAAA==", ArgonTime: 3, ArgonMemory: 65536, ArgonThreads: 4, Nonce: "AAAA", Ciphertext: "AAAA"},
	}

	mgr := NewManager()
	for i, tc := range malformedCases {
		b, _ := json.Marshal(tc)
		_ = os.WriteFile(vaultPath, b, 0600)
		if err := mgr.Unlock(vaultPath, "any-password-here"); err == nil {
			t.Fatalf("case %d: expected Unlock to reject malformed vault header", i)
		}
	}

	// #4 AAD tamper detection on valid v2 vault
	validPath := filepath.Join(dir, "valid.labcert")
	if err := mgr.CreateVault(validPath, "valid-strong-password"); err != nil {
		t.Fatal(err)
	}
	mgr.Lock()

	raw, _ := os.ReadFile(validPath)
	var env encryptedVaultFile
	_ = json.Unmarshal(raw, &env)
	env.ArgonTime = env.ArgonTime + 1 // tamper header
	tampered, _ := json.Marshal(env)
	_ = os.WriteFile(validPath, tampered, 0600)

	if err := mgr.Unlock(validPath, "valid-strong-password"); err == nil {
		t.Fatal("expected tampered v2 vault header to fail AAD authentication")
	}
}
