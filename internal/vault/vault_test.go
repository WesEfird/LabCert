package vault

import (
	"path/filepath"
	"testing"
	"time"

	"LabCert/internal/pki"
)

func TestVaultEncryptionLifecycle(t *testing.T) {
	dir := t.TempDir()
	vaultPath := filepath.Join(dir, "test.labcert")

	mgr := NewManager()
	if err := mgr.CreateVault(vaultPath, "short"); err == nil {
		t.Fatal("expected error for short password")
	}

	if err := mgr.CreateVault(vaultPath, "correct-horse-battery"); err != nil {
		t.Fatalf("CreateVault failed: %v", err)
	}
	if !mgr.IsUnlocked() || !VaultExists(vaultPath) {
		t.Fatal("expected vault to exist and be unlocked")
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

	summaries, err := mgr2.ListSummaries()
	if err != nil || len(summaries) != 1 || !summaries[0].HasKey {
		t.Fatalf("unexpected summaries: %+v, err=%v", summaries, err)
	}

	loaded, err := mgr2.GetItem("ca-1")
	if err != nil || loaded.KeyPEM != keyPEM {
		t.Fatalf("decrypted key mismatch or error: %v", err)
	}

	if err := mgr2.ChangePassword("new-strong-password-99"); err != nil {
		t.Fatalf("ChangePassword failed: %v", err)
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
