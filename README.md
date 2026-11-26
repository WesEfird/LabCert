# LabCert

A cross-platform desktop PKI and TLS certificate helper built with **Go** and **Wails v2** (Vanilla TypeScript + HTML/CSS). Designed for homelabs, LabCert lets you create a Root CA, Intermediate CAs, CSRs, and ready-to-use TLS certificates while keeping private keys encrypted inside a password-protected vault.

---

## Features

- **Encrypted PKI Vault (`*.labcert`)**
  - Protects all stored certificates, CSRs, and private keys using **Argon2id** key derivation and **AES-256-GCM** authenticated encryption.
  - Remembers your last selected vault path and defaults to **Open Vault** on startup, with an option to create additional vaults or change the master password.
- **Full X.509 Certificate Authority Hierarchy**
  - **Root CA**: Self-signed Root CA with configurable Subject DN (`CN`, `O`, `OU`, `C`, `ST`, `L`), key algorithm/size, validity, and `PathLenConstraint`.
  - **Intermediate CA**: Signed by any Root or Intermediate CA in the vault; automatically inherits Subject DN fields from the selected issuer.
  - **Homelab TLS Certificates**: Issue end-entity certificates with a smart **SAN chip builder** (auto-detects DNS names, wildcards, and IPv4/IPv6 addresses), `KeyUsage`, `ExtendedKeyUsage` (`serverAuth`, `clientAuth`, `codeSigning`, `emailProtection`), and quick presets (HTTPS, Wildcard, mTLS).
- **CSR Tools**
  - Generate PKCS#10 CSRs (with encrypted private keys saved in the vault).
  - Sign external CSRs (paste PEM or load `.csr` file) or stored CSRs using any CA in the vault.
- **Certificate Inspector & Verification**
  - Inspect any PEM certificate, chain, or CSR and verify trust chains against CAs in the unlocked vault.
- **Exports**
  - Export `.crt`, `.fullchain.pem` (leaf + intermediate + root), `.key`, `.csr`, or password-protected **PKCS#12 (`.p12` / `.pfx`)** bundles via native save dialogs.
- **Dual Theme UI**
  - Switch between **Slate Dark** and **Mist Light** themes, with a **Tree View** (`Root CA → Intermediate CA → TLS Certs`) and searchable **List View**.

---

## Prerequisites (Building from Source)

- **Go** `1.23+` (tested with `go1.27.4`)
- **Node.js** `20+` and `npm` (build-time only; end users running the compiled binary do **not** need Node.js or Go)
- **Wails CLI v2**:
  ```bash
  go install github.com/wailsapp/wails/v2/cmd/wails@latest
  ```
- **Platform Runtime**:
  - **Windows**: Microsoft Edge WebView2 Runtime (pre-installed on Windows 11 and most Windows 10 systems)
  - **macOS**: Xcode Command Line Tools (WebKit is built-in)
  - **Linux**: `libgtk-3-dev` and `libwebkit2gtk-4.0-dev` (or `webkit2gtk-4.1` depending on distro)

Verify your environment:
```bash
wails doctor
```

---

## Build & Run Instructions

### Live Development
Run Wails in dev mode with hot-reloading for the frontend:
```bash
wails dev
```

### Production Build
Build a standalone, single-binary executable (embeds the compiled frontend assets):
```bash
wails build
```
The compiled binary is written to `build/bin/LabCert.exe` (Windows) or `build/bin/LabCert` (macOS/Linux).

### Running Tests
Run the Go PKI and encrypted vault test suites:
```bash
go test -v ./...
```

---

## Usage Guide

1. **Create or Open a Vault**
   - On first launch, switch to the **Create New Vault** tab, choose a location (defaults to your OS user config directory under `LabCert/vault.labcert`), and set a master password (at least 8 characters).
   - On subsequent launches, LabCert remembers your last vault and opens directly to **Open Vault**.
2. **Create a Root CA**
   - Go to **Root CA** in the sidebar, enter a Common Name (e.g., `Homelab Root CA`), select a key algorithm (e.g., `ECDSA P-384` or `RSA 4096-bit`), and generate.
3. **Create an Intermediate CA (Recommended)**
   - Go to **Intermediate CA** (or click **+ Interm** on your Root CA in the Vault Tree View), pick your Root CA as the issuer, and generate.
4. **Issue Homelab TLS Certificates**
   - Go to **Issue TLS Cert** (or click **+ TLS Cert** on a CA), enter the Common Name (e.g., `proxmox.home.arpa`), add DNS/IP SANs in the SAN builder, choose Key Usage / EKU presets, and issue.
5. **Export for Your Services**
   - Click any item in the Vault to open the detail drawer, switch to the **Export** tab, and save `.crt`, `.fullchain.pem`, `.key`, or `.p12` / `.pfx` files for Nginx, Traefik, Caddy, Proxmox, or TrueNAS.
