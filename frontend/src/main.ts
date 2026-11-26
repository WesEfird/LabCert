import './style.css';
import {
  ChangeVaultPassword,
  CheckVaultPath,
  ChooseVaultFile,
  CreateCSR,
  CreateIntermediateCA,
  CreateLeafCert,
  CreateRootCA,
  CreateVault,
  DeleteItem,
  ExportArtifact,
  GetItemPEM,
  GetVaultStatus,
  InspectPEM,
  ListItems,
  LockVault,
  OpenPEMFile,
  RevealPrivateKey,
  SignCSR,
  UnlockVault,
  VerifyCertificate,
} from '../wailsjs/go/main/App';
import { main, pki, vault } from '../wailsjs/go/models';

type Page = 'vault' | 'root-ca' | 'intermediate-ca' | 'leaf-cert' | 'csr' | 'inspector';
type Theme = 'dark' | 'light';
type VaultView = 'tree' | 'list';
type DrawerTab = 'overview' | 'pem' | 'export';

interface SanEntry {
  type: 'dns' | 'ip';
  value: string;
}

interface ConfirmDialogState {
  title: string;
  message: string;
  confirmLabel: string;
  onConfirm: () => Promise<void>;
}

interface State {
  theme: Theme;
  authMode: 'open' | 'create';
  status: main.VaultStatus;
  items: vault.VaultItemSummary[];
  page: Page;
  vaultView: VaultView;
  filterKind: string;
  searchQuery: string;
  csrTab: 'generate' | 'sign';
  preselectedIssuerId: string;
  sanEntries: SanEntry[];
  sanError: string;
  selectedItem: vault.VaultItemSummary | null;
  selectedPEMs: main.ItemPEMs | null;
  drawerTab: DrawerTab;
  revealedKey: string | null;
  inspectResult: pki.InspectResult | null;
  verifyResult: main.VerifyResult | null;
  inspectInput: string;
  showChangePasswordModal: boolean;
  p12ExportTargetId: string | null;
  confirmDialog: ConfirmDialogState | null;
}

const savedTheme = (localStorage.getItem('labcert-theme') as Theme) || 'dark';
document.documentElement.setAttribute('data-theme', savedTheme);

const state: State = {
  theme: savedTheme,
  authMode: 'open',
  status: new main.VaultStatus({ unlocked: false, exists: false, path: '' }),
  items: [],
  page: 'vault',
  vaultView: 'tree',
  filterKind: 'all',
  searchQuery: '',
  csrTab: 'generate',
  preselectedIssuerId: '',
  sanEntries: [],
  sanError: '',
  selectedItem: null,
  selectedPEMs: null,
  drawerTab: 'overview',
  revealedKey: null,
  inspectResult: null,
  verifyResult: null,
  inspectInput: '',
  showChangePasswordModal: false,
  p12ExportTargetId: null,
  confirmDialog: null,
};

const appEl = document.getElementById('app')!;

const icons = {
  vault: `<svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="16" rx="2"/><circle cx="12" cy="12" r="3"/><path d="M12 9v1m0 4v1m3-3h-1m-4 0H9"/></svg>`,
  search: `<svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg>`,
  shield: `<svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>`,
  layers: `<svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/></svg>`,
  cert: `<svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="14" rx="2"/><path d="M7 8h10M7 12h6"/><circle cx="17" cy="18" r="3"/></svg>`,
  fileText: `<svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>`,
  tree: `<svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 3v12"/><circle cx="18" cy="6" r="3"/><circle cx="6" cy="18" r="3"/><path d="M18 9a9 9 0 0 1-9 9"/></svg>`,
  list: `<svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/></svg>`,
  sun: `<svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M4.93 4.93l1.41 1.41m11.32 11.32 1.41 1.41M2 12h2m16 0h2M4.93 19.07l1.41-1.41m11.32-11.32 1.41-1.41"/></svg>`,
  moon: `<svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>`,
  lock: `<svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>`,
  alert: `<svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`,
};

function esc(val: unknown): string {
  return String(val ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function toggleTheme() {
  state.theme = state.theme === 'dark' ? 'light' : 'dark';
  localStorage.setItem('labcert-theme', state.theme);
  document.documentElement.setAttribute('data-theme', state.theme);
  render();
}

function showToast(msg: string, type: 'info' | 'success' | 'error' = 'info') {
  let container = document.querySelector('.toast-container');
  if (!container) {
    container = document.createElement('div');
    container.className = 'toast-container';
    document.body.appendChild(container);
  }
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.textContent = msg;
  container.appendChild(el);
  setTimeout(() => el.remove(), 4200);
}

function errMsg(e: unknown): string {
  if (e instanceof Error) return e.message;
  return String(e);
}

function formatDate(d: unknown): string {
  if (!d) return '—';
  const dt = new Date(String(d));
  if (isNaN(dt.getTime())) return String(d);
  return dt.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

function daysRemaining(d: unknown): number | null {
  if (!d) return null;
  const dt = new Date(String(d));
  if (isNaN(dt.getTime())) return null;
  return Math.ceil((dt.getTime() - Date.now()) / (1000 * 60 * 60 * 24));
}

function kindBadge(kind: string): string {
  switch (kind) {
    case 'root_ca':
      return '<span class="badge badge-root">Root CA</span>';
    case 'intermediate_ca':
      return '<span class="badge badge-inter">Intermediate CA</span>';
    case 'leaf_cert':
      return '<span class="badge badge-leaf">TLS Cert</span>';
    case 'csr':
      return '<span class="badge badge-csr">CSR</span>';
    default:
      return `<span class="badge badge-neutral">${esc(kind)}</span>`;
  }
}

function isIPv4(s: string): boolean {
  const parts = s.split('.');
  if (parts.length !== 4) return false;
  return parts.every((p) => /^\d+$/.test(p) && Number(p) >= 0 && Number(p) <= 255);
}

function isIPv6(s: string): boolean {
  return s.includes(':') && /^[0-9a-fA-F:]+$/.test(s);
}

function isValidDNS(s: string): boolean {
  return /^(\*\.)?[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/.test(s);
}

function classifySAN(raw: string): SanEntry | null {
  const val = raw.trim();
  if (!val) return null;
  if (isIPv4(val) || isIPv6(val)) return { type: 'ip', value: val };
  if (isValidDNS(val)) return { type: 'dns', value: val };
  return null;
}

function addSANTokens(rawText: string): boolean {
  const tokens = rawText.split(/[\s,;]+/).map((t) => t.trim()).filter(Boolean);
  if (tokens.length === 0) return false;
  let invalid = '';
  for (const tok of tokens) {
    const entry = classifySAN(tok);
    if (!entry) {
      invalid = tok;
      continue;
    }
    const exists = state.sanEntries.some((e) => e.type === entry.type && e.value.toLowerCase() === entry.value.toLowerCase());
    if (!exists) {
      state.sanEntries.push(entry);
    }
  }
  state.sanError = invalid ? `Invalid DNS name or IP address: "${invalid}"` : '';
  return true;
}

async function refreshVault() {
  state.status = await GetVaultStatus();
  if (state.status.unlocked) {
    state.items = (await ListItems()) || [];
  } else {
    state.items = [];
  }
  render();
}

function getAvailableCAs(): vault.VaultItemSummary[] {
  return state.items.filter(
    (it) => (it.kind === 'root_ca' || it.kind === 'intermediate_ca') && it.hasKey && it.hasCert
  );
}

function getIssuerOptions(selectedId = ''): string {
  const cas = getAvailableCAs();
  if (cas.length === 0) {
    return '<option value="">No CAs in vault yet — create a Root CA first</option>';
  }
  const effectiveId = selectedId || cas[0].id;
  return cas
    .map((ca) => {
      const tag = ca.kind === 'root_ca' ? 'Root CA' : 'Intermediate CA';
      const sel = ca.id === effectiveId ? 'selected' : '';
      return `<option value="${esc(ca.id)}" ${sel}>${esc(ca.name)} (${tag} • ${esc(ca.summary.keyAlgorithm)}-${ca.summary.keyBits})</option>`;
    })
    .join('');
}

function getInheritedSubject(issuerId: string): pki.SubjectOptions {
  const cas = getAvailableCAs();
  const target = cas.find((c) => c.id === issuerId) || cas[0];
  if (target?.summary?.subjectFields) {
    return target.summary.subjectFields;
  }
  return new pki.SubjectOptions({ organization: 'Homelab' });
}

function algoSelectHtml(defaultAlgo = 'ECDSA-P256'): string {
  const algos = [
    { val: 'ECDSA-P256', label: 'ECDSA P-256 (Recommended, fast & modern)' },
    { val: 'ECDSA-P384', label: 'ECDSA P-384 (High security)' },
    { val: 'Ed25519', label: 'Ed25519 (Modern Edwards curve)' },
    { val: 'RSA-2048', label: 'RSA 2048-bit (Wide compatibility)' },
    { val: 'RSA-3072', label: 'RSA 3072-bit' },
    { val: 'RSA-4096', label: 'RSA 4096-bit (High security RSA)' },
  ];
  return algos
    .map((a) => `<option value="${a.val}" ${a.val === defaultAlgo ? 'selected' : ''}>${a.label}</option>`)
    .join('');
}

function subjectFieldsHtml(cnPlaceholder: string, defaults?: Partial<pki.SubjectOptions>, collapsible = false): string {
  const fields = `
    <div class="form-grid">
      <div class="field">
        <label>Organization (O)</label>
        <input type="text" id="f-org" value="${esc(defaults?.organization ?? 'Homelab')}" placeholder="e.g. Homelab" />
      </div>
      <div class="field">
        <label>Organizational Unit (OU)</label>
        <input type="text" id="f-ou" value="${esc(defaults?.organizationalUnit ?? '')}" placeholder="e.g. Infrastructure" />
      </div>
      <div class="field">
        <label>Country (2-letter ISO)</label>
        <input type="text" id="f-country" maxlength="2" value="${esc(defaults?.country ?? '')}" placeholder="US" />
      </div>
      <div class="field">
        <label>State / Province (ST)</label>
        <input type="text" id="f-state" value="${esc(defaults?.state ?? '')}" placeholder="e.g. Texas" />
      </div>
      <div class="field span-2">
        <label>Locality / City (L)</label>
        <input type="text" id="f-locality" value="${esc(defaults?.locality ?? '')}" placeholder="e.g. Austin" />
      </div>
    </div>
  `;

  return `
    <div class="field span-2">
      <label>Common Name (CN) <span class="req">*</span></label>
      <input type="text" id="f-cn" placeholder="${esc(cnPlaceholder)}" required />
    </div>
    <div class="span-2">
      ${
        collapsible
          ? `<details class="collapsible-section">
              <summary>
                <span>Subject Details (O, OU, Country, State, Locality)</span>
                <span class="help-text" id="inherit-hint">Auto-inherited from Issuer CA</span>
              </summary>
              ${fields}
            </details>`
          : fields
      }
    </div>
  `;
}

function readSubjectFromForm(): pki.SubjectOptions {
  return new pki.SubjectOptions({
    commonName: (document.getElementById('f-cn') as HTMLInputElement).value.trim(),
    organization: (document.getElementById('f-org') as HTMLInputElement).value.trim(),
    organizationalUnit: (document.getElementById('f-ou') as HTMLInputElement).value.trim(),
    country: (document.getElementById('f-country') as HTMLInputElement).value.trim(),
    state: (document.getElementById('f-state') as HTMLInputElement).value.trim(),
    locality: (document.getElementById('f-locality') as HTMLInputElement).value.trim(),
  });
}

function renderSanBuilderHtml(): string {
  const chips = state.sanEntries
    .map(
      (s, idx) => `
      <span class="san-chip san-chip-${s.type}">
        <span class="san-chip-type">${s.type.toUpperCase()}</span>
        <span>${esc(s.value)}</span>
        <button type="button" class="san-chip-remove" data-san-remove="${idx}" title="Remove">&times;</button>
      </span>
    `
    )
    .join('');

  return `
    <div class="field span-2">
      <label>Subject Alternative Names (SANs — DNS names, wildcards, IPv4/IPv6)</label>
      <div class="san-box">
        ${chips ? `<div class="san-chips">${chips}</div>` : ''}
        <div class="san-input-row">
          <input type="text" id="san-input" class="mono" placeholder="Type or paste e.g. proxmox.home.arpa, *.home.arpa, 192.168.1.10 and press Enter" />
          <button type="button" class="btn btn-secondary btn-sm" id="btn-add-san">Add</button>
        </div>
        ${state.sanError ? `<div class="san-error">${esc(state.sanError)}</div>` : ''}
      </div>
    </div>
  `;
}

function renderLockScreen() {
  const isCreate = state.authMode === 'create';
  const exists = state.status.exists;
  appEl.innerHTML = `
    <div class="lock-screen">
      <div style="position:fixed;top:16px;right:20px;">
        <button class="btn btn-secondary btn-sm" id="btn-theme-toggle" title="Toggle theme">
          ${state.theme === 'dark' ? icons.sun : icons.moon}
          <span>${state.theme === 'dark' ? 'Mist Light' : 'Slate Dark'}</span>
        </button>
      </div>
      <div class="lock-card">
        <div class="lock-header">
          <div class="brand-icon">LC</div>
          <div>
            <h2>LabCert Vault</h2>
            <p>${isCreate ? 'Create a new password-encrypted vault.' : 'Open and unlock your encrypted PKI vault.'}</p>
          </div>
        </div>

        <div class="tabs" style="margin-bottom:16px;">
          <button type="button" class="tab-btn ${!isCreate ? 'active' : ''}" id="tab-auth-open">Open Vault</button>
          <button type="button" class="tab-btn ${isCreate ? 'active' : ''}" id="tab-auth-create">Create New Vault</button>
        </div>

        <form id="vault-auth-form" style="display:flex;flex-direction:column;gap:14px;">
          <div class="field">
            <label>Vault File</label>
            <div class="path-row">
              <input type="text" id="vault-path" value="${esc(state.status.path)}" />
              <button type="button" class="btn btn-secondary" id="btn-browse-vault">Browse</button>
            </div>
            ${
              !isCreate && !exists
                ? `<span class="help-text" style="color:var(--amber);">No vault file found at this path. Browse to an existing vault or switch to <strong>Create New Vault</strong>.</span>`
                : `<span class="help-text">Encrypted with Argon2id + AES-256-GCM.</span>`
            }
          </div>

          <div class="field">
            <label>Master Password</label>
            <input type="password" id="vault-password" placeholder="${isCreate ? 'At least 8 characters' : 'Enter vault password'}" autofocus required />
          </div>

          ${
            isCreate
              ? `
            <div class="field">
              <label>Confirm Password</label>
              <input type="password" id="vault-password-confirm" placeholder="Repeat master password" required />
            </div>
          `
              : ''
          }

          <div style="display:flex;justify-content:flex-end;margin-top:4px;">
            <button type="submit" class="btn btn-primary">
              ${isCreate ? 'Create & Unlock' : 'Unlock Vault'}
            </button>
          </div>
        </form>
      </div>
    </div>
  `;

  document.getElementById('btn-theme-toggle')?.addEventListener('click', toggleTheme);

  document.getElementById('tab-auth-open')?.addEventListener('click', () => {
    state.authMode = 'open';
    renderLockScreen();
  });

  document.getElementById('tab-auth-create')?.addEventListener('click', () => {
    state.authMode = 'create';
    renderLockScreen();
  });

  document.getElementById('vault-path')?.addEventListener('change', async (e) => {
    const val = (e.target as HTMLInputElement).value.trim();
    state.status.path = val;
    state.status.exists = await CheckVaultPath(val);
    renderLockScreen();
  });

  document.getElementById('btn-browse-vault')?.addEventListener('click', async () => {
    try {
      const picked = await ChooseVaultFile(isCreate);
      if (picked) {
        state.status.path = picked;
        state.status.exists = await CheckVaultPath(picked);
        renderLockScreen();
      }
    } catch (e) {
      showToast(errMsg(e), 'error');
    }
  });

  document.getElementById('vault-auth-form')?.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const path = (document.getElementById('vault-path') as HTMLInputElement).value.trim();
    const pw = (document.getElementById('vault-password') as HTMLInputElement).value;
    try {
      if (!isCreate) {
        await UnlockVault(path, pw);
        showToast('Vault unlocked', 'success');
      } else {
        const confirmPw = (document.getElementById('vault-password-confirm') as HTMLInputElement).value;
        if (pw !== confirmPw) {
          showToast('Passwords do not match', 'error');
          return;
        }
        await CreateVault(path, pw);
        state.authMode = 'open';
        showToast('Encrypted vault created', 'success');
      }
      await refreshVault();
    } catch (e) {
      showToast(errMsg(e), 'error');
    }
  });
}

function itemMatchesSearch(it: vault.VaultItemSummary, q: string): boolean {
  if (!q) return true;
  return (
    it.name.toLowerCase().includes(q) ||
    it.summary.commonName.toLowerCase().includes(q) ||
    (it.summary.dnsNames || []).some((d) => d.toLowerCase().includes(q)) ||
    (it.summary.ipAddresses || []).some((ip) => ip.includes(q))
  );
}

function renderItemRow(it: vault.VaultItemSummary): string {
  const days = it.hasCert ? daysRemaining(it.summary.notAfter) : null;
  const expiryBadge =
    days === null
      ? ''
      : days <= 0
      ? '<span class="badge badge-danger">Expired</span>'
      : days <= 30
      ? `<span class="badge badge-csr">Expires in ${days}d</span>`
      : `<span class="badge badge-neutral">${days}d left</span>`;
  const sansCount = (it.summary.dnsNames?.length || 0) + (it.summary.ipAddresses?.length || 0);
  const isCA = it.kind === 'root_ca' || it.kind === 'intermediate_ca';

  return `
    <div class="item-row" data-item-id="${esc(it.id)}">
      <div class="item-main">
        <div class="item-title-row">
          <span class="item-name">${esc(it.name)}</span>
          ${kindBadge(it.kind)}
          ${expiryBadge}
        </div>
        <div class="item-meta">
          <span>CN: ${esc(it.summary.commonName)}</span>
          <span>${esc(it.summary.keyAlgorithm)}-${it.summary.keyBits}</span>
          ${sansCount > 0 ? `<span>SANs: ${sansCount}</span>` : ''}
          ${it.hasCert ? `<span>Valid until ${formatDate(it.summary.notAfter)}</span>` : ''}
        </div>
      </div>
      <div class="item-actions">
        ${
          isCA && it.hasKey
            ? `
            ${
              it.kind === 'root_ca'
                ? `<button class="btn btn-secondary btn-xs" data-issue-inter="${esc(it.id)}" title="Create Intermediate CA under this Root">+ Interm</button>`
                : ''
            }
            <button class="btn btn-secondary btn-xs" data-issue-leaf="${esc(it.id)}" title="Issue TLS Certificate with this CA">+ TLS Cert</button>
          `
            : ''
        }
        <button class="btn btn-secondary btn-xs">Details</button>
      </div>
    </div>
  `;
}

function renderTreeBranch(parentId: string, childrenByParent: Map<string, vault.VaultItemSummary[]>, q: string): string {
  const children = (childrenByParent.get(parentId) || []).filter((c) => itemMatchesSearch(c, q) || hasMatchingDescendant(c.id, childrenByParent, q));
  if (children.length === 0) return '';
  return `
    <div class="tree-branch">
      ${children
        .map(
          (child) => `
          <div class="tree-node-wrap">
            ${renderItemRow(child)}
            ${renderTreeBranch(child.id, childrenByParent, q)}
          </div>
        `
        )
        .join('')}
    </div>
  `;
}

function hasMatchingDescendant(id: string, childrenByParent: Map<string, vault.VaultItemSummary[]>, q: string): boolean {
  const children = childrenByParent.get(id) || [];
  return children.some((c) => itemMatchesSearch(c, q) || hasMatchingDescendant(c.id, childrenByParent, q));
}

function renderStatsHtml(): string {
  const caCount = state.items.filter((i) => i.kind === 'root_ca' || i.kind === 'intermediate_ca').length;
  const leafCount = state.items.filter((i) => i.kind === 'leaf_cert').length;
  const csrCount = state.items.filter((i) => i.kind === 'csr').length;
  const expiringCount = state.items.filter((i) => {
    if (!i.hasCert) return false;
    const d = daysRemaining(i.summary.notAfter);
    return d !== null && d <= 30;
  }).length;

  return `
    <div class="stats-grid">
      <div class="stat-card">
        <div>
          <div class="stat-label">Authorities (CAs)</div>
          <div class="stat-value">${caCount}</div>
        </div>
        <div class="stat-icon" style="background:var(--violet-soft);color:var(--violet);">${icons.shield}</div>
      </div>
      <div class="stat-card">
        <div>
          <div class="stat-label">TLS Certificates</div>
          <div class="stat-value">${leafCount}</div>
        </div>
        <div class="stat-icon" style="background:var(--emerald-soft);color:var(--emerald);">${icons.cert}</div>
      </div>
      <div class="stat-card">
        <div>
          <div class="stat-label">Expiring (&le; 30d)</div>
          <div class="stat-value">${expiringCount}</div>
        </div>
        <div class="stat-icon" style="background:${expiringCount > 0 ? 'var(--danger-soft)' : 'var(--accent-soft)'};color:${expiringCount > 0 ? 'var(--danger)' : 'var(--accent)'};">${icons.alert}</div>
      </div>
      <div class="stat-card">
        <div>
          <div class="stat-label">Pending CSRs</div>
          <div class="stat-value">${csrCount}</div>
        </div>
        <div class="stat-icon" style="background:var(--amber-soft);color:var(--amber);">${icons.fileText}</div>
      </div>
    </div>
  `;
}

function renderVaultPage(): string {
  const q = state.searchQuery.toLowerCase();
  const stats = renderStatsHtml();

  let bodyContent = '';
  if (state.items.length === 0) {
    bodyContent = `
      <div class="empty-state">
        <h3>Your LabCert Vault is Empty</h3>
        <p>Start by creating a Root CA, then optionally an Intermediate CA, and issue TLS certificates for your homelab.</p>
      </div>
    `;
  } else if (state.vaultView === 'tree') {
    const byId = new Map(state.items.map((i) => [i.id, i]));
    const childrenByParent = new Map<string, vault.VaultItemSummary[]>();
    const roots: vault.VaultItemSummary[] = [];
    const standalones: vault.VaultItemSummary[] = [];

    for (const it of state.items) {
      if (it.issuerId && byId.has(it.issuerId)) {
        const arr = childrenByParent.get(it.issuerId) || [];
        arr.push(it);
        childrenByParent.set(it.issuerId, arr);
      } else if (it.kind === 'root_ca' || it.kind === 'intermediate_ca') {
        roots.push(it);
      } else {
        standalones.push(it);
      }
    }

    const visibleRoots = roots.filter((r) => itemMatchesSearch(r, q) || hasMatchingDescendant(r.id, childrenByParent, q));
    const visibleStandalones = standalones.filter((s) => itemMatchesSearch(s, q));

    if (visibleRoots.length === 0 && visibleStandalones.length === 0) {
      bodyContent = `<div class="empty-state"><h3>No matching items</h3><p>Try clearing your search query.</p></div>`;
    } else {
      bodyContent = `
        <div class="tree-section">
          ${visibleRoots
            .map(
              (r) => `
              <div class="tree-node-wrap">
                ${renderItemRow(r)}
                ${renderTreeBranch(r.id, childrenByParent, q)}
              </div>
            `
            )
            .join('')}
          ${
            visibleStandalones.length > 0
              ? `<div class="tree-group-title">Standalone CSRs &amp; Unlinked Certificates</div>
                 <div class="item-list">${visibleStandalones.map(renderItemRow).join('')}</div>`
              : ''
          }
        </div>
      `;
    }
  } else {
    const filtered = state.items.filter((it) => {
      if (state.filterKind !== 'all' && it.kind !== state.filterKind) return false;
      return itemMatchesSearch(it, q);
    });
    bodyContent =
      filtered.length === 0
        ? `<div class="empty-state"><h3>No matching items</h3><p>Try clearing your search or switching the filter.</p></div>`
        : `<div class="item-list">${filtered.map(renderItemRow).join('')}</div>`;
  }

  return `
    ${stats}
    <div class="toolbar">
      <div class="filter-pills">
        ${
          state.vaultView === 'list'
            ? [
                { k: 'all', label: `All (${state.items.length})` },
                { k: 'root_ca', label: 'Root CAs' },
                { k: 'intermediate_ca', label: 'Intermediates' },
                { k: 'leaf_cert', label: 'TLS Certs' },
                { k: 'csr', label: 'CSRs' },
              ]
                .map(
                  (f) =>
                    `<button class="filter-pill ${state.filterKind === f.k ? 'active' : ''}" data-filter="${f.k}">${f.label}</button>`
                )
                .join('')
            : '<span class="help-text">Showing PKI trust hierarchy (Root &rarr; Intermediate &rarr; TLS Certs)</span>'
        }
      </div>
      <div class="toolbar-right">
        <div class="view-toggle">
          <button class="view-toggle-btn ${state.vaultView === 'tree' ? 'active' : ''}" data-view="tree">${icons.tree} Tree</button>
          <button class="view-toggle-btn ${state.vaultView === 'list' ? 'active' : ''}" data-view="list">${icons.list} List</button>
        </div>
        <div class="search-box">
          <input type="text" id="vault-search" placeholder="Search name, CN, SAN..." value="${esc(state.searchQuery)}" />
        </div>
      </div>
    </div>
    ${bodyContent}
  `;
}

function renderRootCAPage(): string {
  return `
    <div class="card">
      <div class="card-header">
        <div>
          <div class="card-title">Create Self-Signed Root CA</div>
          <div class="card-subtitle">Generates an offline-grade Root Certificate Authority stored encrypted in your vault.</div>
        </div>
      </div>
      <form id="form-root-ca" class="form-grid">
        <div class="field span-2">
          <label>Friendly Label</label>
          <input type="text" id="f-name" placeholder="e.g. Homelab Root CA" />
        </div>
        ${subjectFieldsHtml('Homelab Root CA', { organization: 'Homelab' }, false)}
        <div class="field">
          <label>Key Algorithm & Size</label>
          <select id="f-algo">${algoSelectHtml('ECDSA-P384')}</select>
        </div>
        <div class="field">
          <label>Validity (Days)</label>
          <input type="number" id="f-days" value="3650" min="1" max="10950" />
        </div>
        <div class="field">
          <label>Path Length Constraint</label>
          <select id="f-pathlen">
            <option value="-1">Unconstrained (-1)</option>
            <option value="1" selected>1 (Allows Intermediate CAs)</option>
            <option value="0">0 (Leaf certs only)</option>
          </select>
        </div>
        <div class="field" style="justify-content:flex-end;align-items:flex-end;">
          <button type="submit" class="btn btn-primary">Generate Root CA</button>
        </div>
      </form>
    </div>
  `;
}

function renderIntermediateCAPage(): string {
  const inherited = getInheritedSubject(state.preselectedIssuerId);
  return `
    <div class="card">
      <div class="card-header">
        <div>
          <div class="card-title">Create Intermediate CA</div>
          <div class="card-subtitle">Signed by a Root CA; recommended for issuing day-to-day homelab TLS certificates.</div>
        </div>
      </div>
      <form id="form-inter-ca" class="form-grid">
        <div class="field span-2">
          <label>Signing Issuer CA <span class="req">*</span></label>
          <select id="f-issuer">${getIssuerOptions(state.preselectedIssuerId)}</select>
        </div>
        <div class="field span-2">
          <label>Friendly Label</label>
          <input type="text" id="f-name" placeholder="e.g. Homelab Intermediate CA" />
        </div>
        ${subjectFieldsHtml('Homelab Intermediate CA', inherited, true)}
        <div class="field">
          <label>Key Algorithm & Size</label>
          <select id="f-algo">${algoSelectHtml('ECDSA-P256')}</select>
        </div>
        <div class="field">
          <label>Validity (Days)</label>
          <input type="number" id="f-days" value="1825" min="1" max="7300" />
        </div>
        <div class="field">
          <label>Path Length Constraint</label>
          <select id="f-pathlen">
            <option value="0" selected>0 (Issues leaf certificates only)</option>
            <option value="-1">Unconstrained (-1)</option>
          </select>
        </div>
        <div class="field" style="justify-content:flex-end;align-items:flex-end;">
          <button type="submit" class="btn btn-primary">Generate Intermediate CA</button>
        </div>
      </form>
    </div>
  `;
}

function renderLeafCertPage(): string {
  const inherited = getInheritedSubject(state.preselectedIssuerId);
  return `
    <div class="card">
      <div class="card-header">
        <div>
          <div class="card-title">Issue Homelab TLS Certificate</div>
          <div class="card-subtitle">Generates a ready-to-use X.509 certificate with SANs, Key Usage, and Full Chain export.</div>
        </div>
      </div>

      <div class="preset-bar">
        <button type="button" class="btn btn-secondary btn-sm" data-preset="https">Preset: HTTPS Web Server</button>
        <button type="button" class="btn btn-secondary btn-sm" data-preset="wildcard">Preset: Wildcard (*.home.arpa)</button>
        <button type="button" class="btn btn-secondary btn-sm" data-preset="mtls">Preset: mTLS Client + Server</button>
      </div>

      <form id="form-leaf-cert" class="form-grid">
        <div class="field span-2">
          <label>Signing Issuer CA <span class="req">*</span></label>
          <select id="f-issuer">${getIssuerOptions(state.preselectedIssuerId)}</select>
        </div>
        <div class="field span-2">
          <label>Friendly Label</label>
          <input type="text" id="f-name" placeholder="e.g. proxmox.home.arpa" />
        </div>
        ${subjectFieldsHtml('proxmox.home.arpa', inherited, true)}
        ${renderSanBuilderHtml()}
        <div class="field">
          <label>Key Algorithm & Size</label>
          <select id="f-algo">${algoSelectHtml('ECDSA-P256')}</select>
        </div>
        <div class="field">
          <label>Validity (Days)</label>
          <input type="number" id="f-days" value="365" min="1" max="3650" />
        </div>
        <div class="field span-2">
          <label>Key Usage</label>
          <div class="checkbox-group">
            <label class="check-chip"><input type="checkbox" name="ku" value="digitalSignature" checked /> Digital Signature</label>
            <label class="check-chip"><input type="checkbox" name="ku" value="keyEncipherment" checked /> Key Encipherment</label>
            <label class="check-chip"><input type="checkbox" name="ku" value="contentCommitment" /> Content Commitment</label>
            <label class="check-chip"><input type="checkbox" name="ku" value="keyAgreement" /> Key Agreement</label>
          </div>
        </div>
        <div class="field span-2">
          <label>Extended Key Usage (EKU)</label>
          <div class="checkbox-group">
            <label class="check-chip"><input type="checkbox" name="eku" value="serverAuth" checked /> Server Auth (TLS/HTTPS)</label>
            <label class="check-chip"><input type="checkbox" name="eku" value="clientAuth" /> Client Auth (mTLS)</label>
            <label class="check-chip"><input type="checkbox" name="eku" value="codeSigning" /> Code Signing</label>
            <label class="check-chip"><input type="checkbox" name="eku" value="emailProtection" /> Email Protection</label>
          </div>
        </div>
        <div class="span-2" style="display:flex;justify-content:flex-end;">
          <button type="submit" class="btn btn-primary">Issue TLS Certificate</button>
        </div>
      </form>
    </div>
  `;
}

function renderCSRPage(): string {
  const storedCSRs = state.items.filter((i) => i.kind === 'csr');
  return `
    <div class="tabs">
      <button class="tab-btn ${state.csrTab === 'generate' ? 'active' : ''}" data-csr-tab="generate">Generate CSR & Key</button>
      <button class="tab-btn ${state.csrTab === 'sign' ? 'active' : ''}" data-csr-tab="sign">Sign a CSR</button>
    </div>

    ${
      state.csrTab === 'generate'
        ? `
      <div class="card">
        <div class="card-header">
          <div>
            <div class="card-title">Generate Certificate Signing Request (PKCS#10)</div>
            <div class="card-subtitle">Creates a CSR and stores its encrypted private key in your vault.</div>
          </div>
        </div>
        <form id="form-gen-csr" class="form-grid">
          <div class="field span-2">
            <label>Friendly Label</label>
            <input type="text" id="f-name" placeholder="e.g. truenas.home.arpa CSR" />
          </div>
          ${subjectFieldsHtml('truenas.home.arpa', { organization: 'Homelab' }, true)}
          ${renderSanBuilderHtml()}
          <div class="field">
            <label>Key Algorithm & Size</label>
            <select id="f-algo">${algoSelectHtml('ECDSA-P256')}</select>
          </div>
          <div class="field" style="justify-content:flex-end;align-items:flex-end;">
            <button type="submit" class="btn btn-primary">Generate CSR</button>
          </div>
        </form>
      </div>
    `
        : `
      <div class="card">
        <div class="card-header">
          <div>
            <div class="card-title">Sign Certificate Signing Request</div>
            <div class="card-subtitle">Sign an external CSR (paste or open file) or a CSR stored in your vault.</div>
          </div>
          <button type="button" class="btn btn-secondary btn-sm" id="btn-open-csr-file">Load .csr File</button>
        </div>
        <form id="form-sign-csr" class="form-grid">
          <div class="field span-2">
            <label>Signing Issuer CA <span class="req">*</span></label>
            <select id="f-issuer">${getIssuerOptions(state.preselectedIssuerId)}</select>
          </div>
          <div class="field">
            <label>Or Pick Stored CSR</label>
            <select id="f-stored-csr">
              <option value="">— Paste external CSR below —</option>
              ${storedCSRs.map((c) => `<option value="${esc(c.id)}">${esc(c.name)} (${esc(c.summary.commonName)})</option>`).join('')}
            </select>
          </div>
          <div class="field">
            <label>Friendly Label</label>
            <input type="text" id="f-name" placeholder="Optional label for signed cert" />
          </div>
          <div class="field span-2">
            <label>CSR PEM</label>
            <textarea id="f-csr-pem" rows="6" class="mono" placeholder="-----BEGIN CERTIFICATE REQUEST-----&#10;..."></textarea>
          </div>
          <div class="field">
            <label>Validity (Days)</label>
            <input type="number" id="f-days" value="365" min="1" max="3650" />
          </div>
          <div class="field">
            <label>Certificate Type</label>
            <select id="f-sign-isca">
              <option value="false" selected>End-Entity TLS Certificate</option>
              <option value="true">Intermediate CA</option>
            </select>
          </div>
          <div class="field span-2">
            <label>Extended Key Usage</label>
            <div class="checkbox-group">
              <label class="check-chip"><input type="checkbox" name="eku" value="serverAuth" checked /> Server Auth</label>
              <label class="check-chip"><input type="checkbox" name="eku" value="clientAuth" /> Client Auth</label>
              <label class="check-chip"><input type="checkbox" name="eku" value="codeSigning" /> Code Signing</label>
            </div>
          </div>
          <div class="span-2" style="display:flex;justify-content:flex-end;">
            <button type="submit" class="btn btn-primary">Sign CSR</button>
          </div>
        </form>
      </div>
    `
    }
  `;
}

function renderSummaryKV(s: pki.CertSummary): string {
  return `
    <div class="kv-grid">
      <div class="kv-label">Common Name</div><div class="kv-val">${esc(s.commonName)}</div>
      <div class="kv-label">Subject</div><div class="kv-val mono">${esc(s.subject)}</div>
      ${s.issuer ? `<div class="kv-label">Issuer</div><div class="kv-val mono">${esc(s.issuer)}</div>` : ''}
      ${s.serialHex ? `<div class="kv-label">Serial (Hex)</div><div class="kv-val mono">${esc(s.serialHex)}</div>` : ''}
      ${
        s.notBefore
          ? `<div class="kv-label">Validity</div><div class="kv-val">${formatDate(s.notBefore)} &rarr; ${formatDate(s.notAfter)}</div>`
          : ''
      }
      <div class="kv-label">Key</div><div class="kv-val">${esc(s.keyAlgorithm)} (${s.keyBits}-bit) &bull; ${esc(s.signatureAlgorithm)}</div>
      ${s.isCA ? `<div class="kv-label">CA Constraints</div><div class="kv-val">IsCA: true &bull; PathLen: ${s.pathLen >= 0 ? s.pathLen : 'Unconstrained'}</div>` : ''}
      ${s.dnsNames?.length ? `<div class="kv-label">DNS SANs</div><div class="kv-val mono">${esc(s.dnsNames.join(', '))}</div>` : ''}
      ${s.ipAddresses?.length ? `<div class="kv-label">IP SANs</div><div class="kv-val mono">${esc(s.ipAddresses.join(', '))}</div>` : ''}
      ${s.keyUsages?.length ? `<div class="kv-label">Key Usage</div><div class="kv-val">${esc(s.keyUsages.join(', '))}</div>` : ''}
      ${s.extKeyUsages?.length ? `<div class="kv-label">Ext Key Usage</div><div class="kv-val">${esc(s.extKeyUsages.join(', '))}</div>` : ''}
      <div class="kv-label">SHA-256</div><div class="kv-val mono">${esc(s.sha256Fingerprint)}</div>
    </div>
  `;
}

function renderInspectorPage(): string {
  const res = state.inspectResult;
  const ver = state.verifyResult;
  return `
    <div class="card">
      <div class="card-header">
        <div>
          <div class="card-title">X.509 Certificate & CSR Inspector</div>
          <div class="card-subtitle">Paste any PEM certificate, chain, or CSR, or load a file from disk.</div>
        </div>
        <button type="button" class="btn btn-secondary btn-sm" id="btn-inspect-open">Open File</button>
      </div>
      <div class="field">
        <textarea id="inspect-pem" rows="7" class="mono" placeholder="-----BEGIN CERTIFICATE-----&#10;...">${esc(state.inspectInput)}</textarea>
      </div>
      <div style="display:flex;justify-content:flex-end;gap:10px;margin-top:12px;">
        <button type="button" class="btn btn-secondary" id="btn-inspect-clear">Clear</button>
        <button type="button" class="btn btn-primary" id="btn-inspect-run">Inspect PEM</button>
      </div>
    </div>

    ${
      res
        ? `
      <div class="card">
        <div class="card-header">
          <div class="card-title">Parsed ${res.type === 'csr' ? 'Certificate Signing Request' : `Certificate (${res.items.length})`}</div>
          ${ver ? `<span class="badge ${ver.valid ? 'badge-leaf' : 'badge-danger'}">${esc(ver.message)}</span>` : ''}
        </div>
        ${res.warning ? `<p style="color:var(--amber);margin-bottom:12px;">${esc(res.warning)}</p>` : ''}
        ${res.items
          .map(
            (item, idx) => `
            ${idx > 0 ? '<div class="divider" style="margin:14px 0;"></div>' : ''}
            ${renderSummaryKV(item)}
          `
          )
          .join('')}
      </div>
    `
        : ''
    }
  `;
}

function renderDetailDrawer(): string {
  const it = state.selectedItem;
  if (!it || !state.selectedPEMs) return '';
  const pems = state.selectedPEMs;

  let tabContent = '';
  if (state.drawerTab === 'overview') {
    tabContent = renderSummaryKV(it.summary);
  } else if (state.drawerTab === 'pem') {
    tabContent = `
      ${
        pems.certPem
          ? `
        <div class="field">
          <div style="display:flex;justify-content:space-between;align-items:center;">
            <label>Certificate PEM</label>
            <div style="display:flex;gap:6px;">
              <button class="btn btn-secondary btn-xs" data-copy="cert">Copy Cert</button>
              <button class="btn btn-secondary btn-xs" data-copy="fullchain">Copy Full Chain</button>
            </div>
          </div>
          <div class="pem-box">${esc(pems.certPem)}</div>
        </div>
      `
          : ''
      }
      ${
        pems.csrPem
          ? `
        <div class="field">
          <div style="display:flex;justify-content:space-between;align-items:center;">
            <label>CSR PEM</label>
            <button class="btn btn-secondary btn-xs" data-copy="csr">Copy CSR</button>
          </div>
          <div class="pem-box">${esc(pems.csrPem)}</div>
        </div>
      `
          : ''
      }
      ${
        pems.hasKey
          ? `
        <div class="field">
          <div style="display:flex;justify-content:space-between;align-items:center;">
            <label>Private Key (Encrypted in Vault)</label>
            <button class="btn btn-secondary btn-xs" id="btn-reveal-key">
              ${state.revealedKey ? 'Copy Private Key' : 'Reveal Private Key'}
            </button>
          </div>
          ${state.revealedKey ? `<div class="pem-box">${esc(state.revealedKey)}</div>` : '<span class="help-text">Hidden by default for security.</span>'}
        </div>
      `
          : ''
      }
    `;
  } else {
    tabContent = `
      <div class="export-grid">
        ${
          pems.certPem
            ? `<div class="export-card">
                <strong>Certificate (.crt)</strong>
                <span>Public X.509 certificate in PEM format.</span>
                <button class="btn btn-secondary btn-sm" data-export="cert">Save .crt</button>
              </div>
              <div class="export-card">
                <strong>Full Chain (.pem)</strong>
                <span>Leaf + Intermediate + Root CA bundle.</span>
                <button class="btn btn-secondary btn-sm" data-export="fullchain">Save Full Chain</button>
              </div>`
            : ''
        }
        ${
          pems.hasKey
            ? `<div class="export-card">
                <strong>Private Key (.key)</strong>
                <span>Unencrypted PKCS#8 PEM key for servers.</span>
                <button class="btn btn-secondary btn-sm" data-export="key">Save .key</button>
              </div>`
            : ''
        }
        ${
          pems.csrPem
            ? `<div class="export-card">
                <strong>CSR (.csr)</strong>
                <span>PKCS#10 Certificate Signing Request.</span>
                <button class="btn btn-secondary btn-sm" data-export="csr">Save .csr</button>
              </div>`
            : ''
        }
        ${
          pems.certPem && pems.hasKey
            ? `<div class="export-card">
                <strong>PKCS#12 (.p12 / .pfx)</strong>
                <span>Password-protected bundle with key &amp; chain.</span>
                <button class="btn btn-primary btn-sm" id="btn-export-p12">Save .p12</button>
              </div>`
            : ''
        }
      </div>
    `;
  }

  return `
    <div class="drawer-backdrop" id="drawer-backdrop">
      <div class="drawer">
        <div class="drawer-header">
          <div style="display:flex;align-items:center;gap:10px;min-width:0;">
            <strong style="font-size:15px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${esc(it.name)}</strong>
            ${kindBadge(it.kind)}
          </div>
          <button class="btn btn-secondary btn-sm" id="btn-close-drawer">Close</button>
        </div>

        <div class="drawer-tabs">
          <button class="tab-btn ${state.drawerTab === 'overview' ? 'active' : ''}" data-drawer-tab="overview">Overview</button>
          <button class="tab-btn ${state.drawerTab === 'pem' ? 'active' : ''}" data-drawer-tab="pem">PEM &amp; Key</button>
          <button class="tab-btn ${state.drawerTab === 'export' ? 'active' : ''}" data-drawer-tab="export">Export</button>
        </div>

        <div class="drawer-body">${tabContent}</div>

        <div class="drawer-footer">
          <span class="help-text">Created ${formatDate(it.createdAt)}</span>
          <button class="btn btn-danger btn-sm" id="btn-delete-item">Delete Item</button>
        </div>
      </div>
    </div>
  `;
}

function renderP12Modal(): string {
  if (!state.p12ExportTargetId) return '';
  return `
    <div class="modal-backdrop" id="p12-backdrop">
      <div class="modal">
        <div class="modal-header">
          <strong>Export PKCS#12 (.p12 / .pfx)</strong>
          <button class="btn btn-secondary btn-sm" id="btn-p12-cancel">Cancel</button>
        </div>
        <form id="form-p12" class="modal-body">
          <div class="field">
            <label>Bundle Password</label>
            <input type="password" id="p12-pass" placeholder="Leave blank or enter export password" autofocus />
            <span class="help-text">Protects the private key inside the .p12 / .pfx file.</span>
          </div>
          <div style="display:flex;justify-content:flex-end;gap:8px;">
            <button type="submit" class="btn btn-primary">Save .p12 File</button>
          </div>
        </form>
      </div>
    </div>
  `;
}

function renderChangePasswordModal(): string {
  if (!state.showChangePasswordModal) return '';
  return `
    <div class="modal-backdrop" id="cpw-backdrop">
      <div class="modal">
        <div class="modal-header">
          <strong>Change Vault Password</strong>
          <button class="btn btn-secondary btn-sm" id="btn-cpw-cancel">Cancel</button>
        </div>
        <form id="form-cpw" class="modal-body">
          <div class="field">
            <label>New Master Password</label>
            <input type="password" id="cpw-new" placeholder="At least 8 characters" required autofocus />
          </div>
          <div class="field">
            <label>Confirm New Password</label>
            <input type="password" id="cpw-confirm" placeholder="Repeat new password" required />
          </div>
          <div style="display:flex;justify-content:flex-end;gap:8px;">
            <button type="submit" class="btn btn-primary">Update Password</button>
          </div>
        </form>
      </div>
    </div>
  `;
}

function renderConfirmModal(): string {
  if (!state.confirmDialog) return '';
  return `
    <div class="modal-backdrop" id="confirm-backdrop">
      <div class="modal">
        <div class="modal-header">
          <strong>${esc(state.confirmDialog.title)}</strong>
          <button class="btn btn-secondary btn-sm" id="btn-confirm-cancel">Cancel</button>
        </div>
        <div class="modal-body">
          <p style="color:var(--text-secondary);font-size:13.5px;">${esc(state.confirmDialog.message)}</p>
          <div style="display:flex;justify-content:flex-end;gap:8px;">
            <button class="btn btn-secondary" id="btn-confirm-no">Cancel</button>
            <button class="btn btn-danger" id="btn-confirm-yes">${esc(state.confirmDialog.confirmLabel)}</button>
          </div>
        </div>
      </div>
    </div>
  `;
}

function render() {
  if (!state.status.unlocked) {
    renderLockScreen();
    return;
  }

  const pageTitles: Record<Page, string> = {
    vault: 'Encrypted Vault',
    'root-ca': 'Create Root CA',
    'intermediate-ca': 'Create Intermediate CA',
    'leaf-cert': 'Issue TLS Certificate',
    csr: 'CSR Tools',
    inspector: 'Certificate Inspector',
  };

  let bodyHtml = '';
  switch (state.page) {
    case 'vault':
      bodyHtml = renderVaultPage();
      break;
    case 'root-ca':
      bodyHtml = renderRootCAPage();
      break;
    case 'intermediate-ca':
      bodyHtml = renderIntermediateCAPage();
      break;
    case 'leaf-cert':
      bodyHtml = renderLeafCertPage();
      break;
    case 'csr':
      bodyHtml = renderCSRPage();
      break;
    case 'inspector':
      bodyHtml = renderInspectorPage();
      break;
  }

  appEl.innerHTML = `
    <div class="shell">
      <aside class="sidebar">
        <div class="brand">
          <div class="brand-icon">LC</div>
          <div class="brand-text">
            <h1>LabCert</h1>
            <span>Homelab PKI Studio</span>
          </div>
        </div>

        <div class="nav-group">
          <div class="nav-label">Workspace</div>
          <button class="nav-btn ${state.page === 'vault' ? 'active' : ''}" data-nav="vault">${icons.vault}<span>Vault (${state.items.length})</span></button>
          <button class="nav-btn ${state.page === 'inspector' ? 'active' : ''}" data-nav="inspector">${icons.search}<span>Inspector</span></button>
        </div>

        <div class="nav-group">
          <div class="nav-label">PKI &amp; Certificates</div>
          <button class="nav-btn ${state.page === 'root-ca' ? 'active' : ''}" data-nav="root-ca">${icons.shield}<span>Root CA</span></button>
          <button class="nav-btn ${state.page === 'intermediate-ca' ? 'active' : ''}" data-nav="intermediate-ca">${icons.layers}<span>Intermediate CA</span></button>
          <button class="nav-btn ${state.page === 'leaf-cert' ? 'active' : ''}" data-nav="leaf-cert">${icons.cert}<span>Issue TLS Cert</span></button>
          <button class="nav-btn ${state.page === 'csr' ? 'active' : ''}" data-nav="csr">${icons.fileText}<span>CSR Tools</span></button>
        </div>

        <div class="sidebar-footer">
          <div class="vault-pill">
            <div class="vault-pill-row">
              <span><span class="vault-status-dot"></span>Unlocked</span>
              <button class="btn btn-secondary btn-xs" id="btn-lock-vault">${icons.lock} Lock</button>
            </div>
            <div class="vault-path-text" title="${esc(state.status.path)}">${esc(state.status.path)}</div>
          </div>
          <button class="btn btn-secondary btn-sm" id="btn-change-pw">Change Vault Password</button>
        </div>
      </aside>

      <div class="main">
        <header class="topbar">
          <div class="topbar-title">${pageTitles[state.page]}</div>
          <div class="topbar-actions">
            <button class="btn btn-secondary btn-sm" id="btn-theme-toggle" title="Switch color theme">
              ${state.theme === 'dark' ? icons.sun : icons.moon}
              <span>${state.theme === 'dark' ? 'Mist Light' : 'Slate Dark'}</span>
            </button>
            ${
              state.page === 'vault'
                ? '<button class="btn btn-primary btn-sm" id="btn-quick-issue">+ Issue TLS Cert</button>'
                : ''
            }
          </div>
        </header>
        <main class="content">${bodyHtml}</main>
      </div>
    </div>
    ${renderDetailDrawer()}
    ${renderP12Modal()}
    ${renderChangePasswordModal()}
    ${renderConfirmModal()}
  `;

  attachHandlers();
}

function attachSANHandlers() {
  const sanInput = document.getElementById('san-input') as HTMLInputElement | null;
  const commitInput = () => {
    if (!sanInput) return;
    if (addSANTokens(sanInput.value)) {
      sanInput.value = '';
      render();
      document.getElementById('san-input')?.focus();
    }
  };
  document.getElementById('btn-add-san')?.addEventListener('click', commitInput);
  sanInput?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ',') {
      e.preventDefault();
      commitInput();
    }
  });
  document.querySelectorAll<HTMLElement>('[data-san-remove]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const idx = Number(btn.dataset.sanRemove);
      state.sanEntries.splice(idx, 1);
      render();
    });
  });
}

function attachIssuerInheritanceHandler() {
  const issuerSelect = document.getElementById('f-issuer') as HTMLSelectElement | null;
  issuerSelect?.addEventListener('change', () => {
    state.preselectedIssuerId = issuerSelect.value;
    const inherited = getInheritedSubject(issuerSelect.value);
    const setVal = (id: string, v?: string) => {
      const el = document.getElementById(id) as HTMLInputElement | null;
      if (el) el.value = v || '';
    };
    setVal('f-org', inherited.organization);
    setVal('f-ou', inherited.organizationalUnit);
    setVal('f-country', inherited.country);
    setVal('f-state', inherited.state);
    setVal('f-locality', inherited.locality);
  });
}

function attachHandlers() {
  document.getElementById('btn-theme-toggle')?.addEventListener('click', toggleTheme);

  document.querySelectorAll<HTMLElement>('[data-nav]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const next = btn.dataset.nav as Page;
      if (next !== state.page) {
        state.sanEntries = [];
        state.sanError = '';
        state.preselectedIssuerId = '';
      }
      state.page = next;
      render();
    });
  });

  document.getElementById('btn-quick-issue')?.addEventListener('click', () => {
    state.sanEntries = [];
    state.sanError = '';
    state.page = 'leaf-cert';
    render();
  });

  document.getElementById('btn-lock-vault')?.addEventListener('click', async () => {
    await LockVault();
    state.selectedItem = null;
    state.selectedPEMs = null;
    state.revealedKey = null;
    await refreshVault();
    showToast('Vault locked');
  });

  document.getElementById('btn-change-pw')?.addEventListener('click', () => {
    state.showChangePasswordModal = true;
    render();
  });

  // Vault view toggle, filters & search
  document.querySelectorAll<HTMLElement>('[data-view]').forEach((btn) => {
    btn.addEventListener('click', () => {
      state.vaultView = btn.dataset.view as VaultView;
      render();
    });
  });

  document.querySelectorAll<HTMLElement>('[data-filter]').forEach((btn) => {
    btn.addEventListener('click', () => {
      state.filterKind = btn.dataset.filter || 'all';
      render();
    });
  });

  document.getElementById('vault-search')?.addEventListener('input', (e) => {
    state.searchQuery = (e.target as HTMLInputElement).value;
    render();
    const el = document.getElementById('vault-search') as HTMLInputElement | null;
    if (el) {
      el.focus();
      el.setSelectionRange(el.value.length, el.value.length);
    }
  });

  // Contextual CA quick-issue buttons
  document.querySelectorAll<HTMLElement>('[data-issue-inter]').forEach((btn) => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      state.preselectedIssuerId = btn.dataset.issueInter || '';
      state.page = 'intermediate-ca';
      render();
    });
  });

  document.querySelectorAll<HTMLElement>('[data-issue-leaf]').forEach((btn) => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      state.preselectedIssuerId = btn.dataset.issueLeaf || '';
      state.sanEntries = [];
      state.sanError = '';
      state.page = 'leaf-cert';
      render();
    });
  });

  document.querySelectorAll<HTMLElement>('[data-item-id]').forEach((row) => {
    row.addEventListener('click', async () => {
      const id = row.dataset.itemId!;
      const item = state.items.find((i) => i.id === id);
      if (!item) return;
      try {
        state.selectedItem = item;
        state.selectedPEMs = await GetItemPEM(id);
        state.drawerTab = 'overview';
        state.revealedKey = null;
        render();
      } catch (e) {
        showToast(errMsg(e), 'error');
      }
    });
  });

  // Root CA Form
  document.getElementById('form-root-ca')?.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    try {
      const opts = new pki.CertOptions({
        name: (document.getElementById('f-name') as HTMLInputElement).value.trim(),
        subject: readSubjectFromForm(),
        keyAlgorithm: (document.getElementById('f-algo') as HTMLSelectElement).value,
        validityDays: parseInt((document.getElementById('f-days') as HTMLInputElement).value, 10) || 3650,
        pathLen: parseInt((document.getElementById('f-pathlen') as HTMLSelectElement).value, 10),
      });
      await CreateRootCA(opts);
      showToast('Root CA created and encrypted in vault', 'success');
      state.page = 'vault';
      await refreshVault();
    } catch (e) {
      showToast(errMsg(e), 'error');
    }
  });

  // Intermediate CA Form
  attachIssuerInheritanceHandler();
  document.getElementById('form-inter-ca')?.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    try {
      const issuerId = (document.getElementById('f-issuer') as HTMLSelectElement).value;
      if (!issuerId) {
        showToast('Please create or select an Issuer CA first', 'error');
        return;
      }
      const opts = new pki.CertOptions({
        issuerId,
        name: (document.getElementById('f-name') as HTMLInputElement).value.trim(),
        subject: readSubjectFromForm(),
        keyAlgorithm: (document.getElementById('f-algo') as HTMLSelectElement).value,
        validityDays: parseInt((document.getElementById('f-days') as HTMLInputElement).value, 10) || 1825,
        pathLen: parseInt((document.getElementById('f-pathlen') as HTMLSelectElement).value, 10),
      });
      await CreateIntermediateCA(opts);
      showToast('Intermediate CA created', 'success');
      state.page = 'vault';
      await refreshVault();
    } catch (e) {
      showToast(errMsg(e), 'error');
    }
  });

  // Leaf Cert Presets & SANs
  attachSANHandlers();
  document.querySelectorAll<HTMLElement>('[data-preset]').forEach((btn) => {
    btn.addEventListener('click', () => {
      const preset = btn.dataset.preset;
      const cn = document.getElementById('f-cn') as HTMLInputElement;
      const ekus = document.querySelectorAll<HTMLInputElement>('input[name="eku"]');
      if (preset === 'https') {
        if (!cn.value) cn.value = 'service.home.arpa';
        if (state.sanEntries.length === 0) addSANTokens('service.home.arpa');
        ekus.forEach((c) => (c.checked = c.value === 'serverAuth'));
        render();
      } else if (preset === 'wildcard') {
        state.sanEntries = [];
        addSANTokens('*.home.arpa home.arpa');
        render();
        const cnAfter = document.getElementById('f-cn') as HTMLInputElement | null;
        if (cnAfter) cnAfter.value = '*.home.arpa';
        document.querySelectorAll<HTMLInputElement>('input[name="eku"]').forEach((c) => (c.checked = c.value === 'serverAuth'));
      } else if (preset === 'mtls') {
        if (!cn.value) cn.value = 'node-01.home.arpa';
        ekus.forEach((c) => (c.checked = c.value === 'serverAuth' || c.value === 'clientAuth'));
      }
    });
  });

  document.getElementById('form-leaf-cert')?.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const pendingSan = (document.getElementById('san-input') as HTMLInputElement | null)?.value || '';
    if (pendingSan.trim()) addSANTokens(pendingSan);
    if (state.sanError) {
      showToast(state.sanError, 'error');
      render();
      return;
    }
    try {
      const issuerId = (document.getElementById('f-issuer') as HTMLSelectElement).value;
      if (!issuerId) {
        showToast('Please create or select an Issuer CA first', 'error');
        return;
      }
      const keyUsages = Array.from(document.querySelectorAll<HTMLInputElement>('input[name="ku"]:checked')).map((c) => c.value);
      const extKeyUsages = Array.from(document.querySelectorAll<HTMLInputElement>('input[name="eku"]:checked')).map((c) => c.value);
      const opts = new pki.CertOptions({
        issuerId,
        name: (document.getElementById('f-name') as HTMLInputElement).value.trim(),
        subject: readSubjectFromForm(),
        dnsNames: state.sanEntries.filter((s) => s.type === 'dns').map((s) => s.value),
        ipAddresses: state.sanEntries.filter((s) => s.type === 'ip').map((s) => s.value),
        keyAlgorithm: (document.getElementById('f-algo') as HTMLSelectElement).value,
        validityDays: parseInt((document.getElementById('f-days') as HTMLInputElement).value, 10) || 365,
        keyUsages,
        extKeyUsages,
      });
      await CreateLeafCert(opts);
      showToast('TLS certificate issued and saved to vault', 'success');
      state.sanEntries = [];
      state.page = 'vault';
      await refreshVault();
    } catch (e) {
      showToast(errMsg(e), 'error');
    }
  });

  // CSR Tabs & Forms
  document.querySelectorAll<HTMLElement>('[data-csr-tab]').forEach((btn) => {
    btn.addEventListener('click', () => {
      state.csrTab = btn.dataset.csrTab as 'generate' | 'sign';
      render();
    });
  });

  document.getElementById('form-gen-csr')?.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const pendingSan = (document.getElementById('san-input') as HTMLInputElement | null)?.value || '';
    if (pendingSan.trim()) addSANTokens(pendingSan);
    if (state.sanError) {
      showToast(state.sanError, 'error');
      render();
      return;
    }
    try {
      const opts = new pki.CertOptions({
        name: (document.getElementById('f-name') as HTMLInputElement).value.trim(),
        subject: readSubjectFromForm(),
        dnsNames: state.sanEntries.filter((s) => s.type === 'dns').map((s) => s.value),
        ipAddresses: state.sanEntries.filter((s) => s.type === 'ip').map((s) => s.value),
        keyAlgorithm: (document.getElementById('f-algo') as HTMLSelectElement).value,
      });
      await CreateCSR(opts);
      showToast('CSR and encrypted private key saved to vault', 'success');
      state.sanEntries = [];
      state.page = 'vault';
      await refreshVault();
    } catch (e) {
      showToast(errMsg(e), 'error');
    }
  });

  document.getElementById('btn-open-csr-file')?.addEventListener('click', async () => {
    try {
      const text = await OpenPEMFile();
      if (text) (document.getElementById('f-csr-pem') as HTMLTextAreaElement).value = text;
    } catch (e) {
      showToast(errMsg(e), 'error');
    }
  });

  document.getElementById('form-sign-csr')?.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    try {
      const issuerId = (document.getElementById('f-issuer') as HTMLSelectElement).value;
      if (!issuerId) {
        showToast('Please select an Issuer CA', 'error');
        return;
      }
      const extKeyUsages = Array.from(document.querySelectorAll<HTMLInputElement>('input[name="eku"]:checked')).map((c) => c.value);
      const isCA = (document.getElementById('f-sign-isca') as HTMLSelectElement).value === 'true';
      const req = new main.SignCSRRequest({
        name: (document.getElementById('f-name') as HTMLInputElement).value.trim(),
        issuerId,
        storedCsrId: (document.getElementById('f-stored-csr') as HTMLSelectElement).value,
        csrPem: (document.getElementById('f-csr-pem') as HTMLTextAreaElement).value.trim(),
        validityDays: parseInt((document.getElementById('f-days') as HTMLInputElement).value, 10) || 365,
        isCA,
        pathLen: isCA ? 0 : -1,
        extKeyUsages,
      });
      await SignCSR(req);
      showToast('CSR signed and certificate saved to vault', 'success');
      state.page = 'vault';
      await refreshVault();
    } catch (e) {
      showToast(errMsg(e), 'error');
    }
  });

  // Inspector
  document.getElementById('btn-inspect-open')?.addEventListener('click', async () => {
    try {
      const text = await OpenPEMFile();
      if (text) {
        state.inspectInput = text;
        render();
      }
    } catch (e) {
      showToast(errMsg(e), 'error');
    }
  });

  document.getElementById('btn-inspect-clear')?.addEventListener('click', () => {
    state.inspectInput = '';
    state.inspectResult = null;
    state.verifyResult = null;
    render();
  });

  document.getElementById('btn-inspect-run')?.addEventListener('click', async () => {
    const pem = (document.getElementById('inspect-pem') as HTMLTextAreaElement).value;
    state.inspectInput = pem;
    try {
      state.inspectResult = await InspectPEM(pem);
      state.verifyResult = state.inspectResult.type === 'certificate' ? await VerifyCertificate(pem) : null;
      render();
    } catch (e) {
      showToast(errMsg(e), 'error');
    }
  });

  // Detail Drawer
  const closeDrawer = () => {
    state.selectedItem = null;
    state.selectedPEMs = null;
    state.revealedKey = null;
    render();
  };
  document.getElementById('btn-close-drawer')?.addEventListener('click', closeDrawer);
  document.getElementById('drawer-backdrop')?.addEventListener('click', (e) => {
    if (e.target === document.getElementById('drawer-backdrop')) closeDrawer();
  });

  document.querySelectorAll<HTMLElement>('[data-drawer-tab]').forEach((btn) => {
    btn.addEventListener('click', () => {
      state.drawerTab = btn.dataset.drawerTab as DrawerTab;
      render();
    });
  });

  document.querySelectorAll<HTMLElement>('[data-copy]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      if (!state.selectedPEMs) return;
      const which = btn.dataset.copy;
      const text =
        which === 'cert'
          ? state.selectedPEMs.certPem
          : which === 'fullchain'
          ? state.selectedPEMs.fullChainPem
          : state.selectedPEMs.csrPem;
      await navigator.clipboard.writeText(text);
      showToast('Copied to clipboard', 'success');
    });
  });

  document.getElementById('btn-reveal-key')?.addEventListener('click', async () => {
    if (!state.selectedItem) return;
    if (state.revealedKey) {
      await navigator.clipboard.writeText(state.revealedKey);
      showToast('Private key copied to clipboard', 'success');
      return;
    }
    try {
      state.revealedKey = await RevealPrivateKey(state.selectedItem.id);
      render();
    } catch (e) {
      showToast(errMsg(e), 'error');
    }
  });

  document.querySelectorAll<HTMLElement>('[data-export]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      if (!state.selectedItem) return;
      try {
        const saved = await ExportArtifact(state.selectedItem.id, btn.dataset.export!, '');
        if (saved) showToast(`Saved to ${saved}`, 'success');
      } catch (e) {
        showToast(errMsg(e), 'error');
      }
    });
  });

  document.getElementById('btn-export-p12')?.addEventListener('click', () => {
    if (!state.selectedItem) return;
    state.p12ExportTargetId = state.selectedItem.id;
    render();
  });

  document.getElementById('btn-delete-item')?.addEventListener('click', () => {
    const target = state.selectedItem;
    if (!target) return;
    state.confirmDialog = {
      title: 'Delete Item',
      message: `Are you sure you want to permanently delete "${target.name}" from your encrypted vault?`,
      confirmLabel: 'Delete',
      onConfirm: async () => {
        await DeleteItem(target.id);
        state.selectedItem = null;
        state.selectedPEMs = null;
        state.revealedKey = null;
        state.confirmDialog = null;
        await refreshVault();
        showToast('Item deleted');
      },
    };
    render();
  });

  // Confirm Dialog
  const closeConfirm = () => {
    state.confirmDialog = null;
    render();
  };
  document.getElementById('btn-confirm-cancel')?.addEventListener('click', closeConfirm);
  document.getElementById('btn-confirm-no')?.addEventListener('click', closeConfirm);
  document.getElementById('btn-confirm-yes')?.addEventListener('click', async () => {
    if (!state.confirmDialog) return;
    try {
      await state.confirmDialog.onConfirm();
    } catch (e) {
      state.confirmDialog = null;
      render();
      showToast(errMsg(e), 'error');
    }
  });

  // P12 Modal
  document.getElementById('btn-p12-cancel')?.addEventListener('click', () => {
    state.p12ExportTargetId = null;
    render();
  });
  document.getElementById('form-p12')?.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const id = state.p12ExportTargetId;
    const pw = (document.getElementById('p12-pass') as HTMLInputElement).value;
    if (!id) return;
    try {
      const saved = await ExportArtifact(id, 'p12', pw);
      state.p12ExportTargetId = null;
      render();
      if (saved) showToast(`Saved PKCS#12 to ${saved}`, 'success');
    } catch (e) {
      showToast(errMsg(e), 'error');
    }
  });

  // Change Password Modal
  document.getElementById('btn-cpw-cancel')?.addEventListener('click', () => {
    state.showChangePasswordModal = false;
    render();
  });
  document.getElementById('form-cpw')?.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const pw = (document.getElementById('cpw-new') as HTMLInputElement).value;
    const confirmPw = (document.getElementById('cpw-confirm') as HTMLInputElement).value;
    if (pw !== confirmPw) {
      showToast('Passwords do not match', 'error');
      return;
    }
    try {
      await ChangeVaultPassword(pw);
      state.showChangePasswordModal = false;
      render();
      showToast('Vault password updated', 'success');
    } catch (e) {
      showToast(errMsg(e), 'error');
    }
  });
}

refreshVault().catch((e) => {
  appEl.innerHTML = `<div style="padding:24px;color:var(--danger);">Failed to initialize LabCert: ${esc(errMsg(e))}</div>`;
});
