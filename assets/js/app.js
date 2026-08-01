/* app.js — Vault (cloud-synced edition)
 *
 * Two separate layers of protection:
 *  1. Supabase Auth (email + master password) — only you can even
 *     see your row in the database, enforced by Row Level Security.
 *  2. Client-side AES-GCM encryption of the vault contents using
 *     the same master password (see crypto.js) — so even the row
 *     in the database is unreadable without that password.
 *
 * Data shape (unchanged encryption target, richer schema):
 * vault = {
 *   emails: [ { id, email, password, phone } ],
 *   accounts: [ { id, category, name, identifier, emailId|null,
 *                 password, recovery, notes } ]
 * }
 * category is one of: app | bank | api | server | other
 */
(() => {
  const sb = window.supabase.createClient(SUPABASE_CONFIG.url, SUPABASE_CONFIG.anonKey);
  const LEGACY_LOCAL_KEY = 'vault_blob_v2';

  let masterPassword = null;
  let vault = null;
  let currentUserId = null;
  let mode = 'signin'; // 'signin' | 'signup'
  let currentCategoryFilter = 'all';
  let currentEmailFilter = 'all'; // 'all' | 'separate' | emailId
  let currentSearch = '';

  const CATEGORY_LABELS = { app: 'App / Website', bank: 'Bank account', api: 'API key / service', server: 'Server / database', other: 'Other' };

  const $ = id => document.getElementById(id);
  const lockScreen = $('lockScreen');
  const app = $('app');
  const lockForm = $('lockForm');
  const authEmail = $('authEmail');
  const masterInput = $('masterInput');
  const masterConfirm = $('masterConfirm');
  const confirmWrap = $('confirmWrap');
  const lockEyebrow = $('lockEyebrow');
  const lockTitle = $('lockTitle');
  const lockCopy = $('lockCopy');
  const lockError = $('lockError');
  const lockInfo = $('lockInfo');
  const lockSubmit = $('lockSubmit');
  const modeToggleBtn = $('modeToggleBtn');

  const emptyVault = () => ({ emails: [], accounts: [] });

  // ---------- lock screen mode ----------
  function applyMode() {
    if (mode === 'signup') {
      lockEyebrow.textContent = 'First time here';
      lockTitle.textContent = 'Create your vault';
      lockCopy.textContent = "This password signs you into your cloud vault and encrypts everything in it. Nothing readable ever leaves your browser — if you forget it, there's no reset, so keep it safe.";
      confirmWrap.classList.remove('hidden');
      masterConfirm.required = true;
      lockSubmit.textContent = 'Create account';
      modeToggleBtn.textContent = 'Already have an account? Sign in';
    } else {
      lockEyebrow.textContent = 'Welcome back';
      lockTitle.textContent = 'Sign in to your vault';
      lockCopy.textContent = "Enter the email and master password you signed up with.";
      confirmWrap.classList.add('hidden');
      masterConfirm.required = false;
      lockSubmit.textContent = 'Sign in';
      modeToggleBtn.textContent = 'New here? Create an account instead';
    }
    lockError.textContent = '';
    lockInfo.classList.add('hidden');
  }
  modeToggleBtn.addEventListener('click', () => { mode = mode === 'signin' ? 'signup' : 'signin'; applyMode(); });

  $('toggleMaster').addEventListener('click', () => {
    const nowText = masterInput.type === 'password';
    masterInput.type = nowText ? 'text' : 'password';
    masterConfirm.type = nowText ? 'text' : 'password';
  });

  lockForm.addEventListener('submit', async e => {
    e.preventDefault();
    lockError.textContent = '';
    lockInfo.classList.add('hidden');
    const email = authEmail.value.trim();
    const pw = masterInput.value;
    lockSubmit.disabled = true;

    try {
      if (mode === 'signup') {
        if (pw.length < 6) { lockError.textContent = 'Use at least 6 characters.'; return; }
        if (pw !== masterConfirm.value) { lockError.textContent = "Passwords don't match."; return; }

        const { data, error } = await sb.auth.signUp({ email, password: pw });
        if (error) { lockError.textContent = error.message; return; }

        if (!data.session) {
          lockInfo.textContent = 'Account created — check your inbox to confirm your email, then sign in here.';
          lockInfo.classList.remove('hidden');
          mode = 'signin'; applyMode();
          return;
        }
        currentUserId = data.user.id;
        masterPassword = pw;
        vault = await tryMigrateLegacyLocal(pw) || emptyVault();
        await persist();
        enterApp();

      } else {
        const { data, error } = await sb.auth.signInWithPassword({ email, password: pw });
        if (error) { lockError.textContent = "Email or password doesn't match."; return; }
        currentUserId = data.user.id;
        masterPassword = pw;

        const { data: row, error: fetchErr } = await sb.from('vaults').select('payload').eq('user_id', currentUserId).maybeSingle();
        if (fetchErr) { lockError.textContent = 'Could not reach the vault — check your connection.'; return; }

        if (row) {
          try {
            vault = await VaultCrypto.decrypt(masterPassword, row.payload);
          } catch {
            lockError.textContent = "That master password doesn't match this vault.";
            return;
          }
        } else {
          vault = await tryMigrateLegacyLocal(pw) || emptyVault();
          await persist();
        }
        enterApp();
      }
    } finally {
      lockSubmit.disabled = false;
    }
  });

  async function tryMigrateLegacyLocal(password) {
    const raw = localStorage.getItem(LEGACY_LOCAL_KEY);
    if (!raw) return null;
    try {
      const payload = JSON.parse(raw);
      const old = await VaultCrypto.decrypt(password, payload);
      const accounts = (old.accounts || []).map(a => ({
        id: a.id, category: 'app', name: a.appName, identifier: a.loginEmail || '',
        emailId: a.emailId || null, password: a.password || '', recovery: '', notes: a.purpose || a.notes || ''
      }));
      return { emails: old.emails || [], accounts };
    } catch {
      return null; // different password or unrelated data — ignore quietly
    }
  }

  // ---------- sign out ----------
  $('lockBtn').addEventListener('click', async () => {
    await sb.auth.signOut();
    masterPassword = null;
    vault = null;
    currentUserId = null;
    app.classList.add('hidden');
    lockScreen.classList.remove('hidden');
    mode = 'signin';
    lockForm.reset();
    applyMode();
  });

  function enterApp() {
    lockScreen.classList.add('hidden');
    app.classList.remove('hidden');
    renderEmails();
    renderFilterOptions();
    renderKeyring();
  }

  // ---------- sync status ----------
  function setSyncStatus(state) {
    const el = $('syncStatus');
    el.classList.remove('syncing', 'error');
    if (state === 'syncing') { el.textContent = 'Syncing…'; el.classList.add('syncing'); }
    else if (state === 'error') { el.textContent = 'Sync failed'; el.classList.add('error'); }
    else { el.textContent = 'Synced'; }
  }

  // ---------- persistence (cloud) ----------
  async function persist() {
    setSyncStatus('syncing');
    try {
      const payload = await VaultCrypto.encrypt(masterPassword, vault);
      const { error } = await sb.from('vaults').upsert({ user_id: currentUserId, payload, updated_at: new Date().toISOString() });
      if (error) throw error;
      setSyncStatus('ok');
    } catch (err) {
      console.error(err);
      setSyncStatus('error');
      showToast("Couldn't sync to the cloud — check your connection");
    }
  }

  // ---------- toast ----------
  let toastTimer;
  function showToast(msg) {
    const t = $('toast');
    t.textContent = msg;
    t.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => t.classList.remove('show'), 2000);
  }

  function escapeHtml(str) {
    const d = document.createElement('div');
    d.textContent = str == null ? '' : str;
    return d.innerHTML;
  }

  // ---------- emails ----------
  function renderEmails() {
    const grid = $('emailsGrid');
    grid.innerHTML = '';
    vault.emails.forEach(em => {
      const card = document.createElement('div');
      card.className = 'email-card';
      card.innerHTML = `
        <h3 class="email-card-address">${escapeHtml(em.email)}</h3>
        <div class="email-card-fields">
          <div class="email-field">
            <span class="email-field-label">Password</span>
            <span class="email-field-value mono masked" data-reveal-target="pw_${em.id}">••••••••••••</span>
            <button class="icon-btn" data-reveal="pw_${em.id}" aria-label="Show password">show</button>
            <button class="icon-btn" data-copy="pw_${em.id}" aria-label="Copy password">copy</button>
          </div>
          <div class="email-field">
            <span class="email-field-label">Phone</span>
            <span class="email-field-value mono">${escapeHtml(em.phone) || '—'}</span>
          </div>
        </div>
        <div class="email-card-foot">
          <button class="btn btn-ghost btn-small" data-edit-email="${em.id}">Edit</button>
        </div>
      `;
      grid.appendChild(card);
    });

    const addTile = document.createElement('button');
    addTile.type = 'button';
    addTile.className = 'add-email-tile';
    addTile.textContent = '+ Add email';
    addTile.addEventListener('click', () => openEmailModal(null));
    grid.appendChild(addTile);

    grid.querySelectorAll('[data-reveal]').forEach(btn => {
      const targetId = btn.dataset.reveal;
      const emId = targetId.replace('pw_', '');
      const em = vault.emails.find(e => e.id === emId);
      const el = grid.querySelector(`[data-reveal-target="${targetId}"]`);
      el.dataset.value = em ? em.password || '' : '';
      btn.addEventListener('click', () => {
        const revealed = el.dataset.revealed === 'true';
        el.textContent = revealed ? '••••••••••••' : (el.dataset.value || '—');
        el.classList.toggle('masked', revealed);
        el.dataset.revealed = revealed ? 'false' : 'true';
        btn.textContent = revealed ? 'show' : 'hide';
      });
    });
    grid.querySelectorAll('[data-copy]').forEach(btn => {
      btn.addEventListener('click', async () => {
        const targetId = btn.dataset.copy;
        const el = grid.querySelector(`[data-reveal-target="${targetId}"]`);
        const val = el.dataset.value || '';
        if (!val) return;
        try { await navigator.clipboard.writeText(val); showToast('Copied to clipboard'); }
        catch { showToast('Could not copy — select manually'); }
      });
    });
    grid.querySelectorAll('[data-edit-email]').forEach(btn => {
      btn.addEventListener('click', () => openEmailModal(btn.dataset.editEmail));
    });
  }

  const emailModalOverlay = $('emailModalOverlay');
  const emailForm = $('emailForm');

  function openEmailModal(id) {
    emailForm.reset();
    $('deleteEmailBtn').classList.toggle('hidden', !id);
    if (id) {
      const em = vault.emails.find(e => e.id === id);
      $('emailModalTitle').textContent = 'Edit email';
      $('emailId').value = em.id;
      $('emailAddress').value = em.email;
      $('emailPasswordInput').value = em.password || '';
      $('emailPhone').value = em.phone || '';
    } else {
      $('emailModalTitle').textContent = 'Add email';
      $('emailId').value = '';
    }
    emailModalOverlay.classList.remove('hidden');
    $('emailAddress').focus();
  }
  $('emailModalClose').addEventListener('click', () => emailModalOverlay.classList.add('hidden'));
  $('emailCancelBtn').addEventListener('click', () => emailModalOverlay.classList.add('hidden'));
  $('toggleEmailPassword').addEventListener('click', () => {
    const f = $('emailPasswordInput');
    f.type = f.type === 'password' ? 'text' : 'password';
  });

  emailForm.addEventListener('submit', async e => {
    e.preventDefault();
    const id = $('emailId').value || 'email_' + Date.now() + '_' + Math.random().toString(36).slice(2, 7);
    const data = { id, email: $('emailAddress').value.trim(), password: $('emailPasswordInput').value, phone: $('emailPhone').value.trim() };
    const idx = vault.emails.findIndex(e => e.id === id);
    if (idx >= 0) vault.emails[idx] = data; else vault.emails.push(data);

    await persist();
    renderEmails();
    renderFilterOptions();
    renderKeyring();
    emailModalOverlay.classList.add('hidden');
    showToast('Email saved');
  });

  $('deleteEmailBtn').addEventListener('click', async () => {
    const id = $('emailId').value;
    if (!id) return;
    const em = vault.emails.find(e => e.id === id);
    const linkedCount = vault.accounts.filter(a => a.emailId === id).length;
    const msg = linkedCount
      ? `${linkedCount} entr${linkedCount > 1 ? 'ies' : 'y'} currently link to this email. Deleting it will keep those entries but drop the link. Continue?`
      : 'Delete this email from the vault?';
    if (!confirm(msg)) return;

    vault.accounts.forEach(a => { if (a.emailId === id) a.emailId = null; });
    vault.emails = vault.emails.filter(e => e.id !== id);

    await persist();
    renderEmails();
    renderFilterOptions();
    renderKeyring();
    emailModalOverlay.classList.add('hidden');
    showToast('Email deleted');
  });

  // ---------- filters ----------
  function renderFilterOptions() {
    const sel = $('filterSelect');
    const prev = currentEmailFilter;
    sel.innerHTML = '';
    sel.add(new Option('All emails', 'all'));
    vault.emails.forEach(em => sel.add(new Option(em.email, em.id)));
    sel.add(new Option('No linked email', 'separate'));
    const stillValid = prev === 'all' || prev === 'separate' || vault.emails.some(e => e.id === prev);
    currentEmailFilter = stillValid ? prev : 'all';
    sel.value = currentEmailFilter;
  }
  $('filterSelect').addEventListener('change', e => { currentEmailFilter = e.target.value; renderKeyring(); });
  $('categoryFilterSelect').addEventListener('change', e => { currentCategoryFilter = e.target.value; renderKeyring(); });
  $('searchInput').addEventListener('input', e => { currentSearch = e.target.value; renderKeyring(); });

  // ---------- keyring ----------
  function emailLabelForAccount(acc) {
    if (!acc.emailId) return null;
    const em = vault.emails.find(e => e.id === acc.emailId);
    return em ? em.email : null;
  }
  function matchesFilters(acc) {
    if (currentCategoryFilter !== 'all' && acc.category !== currentCategoryFilter) return false;
    if (currentEmailFilter === 'separate' && acc.emailId) return false;
    if (currentEmailFilter !== 'all' && currentEmailFilter !== 'separate' && acc.emailId !== currentEmailFilter) return false;
    return true;
  }
  function matchesSearch(acc) {
    if (!currentSearch) return true;
    const q = currentSearch.toLowerCase();
    return acc.name.toLowerCase().includes(q) || (acc.notes || '').toLowerCase().includes(q) || (acc.identifier || '').toLowerCase().includes(q);
  }

  function renderKeyring() {
    const grid = $('keyring');
    const list = vault.accounts.filter(a => matchesFilters(a) && matchesSearch(a));
    grid.innerHTML = '';
    $('emptyState').classList.toggle('hidden', vault.accounts.length !== 0);

    if (vault.accounts.length && list.length === 0) {
      grid.innerHTML = `<p class="empty-state" style="grid-column:1/-1;">Nothing matches that.</p>`;
      return;
    }

    list.forEach(acc => {
      const card = document.createElement('div');
      card.className = 'key-card';
      const linkedEmail = emailLabelForAccount(acc);
      const metaParts = [];
      if (linkedEmail) metaParts.push('via ' + escapeHtml(linkedEmail));
      if (acc.recovery) metaParts.push('recovery: ' + escapeHtml(acc.recovery));
      card.innerHTML = `
        <div class="key-card-top">
          <h3 class="key-app-name">${escapeHtml(acc.name)}</h3>
          <span class="key-tag cat-${acc.category}">${CATEGORY_LABELS[acc.category] || 'Other'}</span>
        </div>
        <div class="key-login">${escapeHtml(acc.identifier) || '—'}</div>
        <p class="key-purpose">${escapeHtml(acc.notes || 'No notes yet')}</p>
        ${metaParts.length ? `<p class="key-meta">${metaParts.join(' &middot; ')}</p>` : ''}
      `;
      card.addEventListener('click', () => openAccountModal(acc.id));
      grid.appendChild(card);
    });
  }

  // ---------- account modal ----------
  const accountModalOverlay = $('accountModalOverlay');
  const accountForm = $('accountForm');
  const accountEmailSelect = $('accountEmailSelect');

  function populateAccountEmailSelect(selectedEmailId) {
    accountEmailSelect.innerHTML = '';
    accountEmailSelect.add(new Option('— none —', ''));
    vault.emails.forEach(em => accountEmailSelect.add(new Option(em.email, em.id)));
    accountEmailSelect.value = selectedEmailId || '';
  }

  $('addAccountBtn').addEventListener('click', () => openAccountModal(null));

  function openAccountModal(id) {
    accountForm.reset();
    $('deleteAccountBtn').classList.toggle('hidden', !id);
    if (id) {
      const acc = vault.accounts.find(a => a.id === id);
      $('modalTitle').textContent = 'Edit entry';
      $('accountId').value = acc.id;
      $('accountCategory').value = acc.category || 'app';
      $('appName').value = acc.name;
      $('identifier').value = acc.identifier || '';
      $('appPassword').value = acc.password || '';
      $('appRecovery').value = acc.recovery || '';
      $('appNotes').value = acc.notes || '';
      populateAccountEmailSelect(acc.emailId);
    } else {
      $('modalTitle').textContent = 'Add entry';
      $('accountId').value = '';
      $('accountCategory').value = 'app';
      populateAccountEmailSelect(null);
    }
    accountModalOverlay.classList.remove('hidden');
    $('appName').focus();
  }
  $('modalClose').addEventListener('click', () => accountModalOverlay.classList.add('hidden'));
  $('cancelAccountBtn').addEventListener('click', () => accountModalOverlay.classList.add('hidden'));
  $('toggleAppPassword').addEventListener('click', () => {
    const f = $('appPassword');
    f.type = f.type === 'password' ? 'text' : 'password';
  });

  accountForm.addEventListener('submit', async e => {
    e.preventDefault();
    const id = $('accountId').value || 'acc_' + Date.now() + '_' + Math.random().toString(36).slice(2, 7);
    const data = {
      id,
      category: $('accountCategory').value,
      name: $('appName').value.trim(),
      identifier: $('identifier').value.trim(),
      emailId: accountEmailSelect.value || null,
      password: $('appPassword').value,
      recovery: $('appRecovery').value.trim(),
      notes: $('appNotes').value.trim()
    };
    const existingIdx = vault.accounts.findIndex(a => a.id === id);
    if (existingIdx >= 0) vault.accounts[existingIdx] = data; else vault.accounts.push(data);

    await persist();
    renderKeyring();
    accountModalOverlay.classList.add('hidden');
    showToast('Saved');
  });

  $('deleteAccountBtn').addEventListener('click', async () => {
    const id = $('accountId').value;
    if (!id) return;
    if (!confirm('Delete this entry from the vault?')) return;
    vault.accounts = vault.accounts.filter(a => a.id !== id);
    await persist();
    renderKeyring();
    accountModalOverlay.classList.add('hidden');
    showToast('Deleted');
  });

  // close modals on overlay click / escape
  [accountModalOverlay, emailModalOverlay].forEach(ov => {
    ov.addEventListener('click', e => { if (e.target === ov) ov.classList.add('hidden'); });
  });
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') {
      accountModalOverlay.classList.add('hidden');
      emailModalOverlay.classList.add('hidden');
    }
  });

  // ---------- init: resume an existing Supabase session if present ----------
  (async () => {
    applyMode();
    const { data: { session } } = await sb.auth.getSession();
    if (session) {
      // We have a valid cloud session, but we still need the master
      // password (never stored) to decrypt — ask for it, prefilled email.
      authEmail.value = session.user.email;
      lockEyebrow.textContent = 'Welcome back';
      lockTitle.textContent = 'Unlock your vault';
      lockCopy.textContent = 'Enter your master password to decrypt this session.';
    }
  })();
})();
