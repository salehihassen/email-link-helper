const $ = id => document.getElementById(id);
let current = null;
let editing = null;
let deleting = null;
let saving = false;
const lists = value => [...new Set(value.split(/[,\n]/).map(v => v.trim()).filter(Boolean))];
const clone = value => JSON.parse(JSON.stringify(value));

async function request(path, method = 'GET', body, extraHeaders = {}) {
  const response = await fetch(path, {method, credentials: 'same-origin', cache: 'no-store',
    headers: {'Content-Type': 'application/json', 'X-Link-Helper': '1', ...extraHeaders},
    body: body === undefined ? undefined : JSON.stringify(body)});
  const data = await response.json();
  if (!response.ok) {
    const error = new Error(data.detail || 'Request failed');
    error.fields = data.errors || []; error.status = response.status; throw error;
  }
  return data;
}
function announce(message, error = false) {
  $('notice').textContent = message; $('notice').classList.toggle('error', error);
}
function report(error) { announce(error.message, true); }
function closeDialog(id) {
  const dialog = $(id);
  if (dialog.open) dialog.close();
  dialog.querySelector('form').reset();
  for (const control of dialog.querySelectorAll('input, textarea, select')) control.setCustomValidity('');
  if (id === 'provider-dialog') $('provider-password').value = '';
}
function clearPrivateFields() {
  $('password').value = ''; $('device-token').value = ''; $('pairing').hidden = true;
  for (const id of ['provider-dialog', 'rule-dialog', 'delete-dialog']) closeDialog(id);
  $('providers').replaceChildren(); $('rules').replaceChildren(); $('devices').replaceChildren();
  $('origin').textContent = ''; $('device-name').value = ''; current = null;
}
async function load() {
  try {
    current = await request('/api/settings');
    $('login-panel').hidden = true; $('dashboard').hidden = false; $('logout').hidden = false;
    render(); await devices();
  } catch (error) {
    clearPrivateFields(); $('login-panel').hidden = false; $('dashboard').hidden = true; $('logout').hidden = true;
    if (error.status !== 401) report(error);
  }
}
function element(tag, text, className) {
  const node = document.createElement(tag); if (text !== undefined) node.textContent = text;
  if (className) node.className = className; return node;
}
function action(text, handler, disabled = false, title = '') {
  const button = element('button', text, 'quiet'); button.type = 'button';
  button.disabled = disabled; button.title = title; button.addEventListener('click', handler); return button;
}
function render() {
  $('origin').textContent = current.origin;
  const {providers, rules} = current.settings;
  $('providers').replaceChildren(); $('rules').replaceChildren();
  for (const provider of providers) {
    const row = element('article', undefined, 'item'); row.dataset.provider = provider.id;
    const text = element('div', undefined, 'item-copy'); text.append(element('h3', provider.label));
    text.append(element('p', `${provider.type === 'bridge' ? 'Proton Bridge' : provider.host} · ${provider.mailboxes.join(', ')}`, 'muted'));
    const state = current.status[provider.id];
    text.append(element('span', !provider.enabled ? 'Paused' : !state ? 'Waiting for first check' : state.ok ? 'Connected' : 'Needs attention', 'pill' + (state && !state.ok ? ' error' : '')));
    if (state && !state.ok) text.append(element('p', state.error, 'muted'));
    const managed = current.locked.some(v => v.startsWith(`providers.${provider.id}.`));
    const references = rules.filter(r => r.provider === provider.id).length;
    if (managed) text.append(element('p', 'Some fields are managed by the server environment.', 'managed'));
    const reason = managed ? 'Environment-managed providers cannot be deleted.' : references ? 'Delete this provider’s rules before deleting the provider.' : '';
    if (references && !managed) text.append(element('p', `${references} rule${references === 1 ? '' : 's'} use this provider. Remove its rules before deleting it.`, 'muted'));
    const buttons = element('div', undefined, 'actions');
    buttons.append(action('Edit provider', () => editProvider(provider)), action('Delete', () => confirmDelete('providers', provider), !!reason, reason));
    row.append(text, buttons); $('providers').append(row);
  }
  if (!providers.length) $('providers').append(element('p', 'No inboxes connected yet. Add a provider to get started.', 'empty'));
  const rulesLocked = current.locked.includes('rules'); $('rules-lock').hidden = !rulesLocked;
  $('add-rule').disabled = rulesLocked || !providers.length;
  $('add-rule').title = rulesLocked ? 'Rules are managed by LINK_RULES_JSON.' : !providers.length ? 'Add a provider first.' : '';
  for (const rule of rules) {
    const row = element('article', undefined, 'item'); row.dataset.rule = rule.id;
    const text = element('div', undefined, 'item-copy'); text.append(element('h3', rule.label));
    text.append(element('p', `${providers.find(p => p.id === rule.provider)?.label || rule.provider} · ${rule.senders.join(', ')}`, 'muted'));
    text.append(element('p', rule.url_hosts.join(', ') + ' → ' + rule.url_paths.join(', '), 'destinations'));
    text.append(element('span', rule.enabled ? 'Enabled' : 'Paused', 'pill'));
    const buttons = element('div', undefined, 'actions');
    buttons.append(action(rulesLocked ? 'View rule' : 'Edit rule', () => editRule(rule)), action('Delete', () => confirmDelete('rules', rule), rulesLocked, 'Rules managed by the environment cannot be deleted.'));
    row.append(text, buttons); $('rules').append(row);
  }
  if (!rules.length) $('rules').append(element('p', 'No rules yet. Add one to choose which sign-in links reach your browser.', 'empty'));
  for (const [field, id] of [['poll_seconds', 'poll-seconds'], ['max_age_seconds', 'max-age-seconds']]) {
    $(id).value = current.settings[field]; $(id).disabled = current.locked.includes(field);
    $(id).title = $(id).disabled ? 'Managed by environment' : '';
  }
  $('delivery-managed').hidden = !current.locked.some(v => ['poll_seconds', 'max_age_seconds'].includes(v));
  $('save-delivery').disabled = $('poll-seconds').disabled && $('max-age-seconds').disabled;
}
function setValue(form, name, value) {
  const field = form.elements.namedItem(name);
  if (field.type === 'checkbox') field.checked = value;
  else field.value = Array.isArray(value) ? value.join('\n') : value;
}
function prepare(form, values) {
  form.reset();
  for (const field of form.querySelectorAll('input, textarea, select')) {
    field.disabled = false; field.readOnly = false; field.title = ''; field.setCustomValidity(''); field.removeAttribute('aria-invalid');
  }
  for (const note of form.querySelectorAll('.field-managed, .field-error')) note.remove();
  form.querySelector('.form-error').textContent = '';
  for (const [key, value] of Object.entries(values)) if (form.elements.namedItem(key)) setValue(form, key, value);
}
function markManaged(field) {
  field.disabled = true; field.title = 'Managed by environment';
  field.after(element('small', 'Managed by environment', 'field-managed'));
}
function providerType() {
  const bridge = $('provider-type').value === 'bridge';
  $('imap-fields').hidden = bridge; $('bridge-note').hidden = !bridge; $('provider-host').required = !bridge;
  if (bridge && !$('provider-authserv').value && !$('provider-authserv').disabled) $('provider-authserv').value = 'mail.protonmail.ch';
}
function editProvider(provider = null) {
  editing = {kind: 'providers', id: provider?.id || null};
  prepare($('provider-form'), provider || {id: '', label: '', type: 'imap', host: '', port: 993, username: '', password: '', mailboxes: ['INBOX'], authserv_ids: [], enabled: true});
  $('provider-title').textContent = provider ? 'Edit provider' : 'Add provider'; $('provider-id').readOnly = !!provider;
  for (const field of $('provider-form').querySelectorAll('[name]')) {
    if (provider && current.locked.includes(`providers.${provider.id}.${field.name}`)) markManaged(field);
  }
  const source = provider && current.password_sources?.[provider.id];
  const external = ['file', 'env'].includes(source);
  $('provider-password').value = ''; $('provider-password').disabled = external;
  $('provider-password').placeholder = source ? 'Leave blank to keep the current password' : 'Enter a mailbox or app password';
  $('provider-password-note').textContent = external ? `Password supplied by a server ${source === 'file' ? 'secret file' : 'environment variable'}. Change it there.` : source ? 'A password is stored. Enter a new one only to replace it.' : 'Use an app-specific password where supported.';
  $('provider-security').open = !provider; providerType(); $('provider-dialog').showModal();
}
function editRule(rule = null) {
  editing = {kind: 'rules', id: rule?.id || null};
  $('rule-provider').replaceChildren(...current.settings.providers.map(p => {const o = element('option', p.label); o.value = p.id; return o;}));
  prepare($('rule-form'), rule || {id: '', label: '', provider: current.settings.providers[0]?.id || '', senders: [], subject_contains: '', dkim_domains: [], url_hosts: [], url_paths: [], enabled: true});
  $('rule-title').textContent = rule ? 'Edit rule' : 'Add rule'; $('rule-id').readOnly = !!rule;
  const locked = current.locked.includes('rules');
  for (const field of $('rule-form').querySelectorAll('[name]')) if (locked) markManaged(field);
  $('save-rule').disabled = locked; $('rule-dialog').showModal();
}
function formData(form, arrayFields = []) {
  const values = {};
  for (const field of form.querySelectorAll('[name]')) {
    values[field.name] = field.type === 'checkbox' ? field.checked : field.type === 'number' ? Number(field.value) : field.value;
    if (arrayFields.includes(field.name)) values[field.name] = lists(field.value);
    else if (field.name !== 'password' && typeof values[field.name] === 'string') values[field.name] = values[field.name].trim();
  }
  return values;
}
function validate(form) {
  const patterns = {
    senders: [/^[a-zA-Z0-9._+*\-]+@[a-zA-Z0-9.-]+$/, 'Use sender addresses with exact domains. * is allowed only before @.'],
    dkim_domains: [/^[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?$/, 'Use exact signing domains without a scheme, path or wildcard.'],
    url_hosts: [/^[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?$/, 'Use exact host names without https://, paths or wildcards.'],
    url_paths: [/^\/[a-zA-Z0-9/_-]*$/, 'Use exact paths beginning with /, without wildcards or query strings.']
  };
  for (const [name, [pattern, message]] of Object.entries(patterns)) {
    const field = form.elements.namedItem(name);
    if (field && !field.disabled) field.setCustomValidity(lists(field.value).some(v => !pattern.test(v)) ? message : '');
  }
  for (const field of form.querySelectorAll('input, textarea, select')) {
    field.removeAttribute('aria-invalid');
    if (!field.disabled && !field.checkValidity()) {
      field.setAttribute('aria-invalid', 'true');
      const details = field.closest('details'); if (details) details.open = true;
      form.querySelector('.form-error').textContent = field.validationMessage;
      field.focus(); field.reportValidity(); return false;
    }
  }
  return true;
}
function showErrors(form, error, kind, index) {
  form.querySelector('.form-error').textContent = [error.message, ...(error.fields || []).map(e => e.message)].join('\n');
  for (const entry of error.fields || []) {
    let name = entry.path[0];
    if (kind && entry.path[0] === kind && entry.path[1] === index) name = entry.path[2];
    const field = name && form.elements.namedItem(name);
    if (!field || field.disabled) continue;
    field.setAttribute('aria-invalid', 'true'); field.after(element('small', entry.message, 'field-error'));
    const details = field.closest('details'); if (details) details.open = true;
  }
  if (error.status === 401) { clearPrivateFields(); load(); }
}
async function persist(candidate) {
  await request('/api/settings', 'PUT', candidate, {'If-Match': current.revision});
  current = await request('/api/settings'); render();
}
async function saveItem(event, kind, arrayFields, dialog) {
  event.preventDefault(); if (saving) return;
  const form = event.currentTarget; form.querySelector('.form-error').textContent = '';
  for (const note of form.querySelectorAll('.field-error')) note.remove();
  if (!validate(form)) return;
  const value = formData(form, arrayFields); const candidate = clone(current.settings);
  let index = candidate[kind].findIndex(v => v.id === editing.id);
  if (index < 0 && candidate[kind].some(v => v.id === value.id)) {
    form.querySelector('.form-error').textContent = 'That ID is already in use. Choose a different ID.'; return;
  }
  if (kind === 'providers' && value.type === 'imap' && value.host.toLowerCase().endsWith('gmail.com')) {
    form.querySelector('.form-error').textContent = 'Gmail is not supported.'; $('provider-host').focus(); return;
  }
  if (index < 0) { index = candidate[kind].length; candidate[kind].push(value); } else candidate[kind][index] = value;
  const button = form.querySelector('button[id^="save-"]'); const label = button.textContent;
  saving = true; button.disabled = true; button.textContent = 'Saving…';
  try { await persist(candidate); closeDialog(dialog); announce(`${kind === 'providers' ? 'Provider' : 'Rule'} saved. Mail checks will use the updated settings shortly.`); }
  catch (error) { showErrors(form, error, kind, index); }
  finally { saving = false; button.disabled = false; button.textContent = label; }
}
function confirmDelete(kind, item) {
  deleting = {kind, id: item.id}; $('delete-title').textContent = `Delete ${kind === 'providers' ? 'provider' : 'rule'}?`;
  $('delete-description').textContent = `“${item.label}” will be removed from this helper. Your emails will not be changed.`;
  $('delete-error').textContent = ''; $('delete-dialog').showModal();
}
async function devices() {
  const result = await request('/api/devices'); $('devices').replaceChildren();
  for (const device of result) {
    const row = element('div', undefined, 'row');
    row.append(element('span', device.name), action('Revoke', () => request('/api/devices/' + device.id, 'DELETE').then(devices).catch(report)));
    $('devices').append(row);
  }
}
for (const button of document.querySelectorAll('[data-close]')) button.addEventListener('click', () => { if (!saving) closeDialog(button.dataset.close); });
for (const dialog of document.querySelectorAll('dialog')) {
  dialog.addEventListener('cancel', event => { event.preventDefault(); if (!saving) closeDialog(dialog.id); });
  dialog.addEventListener('close', () => { if (dialog.id === 'provider-dialog') $('provider-password').value = ''; });
}
for (const form of document.querySelectorAll('dialog form, #delivery-form')) form.addEventListener('input', event => {event.target.setCustomValidity?.(''); event.target.removeAttribute('aria-invalid');});
$('provider-type').addEventListener('change', providerType);
$('add-provider').addEventListener('click', () => editProvider());
$('add-rule').addEventListener('click', () => editRule());
$('provider-form').addEventListener('submit', event => saveItem(event, 'providers', ['mailboxes', 'authserv_ids'], 'provider-dialog'));
$('rule-form').addEventListener('submit', event => saveItem(event, 'rules', ['senders', 'dkim_domains', 'url_hosts', 'url_paths'], 'rule-dialog'));
$('delete-form').addEventListener('submit', async event => {
  event.preventDefault(); if (saving) return;
  const candidate = clone(current.settings); candidate[deleting.kind] = candidate[deleting.kind].filter(v => v.id !== deleting.id);
  saving = true; $('confirm-delete').disabled = true;
  try { await persist(candidate); closeDialog('delete-dialog'); announce('Deleted. Your emails are unchanged.'); }
  catch (error) { showErrors($('delete-form'), error); }
  finally { saving = false; $('confirm-delete').disabled = false; }
});
$('delivery-form').addEventListener('submit', async event => {
  event.preventDefault(); if (saving || !validate(event.currentTarget)) return;
  const candidate = {...clone(current.settings), ...formData(event.currentTarget)};
  saving = true; $('save-delivery').disabled = true;
  try { await persist(candidate); $('delivery-error').textContent = ''; announce('Timing saved.'); }
  catch (error) { showErrors(event.currentTarget, error); }
  finally { saving = false; $('save-delivery').disabled = false; }
});
$('login').addEventListener('submit', async event => {
  event.preventDefault(); announce('');
  try { await request('/api/login', 'POST', {username: $('username').value, password: $('password').value}); $('password').value = ''; await load(); } catch (error) { report(error); }
});
$('logout').addEventListener('click', async () => { clearPrivateFields(); try { await request('/api/logout', 'POST'); await load(); } catch (error) { report(error); } });
$('reload').addEventListener('click', async () => { await load(); if (current) announce('Status and settings refreshed.'); });
$('device-form').addEventListener('submit', async event => {
  event.preventDefault();
  try { const device = await request('/api/devices', 'POST', {name: $('device-name').value}); $('device-token').value = device.token; $('pairing').hidden = false; await devices(); } catch (error) { report(error); }
});
$('hide-token').addEventListener('click', () => { $('device-token').value = ''; $('pairing').hidden = true; });
load();
