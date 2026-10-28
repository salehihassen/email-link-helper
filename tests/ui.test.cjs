const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const {JSDOM} = require('jsdom');
const copy = value => JSON.parse(JSON.stringify(value));
async function waitFor(predicate) {
  for (let i = 0; i < 100; i++) {
    if (predicate()) return;
    await new Promise(resolve => setTimeout(resolve, 5));
  }
  assert.fail('UI did not reach the expected state');
}
function page(html) {
  const dom = new JSDOM(fs.readFileSync(html, 'utf8'), {url: 'https://links.private.example', runScripts: 'outside-only'});
  dom.window.HTMLDialogElement.prototype.showModal = function() { this.setAttribute('open', ''); };
  dom.window.HTMLDialogElement.prototype.close = function() { this.removeAttribute('open'); this.dispatchEvent(new dom.window.Event('close')); };
  const $ = id => dom.window.document.getElementById(id);
  const input = (id, value) => { if ($(id).type === 'checkbox') $(id).checked = value; else $(id).value = value; $(id).dispatchEvent(new dom.window.Event('input', {bubbles: true})); };
  const submit = id => $(id).dispatchEvent(new dom.window.Event('submit', {bubbles: true, cancelable: true}));
  return {dom, $, input, submit};
}
async function dashboard(options = {}) {
  const ui = page('static/index.html');
  const data = {origin: 'https://links.private.example', revision: 'first', locked: [], password_sources: {proton: 'file'}, status: {proton: {ok: true}}, settings: {
    providers: [{id: 'proton', label: 'Personal', type: 'bridge', host: '', port: 993, username: 'test@example.test', password: '', mailboxes: ['INBOX'], authserv_ids: ['mail.protonmail.ch'], enabled: true}],
    rules: [{id: 'claude', label: 'Claude', provider: 'proton', senders: ['no-reply@example.test'], subject_contains: 'sign in', dkim_domains: ['example.test'], url_hosts: ['accounts.example.test'], url_paths: ['/login'], enabled: true}],
    poll_seconds: 5, max_age_seconds: 600
  }, ...options};
  const writes = []; let failure;
  ui.dom.window.fetch = async (path, request = {}) => {
    if (request.method === 'PUT') {
      writes.push(copy(request));
      if (failure) return {ok: false, status: failure.status, json: async () => failure};
      data.settings = JSON.parse(request.body); data.revision += 'next';
      return {ok: true, status: 200, json: async () => ({ok: true})};
    }
    if (failure?.status === 401) return {ok: false, status: 401, json: async () => ({detail: 'Sign in to continue'})};
    const response = path === '/api/devices' ? [] : copy(data);
    if (path === '/api/settings') for (const p of response.settings.providers) p.password = '';
    return {ok: true, status: 200, json: async () => response};
  };
  ui.dom.window.eval(fs.readFileSync('static/app.js', 'utf8'));
  await waitFor(() => !ui.$('dashboard').hidden);
  return {...ui, data, writes, fail: value => { failure = value; }};
}
function ruleFields(ui, label = 'Example login') {
  for (const [field, value] of Object.entries({id: 'example', label, senders: 'no-reply@example.test', dkim: 'example.test', hosts: 'accounts.example.test', paths: '/login'})) ui.input('rule-'+field, value);
}

test('providers can be created, edited without returning passwords, and deleted', async t => {
  const ui = await dashboard(); t.after(() => ui.dom.window.close());
  ui.$('add-provider').click();
  for (const [name, value] of Object.entries({id: 'work', label: 'Work', host: 'imap.example.test', username: 'user@example.test', password: 'test-only-password', authserv: 'mx.example.test'})) ui.input('provider-'+name, value);
  ui.input('provider-enabled', false); ui.submit('provider-form');
  await waitFor(() => !ui.$('provider-dialog').open);
  assert.equal(ui.data.settings.providers.length, 2);
  assert.equal(JSON.parse(ui.writes[0].body).providers[1].password, 'test-only-password');
  assert.equal(ui.writes[0].headers['If-Match'], 'first');
  ui.dom.window.document.querySelector('[data-provider="work"] button').click();
  assert.equal(ui.$('provider-password').value, '');
  ui.input('provider-label', 'Work updated'); ui.submit('provider-form');
  await waitFor(() => !ui.$('provider-dialog').open);
  assert.equal(ui.data.settings.providers[1].label, 'Work updated');
  ui.dom.window.document.querySelectorAll('[data-provider="work"] button')[1].click();
  assert.equal(ui.$('delete-dialog').open, true); ui.submit('delete-form');
  await waitFor(() => !ui.$('delete-dialog').open);
  assert.equal(ui.data.settings.providers.length, 1);
});

test('rule forms create, edit, validate and delete rules without touching other rules', async t => {
  const ui = await dashboard(); t.after(() => ui.dom.window.close());
  ui.$('add-rule').click(); ruleFields(ui); ui.submit('rule-form');
  await waitFor(() => !ui.$('rule-dialog').open);
  assert.equal(ui.data.settings.rules.length, 2);
  ui.dom.window.document.querySelector('[data-rule="example"] button').click();
  ui.input('rule-label', 'Renamed'); ui.input('rule-hosts', '*.example.test'); ui.submit('rule-form');
  assert.equal(ui.$('rule-hosts').getAttribute('aria-invalid'), 'true');
  assert.equal(ui.writes.length, 1);
  ui.input('rule-hosts', 'accounts.example.test'); ui.submit('rule-form');
  await waitFor(() => !ui.$('rule-dialog').open);
  assert.equal(ui.data.settings.rules[1].label, 'Renamed');
  ui.dom.window.document.querySelectorAll('[data-rule="example"] button')[1].click(); ui.submit('delete-form');
  await waitFor(() => !ui.$('delete-dialog').open);
  assert.deepEqual(ui.data.settings.rules.map(v => v.id), ['claude']);
});

test('managed fields stay locked and providers with rules cannot be deleted', async t => {
  const ui = await dashboard({locked: ['providers.proton.id', 'providers.proton.type', 'providers.proton.username', 'rules']});
  t.after(() => ui.dom.window.close());
  ui.dom.window.document.querySelector('[data-provider="proton"] button').click();
  assert.equal(ui.$('provider-username').disabled, true);
  assert.equal(ui.$('provider-type').disabled, true);
  assert.equal(ui.$('provider-label').disabled, false);
  assert.equal(ui.$('provider-password').disabled, true);
  assert.equal(ui.dom.window.document.querySelectorAll('[data-provider="proton"] button')[1].disabled, true);
  ui.dom.window.closeDialog('provider-dialog');
  assert.equal(ui.$('add-rule').disabled, true);
  ui.dom.window.document.querySelector('[data-rule="claude"] button').click();
  assert.equal(ui.$('rule-senders').disabled, true);
  assert.equal(ui.$('save-rule').disabled, true);
});

test('field validation errors and concurrent changes retain the user draft', async t => {
  const ui = await dashboard(); t.after(() => ui.dom.window.close());
  ui.$('add-rule').click(); ruleFields(ui);
  ui.fail({status: 422, detail: 'Check the fields', errors: [{path: ['rules', 1, 'dkim_domains'], message: 'Use an exact signing domain'}]});
  ui.submit('rule-form'); await waitFor(() => ui.$('rule-dkim').getAttribute('aria-invalid') === 'true');
  assert.match(ui.$('rule-error').textContent, /exact signing domain/);
  assert.equal(ui.$('rule-label').value, 'Example login');
  ui.fail({status: 409, detail: 'Settings changed in another tab. Refresh before editing again.'});
  ui.submit('rule-form'); await waitFor(() => ui.$('rule-error').textContent.includes('another tab'));
  assert.equal(ui.$('rule-dialog').open, true);
  assert.equal(ui.$('rule-label').value, 'Example login');
  assert.equal(ui.data.settings.rules.length, 1);
});

test('session failure closes dialogs and erases unsaved credentials', async t => {
  const ui = await dashboard(); t.after(() => ui.dom.window.close());
  ui.$('add-provider').click(); ui.input('provider-password', 'test-only-unsaved-password');
  ui.fail({status: 401}); await ui.dom.window.load();
  assert.equal(ui.$('provider-password').value, '');
  assert.equal(ui.$('provider-dialog').open, false);
  assert.equal(ui.$('dashboard').hidden, true);
});

async function extensionSettings(options = {}) {
  const ui = page('extension/options.html');
  const saved = {source: 'https://links.private.example', token: 'T'.repeat(43), allowedHosts: ['claude.ai']};
  let writes = 0;
  ui.dom.window.browser = {
    storage: {local: {get: async keys => typeof keys === 'string' ? {[keys]: saved[keys]} : copy(saved), set: async value => {Object.assign(saved, value); writes++;}, clear: async () => {for (const k of Object.keys(saved)) delete saved[k];}}},
    permissions: {request: async () => options.granted !== false, remove: async () => true},
    runtime: {sendMessage: async () => options.refresh || {pending: []}}, action: {setBadgeText: async () => {}}
  };
  ui.dom.window.eval(fs.readFileSync('extension/options.js', 'utf8'));
  await waitFor(() => ui.$('save-state').textContent === 'All changes saved');
  return {...ui, saved, writes: () => writes};
}

test('extension detects edits and confirms settings were saved and connected', async t => {
  const ui = await extensionSettings(); t.after(() => ui.dom.window.close());
  assert.equal(ui.$('save').disabled, true);
  ui.input('hosts', 'claude.ai, app.notion.com');
  assert.equal(ui.$('save-state').textContent, 'Unsaved changes');
  assert.equal(ui.$('save').disabled, false); ui.submit('settings');
  await waitFor(() => ui.$('save-state').textContent === 'Saved · connected');
  assert.deepEqual(Array.from(ui.saved.allowedHosts), ['claude.ai', 'app.notion.com']);
  assert.equal(ui.$('save').textContent, 'Saved ✓'); assert.equal(ui.$('save').disabled, true);
  ui.input('hosts', 'claude.ai'); assert.equal(ui.$('save-state').textContent, 'Unsaved changes');
});

test('extension distinguishes a saved offline configuration from an unsaved permission failure', async t => {
  const offline = await extensionSettings({refresh: {error: 'Cannot reach helper.'}}); t.after(() => offline.dom.window.close());
  offline.input('hosts', 'app.notion.com'); offline.submit('settings');
  await waitFor(() => offline.$('save-state').textContent === 'Saved · connection needs attention');
  assert.equal(offline.writes(), 1); assert.match(offline.$('status').textContent, /changes are saved/);
  const denied = await extensionSettings({granted: false}); t.after(() => denied.dom.window.close());
  denied.input('source', 'https://another.private.example'); denied.submit('settings');
  await waitFor(() => denied.$('save-state').textContent === 'Changes not saved');
  assert.equal(denied.writes(), 0); assert.equal(denied.saved.source, 'https://links.private.example');
  assert.equal(denied.$('save').disabled, false);
});

test('extension shows saving progress and recognizes when edits are undone', async t => {
  let finish;
  const refresh = new Promise(resolve => { finish = resolve; });
  const ui = await extensionSettings({refresh}); t.after(() => ui.dom.window.close());
  ui.input('hosts', 'app.notion.com');
  ui.input('hosts', 'claude.ai');
  assert.equal(ui.$('save').disabled, true);
  ui.input('hosts', 'claude.ai, app.notion.com'); ui.submit('settings');
  await waitFor(() => ui.writes() === 1);
  assert.equal(ui.$('save').textContent, 'Saving…'); assert.equal(ui.$('save').disabled, true);
  finish({pending: []});
  await waitFor(() => ui.$('save-state').textContent === 'Saved · connected');
});
