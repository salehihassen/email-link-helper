const api = globalThis.browser || chrome;
const $ = id => document.getElementById(id);
let savedSnapshot = '';
let hasSavedSettings = false;
let busy = false;
const snapshot = () => JSON.stringify(['source', 'token', 'hosts'].map(id => $(id).value));

function showState(state, title, detail = '') {
  document.querySelector('.save-bar').dataset.state = state;
  $('save-state').textContent = title; $('status').textContent = detail;
  const dirty = snapshot() !== savedSnapshot;
  $('save').disabled = busy || (!dirty && hasSavedSettings);
  $('save').textContent = busy ? 'Saving…' : dirty ? 'Save changes' : hasSavedSettings ? 'Saved ✓' : 'Save settings';
}
function edited() {
  if (busy) return;
  if (snapshot() !== savedSnapshot) showState('dirty', 'Unsaved changes', 'Click Save changes to apply these settings to this browser.');
  else showState('saved', hasSavedSettings ? 'All changes saved' : 'Connect your helper', hasSavedSettings ? 'These settings are saved on this browser.' : 'Enter your source and device token, then save.');
}
async function load() {
  const config = await api.storage.local.get(['source', 'token', 'allowedHosts']);
  $('source').value = config.source || ''; $('token').value = config.token || '';
  $('hosts').value = (config.allowedHosts || ['claude.ai', 'platform.claude.com', 'console.anthropic.com']).join(', ');
  hasSavedSettings = !!(config.source && config.token); savedSnapshot = snapshot(); edited();
}
function setBusy(value) {
  busy = value; $('settings').setAttribute('aria-busy', String(value));
  for (const id of ['source', 'token', 'hosts', 'disconnect']) $(id).disabled = value;
}
for (const id of ['source', 'token', 'hosts']) $(id).addEventListener('input', edited);
$('settings').addEventListener('submit', async event => {
  event.preventDefault(); if (busy) return;
  let persisted = false;
  try {
    const url = new URL($('source').value.trim());
    if (url.protocol !== 'https:' || url.username || url.password || url.pathname !== '/' || url.search || url.hash) throw new Error('Enter an HTTPS origin without a path.');
    const token = $('token').value.trim();
    if (!/^[A-Za-z0-9_-]{43}$/.test(token)) throw new Error('Paste a device token created by the helper.');
    const allowedHosts = [...new Set($('hosts').value.split(',').map(v => v.trim().toLowerCase()).filter(Boolean))];
    if (!allowedHosts.length || allowedHosts.some(v => !/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(v))) throw new Error('Enter exact destination host names, separated by commas.');
    // Keep this as the first async call: host permission needs the user's click.
    const permission = api.permissions.request({origins: [url.origin + '/*']});
    setBusy(true); showState('saving', 'Saving changes…', 'Grant access to your chosen helper source if asked.');
    if (!await permission) throw new Error('Access to your configured helper source is required. Your changes were not saved.');
    const {source: oldSource} = await api.storage.local.get('source');
    await api.storage.local.set({source: url.origin, token, allowedHosts, pending: []});
    persisted = true; hasSavedSettings = true;
    $('source').value = url.origin; $('token').value = token; $('hosts').value = allowedHosts.join(', '); savedSnapshot = snapshot();
    if (oldSource && oldSource !== url.origin) await api.permissions.remove({origins: [oldSource + '/*']});
    const result = await api.runtime.sendMessage({type: 'refresh'});
    setBusy(false);
    if (result?.error) showState('offline', 'Saved · connection needs attention', 'Your changes are saved. ' + result.error);
    else showState('saved', 'Saved · connected', 'Your updated settings are active. New links will appear in the badge.');
  } catch (error) {
    setBusy(false);
    if (persisted) showState('offline', 'Settings saved', 'Your changes are stored, but connection or permission cleanup failed. Check the source and try the popup to reconnect.');
    else showState('error', 'Changes not saved', error instanceof TypeError ? 'Enter a valid HTTPS helper source.' : error.message);
  }
});
$('disconnect').addEventListener('click', async () => {
  if (busy) return;
  try {
    const {source} = await api.storage.local.get('source');
    await api.storage.local.clear();
    if (source) await api.permissions.remove({origins: [source + '/*']});
    await api.action.setBadgeText({text: ''}); await load();
    showState('empty', 'Disconnected', 'Revoke this device in the helper to invalidate its token.');
  } catch (_) { showState('error', 'Could not finish disconnecting', 'Revoke the device token in the helper to stop access.'); }
});
load().catch(() => showState('error', 'Could not load settings', 'Close this page and try opening extension Settings again.'));
