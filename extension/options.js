const api = globalThis.browser || chrome;
const $ = id => document.getElementById(id);
async function load() {
  const config = await api.storage.local.get(['source', 'token', 'allowedHosts']);
  $('source').value = config.source || '';
  $('token').value = config.token || '';
  if (config.allowedHosts) $('hosts').value = config.allowedHosts.join(', ');
}
$('settings').addEventListener('submit', async event => {
  event.preventDefault();
  try {
    const url = new URL($('source').value);
    if (url.protocol !== 'https:' || url.username || url.password || url.pathname !== '/' || url.search || url.hash) throw new Error('Enter an HTTPS origin without a path.');
    const token = $('token').value.trim();
    if (!/^[A-Za-z0-9_-]{43}$/.test(token)) throw new Error('Paste a device token created by the helper.');
    const allowedHosts = $('hosts').value.split(',').map(v => v.trim().toLowerCase());
    if (!allowedHosts.length || allowedHosts.some(v => !/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(v))) throw new Error('Enter exact destination host names, separated by commas.');
    const granted = await api.permissions.request({origins: [url.origin + '/*']});
    if (!granted) throw new Error('Access to your configured helper source is required.');
    const {source: oldSource} = await api.storage.local.get('source');
    await api.storage.local.set({source: url.origin, token, allowedHosts, pending: []});
    if (oldSource && oldSource !== url.origin) await api.permissions.remove({origins: [oldSource + '/*']});
    const result = await api.runtime.sendMessage({type: 'refresh'});
    $('status').textContent = result.error || 'Connected. New links will appear in the extension badge.';
  } catch (error) { $('status').textContent = error.message; }
});
$('disconnect').addEventListener('click', async () => {
  const {source} = await api.storage.local.get('source');
  await api.storage.local.clear();
  if (source) await api.permissions.remove({origins: [source + '/*']});
  await api.action.setBadgeText({text: ''});
  await load();
  $('status').textContent = 'Disconnected. Revoke this device in the helper to invalidate its token.';
});
load();
