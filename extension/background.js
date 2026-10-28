/* No content scripts, page inspection, remote code, synchronized storage or auto-open. */
const api = globalThis.browser || chrome;
let checking;

function sourceOrigin(value) {
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.username || url.password || url.pathname !== '/' || url.search || url.hash) {
    throw new Error('Use an HTTPS source origin, without a path.');
  }
  return url.origin;
}

async function request(path, method = 'GET') {
  const {source, token} = await api.storage.local.get(['source', 'token']);
  if (!source || !token) throw new Error('Configure your helper source and device token in Settings.');
  const origin = sourceOrigin(source);
  const response = await fetch(origin + path, {
    method, headers: {Authorization: `Bearer ${token}`},
    credentials: 'omit', cache: 'no-store', redirect: 'error',
    referrerPolicy: 'no-referrer', signal: AbortSignal.timeout(10000)
  });
  if (!response.ok) {
    if (response.status === 401) throw new Error('Device token is invalid or revoked. Check Settings.');
    if (response.status === 404) throw new Error('This link expired or was already opened.');
    throw new Error('The helper could not complete the request.');
  }
  return response.json();
}

async function refresh() {
  if (checking) return checking;
  checking = (async () => {
    try {
      const result = await request('/api/links');
      if (!Array.isArray(result)) throw new Error('Unexpected helper response.');
      const pending = result.filter(v => v.expires * 1000 > Date.now()).slice(0, 40)
        .map(v => ({id: v.id, label: v.label, host: v.host, expires: v.expires}));
      await api.storage.local.set({pending, lastCheck: Date.now(), error: ''});
      await api.action.setBadgeText({text: pending.length ? String(pending.length) : ''});
      await api.action.setBadgeBackgroundColor({color: '#315c48'});
      return {pending};
    } catch (error) {
      // Do not persist arbitrary server/network exception text or token values.
      const message = error.message.startsWith('Device token') || error.message.startsWith('Configure')
        ? error.message : 'Cannot reach helper. Check Tailscale, source permissions and Settings.';
      await api.storage.local.set({pending: [], error: message});
      await api.action.setBadgeText({text: '!'});
      await api.action.setBadgeBackgroundColor({color: '#9b5934'});
      return {pending: [], error: message};
    }
  })();
  try { return await checking; } finally { checking = undefined; }
}

async function openLink(id) {
  if (typeof id !== 'string' || !/^[A-Za-z0-9_-]{24}$/.test(id)) throw new Error('Invalid link.');
  const {allowedHosts = []} = await api.storage.local.get('allowedHosts');
  const {url: value} = await request(`/api/links/${id}/claim`, 'POST');
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.username || url.password || (url.port && url.port !== '443')
      || !allowedHosts.includes(url.hostname) || /[\s\\]/.test(value)) {
    throw new Error('Link destination is outside your extension allowlist.');
  }
  await api.tabs.create({url: url.href});
  await refresh();
  return {ok: true};
}

async function ensureAlarm() {
  if (!await api.alarms.get('check-links')) {
    await api.alarms.create('check-links', {periodInMinutes: 0.5});
  }
  if (api.storage.local.setAccessLevel) {
    await api.storage.local.setAccessLevel({accessLevel: 'TRUSTED_CONTEXTS'});
  }
}
api.runtime.onInstalled.addListener(() => { ensureAlarm(); refresh(); });
api.runtime.onStartup.addListener(() => { ensureAlarm(); refresh(); });
api.alarms.onAlarm.addListener(alarm => { if (alarm.name === 'check-links') refresh(); });
api.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const popup = api.runtime.getURL('popup.html');
  const options = api.runtime.getURL('options.html');
  if (sender.id !== api.runtime.id || ![popup, options].includes(sender.url)) return false;
  let operation;
  if (message.type === 'refresh') operation = refresh();
  if (message.type === 'open' && sender.url === popup) operation = openLink(message.id);
  if (!operation) return false;
  operation.then(sendResponse, () => sendResponse({error: 'Could not open link. It may be expired, used, or outside your destination allowlist.'}));
  return true;
});
ensureAlarm();
