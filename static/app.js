const $ = id => document.getElementById(id);
async function request(path, method = 'GET', body) {
  const response = await fetch(path, {method, credentials: 'same-origin', cache: 'no-store',
    headers: {'Content-Type': 'application/json', 'X-Link-Helper': '1'},
    body: body === undefined ? undefined : JSON.stringify(body)});
  const data = await response.json();
  if (!response.ok) throw new Error(data.detail || 'Request failed');
  return data;
}
function report(error) { $('notice').textContent = error.message; }
function clearPrivateFields() {
  $('password').value = '';
  $('device-token').value = '';
  $('pairing').hidden = true;
  $('config').value = '';
  $('providers').replaceChildren();
  $('devices').replaceChildren();
  $('origin').textContent = '';
  $('device-name').value = '';
  $('locked').textContent = '';
}
async function load() {
  try {
    const data = await request('/api/settings');
    $('login-panel').hidden = true; $('dashboard').hidden = false; $('logout').hidden = false;
    $('origin').textContent = data.origin;
    $('config').value = JSON.stringify(data.settings, null, 2);
    $('locked').textContent = data.locked.length ? 'Managed by environment: ' + data.locked.join(', ') : 'All settings can be changed here.';
    $('providers').replaceChildren();
    for (const p of data.settings.providers) {
      const row = document.createElement('div'); row.className = 'row';
      const text = document.createElement('div'); text.textContent = p.label;
      const detail = document.createElement('small'); detail.textContent = `${p.type === 'bridge' ? 'Proton Bridge' : p.host} · ${p.mailboxes.join(', ')}`;
      text.append(detail);
      const status = data.status[p.id]; const badge = document.createElement('span');
      badge.className = 'pill' + (status && !status.ok ? ' error' : '');
      badge.textContent = !p.enabled ? 'Paused' : !status ? 'Waiting for first check' : status.ok ? 'Connected' : 'Needs attention';
      if (status && !status.ok) { const error = document.createElement('small'); error.textContent = status.error; text.append(error); }
      row.append(text, badge); $('providers').append(row);
    }
    await devices();
  } catch (error) {
    clearPrivateFields();
    $('login-panel').hidden = false; $('dashboard').hidden = true; $('logout').hidden = true;
    if (error.message !== 'Sign in to continue') report(error);
  }
}
async function devices() {
  const result = await request('/api/devices'); $('devices').replaceChildren();
  for (const device of result) {
    const row = document.createElement('div'); row.className = 'row';
    const text = document.createElement('span'); text.textContent = device.name;
    const revoke = document.createElement('button'); revoke.className = 'quiet'; revoke.textContent = 'Revoke';
    revoke.addEventListener('click', () => request('/api/devices/' + device.id, 'DELETE').then(devices).catch(report));
    row.append(text, revoke); $('devices').append(row);
  }
}
$('login').addEventListener('submit', async event => {
  event.preventDefault(); $('notice').textContent = '';
  try { await request('/api/login', 'POST', {username: $('username').value, password: $('password').value}); $('password').value = ''; await load(); } catch (error) { report(error); }
});
$('logout').addEventListener('click', async () => {
  clearPrivateFields();
  try { await request('/api/logout', 'POST'); await load(); } catch (error) { report(error); }
});
$('reload').addEventListener('click', load);
$('config-form').addEventListener('submit', async event => {
  event.preventDefault();
  try { await request('/api/settings', 'PUT', JSON.parse($('config').value)); await load(); $('notice').textContent = 'Settings saved. Mail connections will refresh on the next check.'; } catch (error) { report(error); }
});
$('device-form').addEventListener('submit', async event => {
  event.preventDefault();
  try { const device = await request('/api/devices', 'POST', {name: $('device-name').value}); $('device-token').value = device.token; $('pairing').hidden = false; await devices(); } catch (error) { report(error); }
});
$('hide-token').addEventListener('click', () => { $('device-token').value = ''; $('pairing').hidden = true; });
load();
