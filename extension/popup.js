const api = globalThis.browser || chrome;
const status = document.getElementById('status');
async function refresh() {
  const result = await api.runtime.sendMessage({type: 'refresh'});
  document.getElementById('links').replaceChildren();
  status.textContent = result.error || (result.pending.length ? 'Click a link to sign in. Links expire after a few minutes.' : 'No fresh sign-in links. We check every 30 seconds while your browser is awake.');
  for (const link of result.pending || []) {
    const card = document.createElement('article');
    const title = document.createElement('strong'); title.textContent = link.label;
    const host = document.createElement('p'); host.textContent = link.host;
    const open = document.createElement('button'); open.textContent = 'Open sign-in link';
    open.addEventListener('click', async () => {
      open.disabled = true;
      const result = await api.runtime.sendMessage({type: 'open', id: link.id});
      if (result.error) { status.textContent = result.error; open.disabled = false; }
      else await refresh();
    });
    card.append(title, host, open); document.getElementById('links').append(card);
  }
}
document.getElementById('refresh').addEventListener('click', refresh);
document.getElementById('settings').addEventListener('click', () => api.runtime.openOptionsPage());
refresh().catch(() => { status.textContent = 'Open Settings to connect your helper.'; });
