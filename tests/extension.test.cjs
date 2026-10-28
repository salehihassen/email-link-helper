const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

function extension() {
  const saved = {source: 'https://links.private.example', token: 'T'.repeat(43), allowedHosts: ['claude.ai']};
  const opened = [], requests = [], badges = [];
  let listener, links = [{id: 'a'.repeat(24), label: 'Claude', host: 'claude.ai', expires: Date.now()/1000+300}];
  let destination = 'https://claude.ai/magic-link#test-token';
  const api = {
    storage: {local: {
      get: async keys => Object.fromEntries((Array.isArray(keys) ? keys : [keys]).filter(k => k in saved).map(k => [k, saved[k]])),
      set: async values => Object.assign(saved, values), setAccessLevel: async () => {}
    }},
    action: {setBadgeText: async ({text}) => badges.push(text), setBadgeBackgroundColor: async () => {}},
    tabs: {create: async tab => opened.push(tab)},
    alarms: {get: async () => true, onAlarm: {addListener: () => {}}},
    runtime: {id: 'test-extension', getURL: path => 'chrome-extension://test-extension/'+path,
      onInstalled: {addListener: () => {}}, onStartup: {addListener: () => {}},
      onMessage: {addListener: value => { listener = value; }}}
  };
  const context = {chrome: api, URL, AbortSignal, Date, fetch: async (url, options) => {
    requests.push({url, options});
    return {ok: true, json: async () => url.endsWith('/claim') ? {url: destination} : links};
  }};
  vm.runInNewContext(fs.readFileSync('extension/background.js', 'utf8'), context);
  const send = message => new Promise(resolve => {
    listener(message, {id: api.runtime.id, url: api.runtime.getURL('popup.html')}, resolve);
  });
  return {saved, opened, requests, badges, send,
    destination: value => { destination = value; },
    clear: () => { links = []; },
    malicious: () => listener({type: 'open', id: 'a'.repeat(24)}, {id: 'other', url: 'https://evil.test/'}, () => {})};
}

test('refresh shows badge without opening or downloading sign-in URL', async () => {
  const ext = extension();
  const result = await ext.send({type: 'refresh'});
  assert.equal(result.pending.length, 1);
  assert.equal(ext.badges.at(-1), '1');
  assert.equal(ext.opened.length, 0);
  assert.equal(ext.requests[0].url, 'https://links.private.example/api/links');
  assert.equal(ext.requests[0].options.redirect, 'error');
  assert.equal(ext.requests[0].options.credentials, 'omit');
  assert.equal(JSON.stringify(ext.saved).includes('test-token'), false);
});

test('only explicit popup action claims and opens one allowlisted link', async () => {
  const ext = extension();
  assert.equal(ext.malicious(), false);
  assert.equal(ext.requests.length, 0);
  const result = await ext.send({type: 'open', id: 'a'.repeat(24)});
  assert.equal(result.ok, true);
  assert.equal(ext.opened.length, 1);
  assert.equal(ext.opened[0].url, 'https://claude.ai/magic-link#test-token');
  assert.equal(JSON.stringify(ext.saved).includes('test-token'), false);
});

test('even authenticated helper cannot open a destination outside local allowlist', async () => {
  const ext = extension();
  ext.destination('https://evil.test/magic-link#stolen');
  const result = await ext.send({type: 'open', id: 'a'.repeat(24)});
  assert.ok(result.error);
  assert.equal(ext.opened.length, 0);
});

test('expired or removed metadata clears badge', async () => {
  const ext = extension();
  await ext.send({type: 'refresh'});
  ext.clear();
  await ext.send({type: 'refresh'});
  assert.equal(ext.badges.at(-1), '');
});
