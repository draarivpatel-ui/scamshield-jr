import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export const CHROME = process.env.CHROME_BIN || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
export const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export async function launchChrome(width = 1440, height = 900) {
  const profile = mkdtempSync(join(tmpdir(), 'scamshield-chrome-'));
  const chrome = spawn(CHROME, [
    '--headless=new', `--user-data-dir=${profile}`, '--remote-debugging-port=0',
    '--no-first-run', '--no-default-browser-check', '--mute-audio', '--hide-scrollbars',
    `--window-size=${width},${height}`, '--force-color-profile=srgb', 'about:blank',
  ], { stdio: 'ignore' });
  let port = null;
  for (let i = 0; i < 100 && !port; i++) {
    await sleep(100);
    const file = join(profile, 'DevToolsActivePort');
    if (existsSync(file)) port = readFileSync(file, 'utf8').split('\n')[0].trim();
  }
  if (!port) {
    chrome.kill('SIGKILL');
    rmSync(profile, { recursive: true, force: true });
    throw new Error('Chrome did not start');
  }
  const version = await (await fetch(`http://127.0.0.1:${port}/json/version`)).json();
  const cleanup = async () => {
    if (chrome.exitCode === null) {
      const gone = new Promise((resolve) => chrome.once('exit', resolve));
      chrome.kill('SIGTERM');
      await Promise.race([gone, sleep(2500)]);
      if (chrome.exitCode === null) chrome.kill('SIGKILL');
    }
    for (let attempt = 0; attempt < 5; attempt += 1) {
      try {
        rmSync(profile, { recursive: true, force: true });
        break;
      } catch (error) {
        if (attempt === 4) throw error;
        await sleep(350);
      }
    }
  };
  return { chrome, profile, cleanup, webSocketDebuggerUrl: version.webSocketDebuggerUrl };
}

export async function connectCdp(webSocketDebuggerUrl) {
  const ws = new WebSocket(webSocketDebuggerUrl);
  let nextId = 0;
  const pending = new Map();
  const listeners = [];
  ws.onmessage = (event) => {
    const message = JSON.parse(event.data);
    if (message.id && pending.has(message.id)) {
      const item = pending.get(message.id);
      pending.delete(message.id);
      message.error ? item.reject(new Error(message.error.message)) : item.resolve(message.result);
    } else if (message.method) {
      listeners.forEach((listener) => listener(message));
    }
  };
  await new Promise((resolve, reject) => {
    ws.onopen = resolve;
    ws.onerror = reject;
  });
  const send = (method, params = {}, sessionId) => new Promise((resolve, reject) => {
    const id = ++nextId;
    pending.set(id, { resolve, reject });
    ws.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
  });
  return { ws, send, listeners };
}

export async function openPage(cdp, url, width = 1440, height = 900) {
  const { targetId } = await cdp.send('Target.createTarget', { url: 'about:blank' });
  const { sessionId } = await cdp.send('Target.attachToTarget', { targetId, flatten: true });
  const page = (method, params = {}) => cdp.send(method, params, sessionId);
  await page('Page.enable');
  await page('Runtime.enable');
  await page('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: 1, mobile: false });
  await page('Emulation.setFocusEmulationEnabled', { enabled: true });
  await page('Page.navigate', { url });
  await sleep(1600);
  const evaluate = async (expression, awaitPromise = true) => {
    const result = await page('Runtime.evaluate', { expression, awaitPromise, returnByValue: true });
    if (result.exceptionDetails) {
      throw new Error(result.exceptionDetails.exception?.description || result.exceptionDetails.text);
    }
    return result.result.value;
  };
  const click = async (selector) => {
    const rect = await evaluate(`(() => {
      const node = document.querySelector(${JSON.stringify(selector)});
      if (!node) throw new Error('missing click target ${selector}');
      node.scrollIntoView({ block: 'center', inline: 'center' });
      const box = node.getBoundingClientRect();
      return { x: box.left + box.width / 2, y: box.top + box.height / 2 };
    })()`);
    await page('Input.dispatchMouseEvent', { type: 'mouseMoved', x: rect.x, y: rect.y, button: 'left', clickCount: 1 });
    await page('Input.dispatchMouseEvent', { type: 'mousePressed', x: rect.x, y: rect.y, button: 'left', clickCount: 1 });
    await page('Input.dispatchMouseEvent', { type: 'mouseReleased', x: rect.x, y: rect.y, button: 'left', clickCount: 1 });
    await sleep(130);
  };
  return { page, evaluate, click, sessionId, targetId };
}
