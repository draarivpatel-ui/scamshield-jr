import assert from 'node:assert/strict';
import { serve } from './serve.mjs';
import { connectCdp, launchChrome, openPage, sleep } from './cdp.mjs';

const { server, origin } = await serve(0, '/');
const browser = await launchChrome(1440, 900);

async function shutdown(code) {
  await browser.cleanup();
  server.close();
  process.exit(code);
}

process.on('unhandledRejection', async (error) => {
  console.error(error);
  await shutdown(1);
});

try {
  const cdp = await connectCdp(browser.webSocketDebuggerUrl);
  const page = await openPage(cdp, origin, 1440, 900);
  await page.evaluate(`new Promise((resolve) => {
    const started = Date.now();
    (function check() {
      if (window.__scamshieldReady) return resolve(true);
      if (Date.now() - started > 8000) return resolve(false);
      setTimeout(check, 80);
    })();
  })`);
  await sleep(350);

  const initial = await page.evaluate(`(() => {
    const state = window.__scamshield.getState();
    return {
      score: state.analysis.verdict.score,
      tactics: document.querySelectorAll('.tactic-card').length,
      marks: document.querySelectorAll('mark').length,
      unevaluated: state.analysis.unevaluated.length,
      verdict: state.analysis.verdict.label,
      resources: performance.getEntriesByType('resource').map((item) => item.name),
    };
  })()`);
  assert.equal(initial.score, 43);
  assert.equal(initial.tactics, 8);
  assert.ok(initial.marks >= 4, `expected highlighted evidence, got ${initial.marks}`);
  assert.equal(initial.unevaluated, 2);
  assert.doesNotMatch(initial.verdict.toLowerCase(), /\bsafe\b/);
  assert.ok(initial.resources.every((url) => url.startsWith(origin) || url.startsWith('data:')), 'only same-origin resources may load');

  await page.click('#mode-drill');
  await sleep(250);
  const drillVisible = await page.evaluate(`(() => ({
    hidden: document.querySelector('#drill-section').hidden,
    buttons: document.querySelectorAll('.drill-choice').length,
    analyzerHidden: document.querySelector('#analyzer-form').hidden,
  }))()`);
  assert.equal(drillVisible.hidden, false);
  assert.equal(drillVisible.buttons, 6);
  assert.equal(drillVisible.analyzerHidden, true);

  for (const tactic of ['urgency-pressure', 'payment-rail-switch', 'family-emergency-script']) {
    await page.click(`#drill-tactics label:has(input[value="${tactic}"])`);
  }
  await page.click('[data-category="scam"]');
  await page.click('#grade-drill');
  await sleep(250);
  const grade = await page.evaluate(`(() => {
    const state = window.__scamshield.getState();
    return {
      score: state.drillGrade && state.drillGrade.score,
      text: document.querySelector('#grade-panel').textContent,
      selected: state.drillSelections.length,
    };
  })()`);
  assert.equal(grade.score, 100);
  assert.equal(grade.selected, 3);
  assert.match(grade.text, /False alarms: none/);

  await page.click('#mode-analyze');
  await sleep(220);
  const analyzerVisible = await page.evaluate(`(() => ({
    formHidden: document.querySelector('#analyzer-form').hidden,
    drillHidden: document.querySelector('#drill-section').hidden,
  }))()`);
  assert.equal(analyzerVisible.formHidden, false);
  assert.equal(analyzerVisible.drillHidden, true);

  await page.page('Emulation.setDeviceMetricsOverride', { width: 390, height: 844, deviceScaleFactor: 2, mobile: true });
  await sleep(450);
  const mobile = await page.evaluate(`(() => ({
    width: innerWidth,
    overflow: document.documentElement.scrollWidth > innerWidth + 1,
    title: document.querySelector('h1').getBoundingClientRect().width,
  }))()`);
  assert.equal(mobile.width, 390);
  assert.equal(mobile.overflow, false, 'mobile layout has horizontal overflow');
  assert.ok(mobile.title > 180, 'mobile title is visible');

  cdp.ws.close();
  console.log('browser-check passed');
  await shutdown(0);
} catch (error) {
  console.error(error);
  await shutdown(1);
}
