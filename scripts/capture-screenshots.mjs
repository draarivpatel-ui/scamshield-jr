import { mkdirSync, writeFileSync } from 'node:fs';
import { serve } from './serve.mjs';
import { connectCdp, launchChrome, openPage, sleep } from './cdp.mjs';

const WIDTH = 1440;
const HEIGHT = 900;
const outDir = new URL('../assets/', import.meta.url);
mkdirSync(outDir, { recursive: true });

const { server, origin } = await serve(0, '/');
const browser = await launchChrome(WIDTH, HEIGHT);

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
  const page = await openPage(cdp, origin, WIDTH, HEIGHT);
  await page.evaluate(`new Promise((resolve) => {
    const started = Date.now();
    (function check() {
      if (window.__scamshieldReady && document.fonts.status === 'loaded') return resolve(true);
      if (Date.now() - started > 9000) return resolve(false);
      setTimeout(check, 90);
    })();
  })`);
  await sleep(450);

  const capture = async (name) => {
    const shot = await page.page('Page.captureScreenshot', { format: 'png', captureBeyondViewport: false });
    writeFileSync(new URL(name, outDir), Buffer.from(shot.data, 'base64'));
    console.log(`captured assets/${name}`);
  };

  await page.evaluate(`scrollTo(0, 0)`);
  await capture('analyzer-1440x900.png');

  await page.evaluate(`window.__scamshield.loadSample('lookalike-payment')`);
  await sleep(420);
  await page.evaluate(`document.querySelector('#evidence-title').scrollIntoView({ block: 'start' }); scrollBy(0, -18)`);
  await sleep(360);
  await capture('evidence-1440x900.png');

  await page.evaluate(`window.__scamshield.setMode('drill')`);
  await sleep(260);
  await page.evaluate(`window.__scamshield.selectDrill('family-bail-secret')`);
  await sleep(220);
  await page.evaluate(`window.__scamshield.markDrillTactics(['urgency-pressure', 'payment-rail-switch', 'family-emergency-script'])`);
  await page.evaluate(`window.__scamshield.chooseDrillCategory('scam')`);
  await page.evaluate(`window.__scamshield.gradeCurrentDrill()`);
  await sleep(300);
  await page.evaluate(`document.querySelector('#drill-title').scrollIntoView({ block: 'start' }); scrollBy(0, -18)`);
  await sleep(300);
  await capture('drill-1440x900.png');

  cdp.ws.close();
  await shutdown(0);
} catch (error) {
  console.error(error);
  await shutdown(1);
}
