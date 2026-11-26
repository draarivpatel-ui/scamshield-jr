import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const root = new URL('../', import.meta.url);
const types = {
  html: 'text/html', css: 'text/css', js: 'text/javascript', svg: 'image/svg+xml', json: 'application/json',
  png: 'image/png', mp4: 'video/mp4', wav: 'audio/wav', woff2: 'font/woff2', txt: 'text/plain', md: 'text/markdown',
};
const allow = /^(?:index\.html|styles\.css|favicon\.svg|src\/[a-z-]+\.js|assets\/(?:fonts\/)?[a-z0-9.-]+|video\/[a-z0-9.-]+|README\.md|DEVPOST\.md)$/;
const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'none'; worker-src 'none'; manifest-src 'none'; base-uri 'none'; object-src 'none'; form-action 'none'; frame-ancestors 'none'";

export async function serve(port = 0, prefix = '/') {
  const server = createServer(async (request, response) => {
    const headers = {
      'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Cache-Control': 'no-cache',
      'Referrer-Policy': 'no-referrer', 'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    };
    const send = (code, payload, more = {}) => {
      response.writeHead(code, { ...headers, ...more });
      response.end(request.method === 'HEAD' ? undefined : payload);
    };
    try {
      const path = new URL(request.url, 'http://localhost').pathname;
      if (!['GET', 'HEAD'].includes(request.method)) return send(405, 'Method not allowed', { Allow: 'GET, HEAD' });
      if (!path.startsWith(prefix)) return send(404, 'Not found');
      let relative = decodeURIComponent(path.slice(prefix.length)) || 'index.html';
      if (relative.endsWith('/')) relative += 'index.html';
      if (!allow.test(relative)) return send(404, 'Not found');
      const type = types[relative.split('.').at(-1)] || 'application/octet-stream';
      send(200, await readFile(new URL(relative, root)), {
        'Content-Type': `${type}${type.startsWith('text/') || type === 'application/json' || type === 'image/svg+xml' ? '; charset=utf-8' : ''}`,
        ...(relative === 'index.html' ? { 'Content-Security-Policy': CSP } : {}),
      });
    } catch {
      send(404, 'Not found');
    }
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', resolve);
  });
  return { server, origin: `http://127.0.0.1:${server.address().port}${prefix}` };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const { origin } = await serve(Number(process.env.PORT ?? 4173));
  console.log(`ScamShield Jr running at ${origin}`);
}
