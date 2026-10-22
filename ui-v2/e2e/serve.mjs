import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

// Minimal production-shell server for Playwright: the V2 SPA is served under
// /admin/v2 exactly like the Go binary does, and the built assets come from
// cmd/api/static. API calls are intercepted by page.route() in the tests.
const here = resolve(fileURLToPath(new URL('.', import.meta.url)));
const repo = resolve(here, '..', '..');
const staticRoot = join(repo, 'cmd', 'api', 'static');
const shellPath = join(repo, 'web', 'admin', 'admin-v2.html');
const port = Number(process.env.E2E_PORT || 4173);

const TYPES = {
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.html': 'text/html; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
  '.woff': 'font/woff',
  '.ttf': 'font/ttf',
};

async function sendFile(res, path, type) {
  const body = await readFile(path);
  res.writeHead(200, {
    'Content-Type': type || TYPES[extname(path)] || 'application/octet-stream',
    'Cache-Control': 'no-store',
  });
  res.end(body);
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url || '/', 'http://127.0.0.1');
  const pathname = decodeURIComponent(url.pathname);
  try {
    if (pathname === '/admin/v2' || pathname.startsWith('/admin/v2/')) {
      await sendFile(res, shellPath, TYPES['.html']);
      return;
    }
    if (pathname.startsWith('/static/')) {
      const file = normalize(join(staticRoot, pathname.slice('/static/'.length)));
      if (!file.startsWith(staticRoot + sep)) {
        res.writeHead(403).end('forbidden');
        return;
      }
      await sendFile(res, file);
      return;
    }
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('not found');
  } catch {
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('not found');
  }
});

server.listen(port, '127.0.0.1', () => {
  console.log(`V2 e2e shell on http://127.0.0.1:${port}/admin/v2`);
});
