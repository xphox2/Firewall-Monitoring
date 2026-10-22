import type { Page, Request, Route } from '@playwright/test';

export const ME = {
  id: 1,
  username: 'e2e-admin',
  role: 'admin',
  totp_enabled: false,
  email: 'e2e@example.test',
  full_name: 'E2E Admin',
  created_at: '2026-01-01T00:00:00Z',
  must_change_password: false,
  mfa_prompt_dismissed: true,
};

export interface ApiHandler {
  match: (url: URL) => boolean;
  method?: string;
  /** Static body, or a function receiving the request (for POST capture). */
  body?: unknown;
  onRequest?: (request: Request) => unknown;
  status?: number;
}

function fulfill(route: Route, data: unknown, status = 200) {
  return route.fulfill({
    status,
    contentType: 'application/json',
    body: JSON.stringify({ success: status < 400, data }),
  });
}

/**
 * Mock the admin API. Unknown GETs return an empty array (the shape most list
 * screens expect); unknown mutations return {ok:true}. Specs add precise
 * handlers for object-shaped endpoints and assertions.
 */
export async function installApiMocks(page: Page, handlers: ApiHandler[] = []) {
  await page.route('**/admin/api/**', async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const method = request.method();

    if (method === 'GET' && url.pathname === '/admin/api/me') {
      return fulfill(route, ME);
    }
    if (url.pathname === '/admin/api/csrf-token') {
      return fulfill(route, { csrf_token: 'e2e-csrf-token' });
    }
    for (const handler of handlers) {
      if (handler.method && handler.method !== method) continue;
      if (!handler.match(url)) continue;
      const data = handler.onRequest ? handler.onRequest(request) : handler.body;
      return fulfill(route, data, handler.status);
    }
    if (method !== 'GET') return fulfill(route, { ok: true });
    return fulfill(route, []);
  });
  await page.route('**/api/version', (route) => fulfill(route, { version: '0.11.376-e2e' }));
}
