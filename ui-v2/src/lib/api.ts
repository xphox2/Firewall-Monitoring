export class ApiError extends Error {
  status: number;
  code?: string;
  details?: unknown;

  constructor(message: string, status: number, code?: string, details?: unknown) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

let cachedCsrfToken: string | null = null;
let csrfInflight: Promise<string> | null = null;

// While the 2FA enrollment screen shows one-time recovery codes the session has
// already been revoked (token_version bump). The shell's background poller
// would otherwise 401 and hard-redirect before the operator can save them.
let suppressAuthRedirect = false;

export function setSuppressAuthRedirect(suppress: boolean) {
  suppressAuthRedirect = suppress;
}

export async function getCsrfToken(forceRefresh = false): Promise<string> {
  if (cachedCsrfToken && !forceRefresh) {
    return cachedCsrfToken;
  }
  if (csrfInflight && !forceRefresh) {
    return csrfInflight;
  }
  csrfInflight = (async () => {
    const res = await fetch('/admin/api/csrf-token', {
      credentials: 'same-origin',
      headers: { Accept: 'application/json' },
    });
    if (res.status === 401) {
      if (!suppressAuthRedirect) {
        window.top
          ? (window.top.location.href = '/admin/login')
          : (window.location.href = '/admin/login');
      }
      throw new ApiError('Authentication required', 401);
    }
    if (!res.ok) {
      throw new ApiError('Failed to fetch CSRF token', res.status);
    }
    const body = (await res.json()) as { csrf_token?: string };
    cachedCsrfToken = body.csrf_token || '';
    return cachedCsrfToken;
  })();

  try {
    return await csrfInflight;
  } finally {
    csrfInflight = null;
  }
}

export function clearCsrfToken() {
  cachedCsrfToken = null;
}

const MUTATION_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

export interface ApiFetchOptions extends Omit<RequestInit, 'body'> {
  body?: unknown;
  skipAuthRedirect?: boolean;
}

export async function apiFetch<T = unknown>(
  path: string,
  options: ApiFetchOptions = {},
): Promise<T> {
  const method = (options.method || 'GET').toUpperCase();
  const headers = new Headers(options.headers || {});
  headers.set('Accept', 'application/json');

  let serializedBody: BodyInit | undefined;
  if (options.body !== undefined) {
    if (
      typeof options.body === 'string' ||
      options.body instanceof FormData ||
      options.body instanceof URLSearchParams
    ) {
      serializedBody = options.body;
    } else {
      headers.set('Content-Type', 'application/json');
      serializedBody = JSON.stringify(options.body);
    }
  }

  if (MUTATION_METHODS.has(method) && path.startsWith('/admin/')) {
    const token = await getCsrfToken();
    if (token) {
      headers.set('X-CSRF-Token', token);
    }
  }

  const execute = async (): Promise<Response> =>
    fetch(path, {
      ...options,
      method,
      headers,
      body: serializedBody,
      credentials: 'same-origin',
    });

  let res = await execute();

  // Retry once on CSRF mismatch in case session rotated
  if (res.status === 403 && MUTATION_METHODS.has(method) && path.startsWith('/admin/')) {
    const clone = res.clone();
    try {
      const errJson = (await clone.json()) as { error?: string; code?: string };
      if (errJson.error && errJson.error.toLowerCase().includes('csrf')) {
        const freshToken = await getCsrfToken(true);
        headers.set('X-CSRF-Token', freshToken);
        res = await execute();
      }
    } catch {
      // Ignore parse error and handle below
    }
  }

  // Transient 502/503/504 retry once for GET requests (AUDIT-130 parity)
  if ((res.status === 502 || res.status === 503 || res.status === 504) && method === 'GET') {
    await new Promise((r) => setTimeout(r, 400));
    res = await execute();
  }

  if (res.status === 401 && !options.skipAuthRedirect && !suppressAuthRedirect) {
    if (window.top) {
      window.top.location.href = '/admin/login';
    } else {
      window.location.href = '/admin/login';
    }
    throw new ApiError('Authentication required', 401);
  }

  const contentType = res.headers.get('content-type') || '';
  const isJson = contentType.includes('application/json');
  const payload = isJson ? await res.json() : await res.text();

  if (!res.ok) {
    const errObj = typeof payload === 'object' && payload !== null ? (payload as Record<string, unknown>) : {};
    const code = typeof errObj.code === 'string' ? errObj.code : undefined;
    const msg =
      (typeof errObj.error === 'string' && errObj.error) ||
      (typeof errObj.message === 'string' && errObj.message) ||
      `Request failed (${res.status})`;

    if (res.status === 403 && code === 'password_change_required') {
      window.dispatchEvent(new CustomEvent('fwmon:password-change-required'));
    }

    throw new ApiError(msg, res.status, code, payload);
  }

  // Unwrap standard `{ success: true, data: ... }` envelope when present,
  // unless caller expects raw envelope or pagination fields sit alongside `data`.
  if (
    typeof payload === 'object' &&
    payload !== null &&
    'data' in payload &&
    !('total' in payload) &&
    !('page' in payload) &&
    !('items' in payload)
  ) {
    return unwrapEnvelope<T>(payload as Record<string, unknown>);
  }

  return payload as T;
}

/**
 * Unwrap the `{ success, data, ... }` envelope, KEEPING the sibling keys.
 *
 * Four handlers put metadata BESIDE `data` rather than inside it, and the
 * old unwrap dropped it on the floor:
 *
 *   - `GET /admin/api/normalize/backfill/status` → `history`, `resumable`,
 *     `hint`;
 *   - `POST /admin/api/normalize/backfill` → `estimate`;
 *   - `POST /admin/api/archive/restores` → `estimate`;
 *   - `GET /admin/api/display-settings` → `is_admin`.
 *
 * So the backfill panel could not show its history or its resume hint, and
 * the backfill and restore confirmations lost their row/disk estimate.
 *
 * The siblings are MERGED INTO the unwrapped `data` when `data` is a plain
 * object. An array `data` (traps, flows, the settings list) is returned
 * untouched: there is nothing to merge into, and the siblings of those
 * endpoints are not part of any contract.
 */
export function unwrapEnvelope<T>(payload: Record<string, unknown>): T {
  const { success, error, message, data, ...siblings } = payload;
  void success;
  void error;
  void message;
  if (data && typeof data === 'object' && !Array.isArray(data)) {
    return { ...(data as Record<string, unknown>), ...siblings } as T;
  }
  return data as T;
}

// --- Core Shared API Types ---

export interface SystemSetting {
  key: string;
  value: string;
  label?: string;
  category?: string;
  type?: string;
  is_secret?: boolean;
}

export type AdminRole = 'viewer' | 'operator' | 'admin';

export interface MeResponse {
  id: number;
  username: string;
  role: AdminRole;
  totp_enabled: boolean;
  email: string;
  full_name: string;
  created_at?: string;
  must_change_password: boolean;
  mfa_prompt_dismissed: boolean;
}

export interface DashboardSummary {
  generated_at: string;
  partial?: boolean;
  // The dashboard handler emits partial_blocks (the failed-block names).
  partial_blocks?: string[];
  device_counts: {
    total: number;
    online: number;
    offline: number;
  };
  devices: Array<{
    id: number;
    name: string;
    status: string;
    last_polled?: string;
  }>;
  probe_count_active: number;
  probe_count_pending: number;
  probe_count_stale: number;
  syslog_24h: number;
  trap_24h: number;
}

export interface SystemHealthSnapshot {
  status?: string;
  uptime_seconds?: number;
  goroutines?: number;
  memory_alloc_bytes?: number;
  memory_sys_bytes?: number;
  db_size_bytes?: number;
  db_open_connections?: number;
  active_alerts_count?: number;
  runtime?: {
    goroutines?: number;
    heap_alloc_mb?: number;
    heap_sys_mb?: number;
  };
  db?: {
    size_bytes?: number;
    pool?: {
      open?: number;
      in_use?: number;
      idle?: number;
    };
  };
}

export function hasMinRole(userRole: AdminRole | undefined, minRole: AdminRole): boolean {
  const rank: Record<AdminRole, number> = {
    viewer: 1,
    operator: 2,
    admin: 3,
  };
  const current = userRole ? rank[userRole] || 0 : 0;
  return current >= rank[minRole];
}
