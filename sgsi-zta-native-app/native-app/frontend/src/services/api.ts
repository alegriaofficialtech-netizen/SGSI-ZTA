const base = '/api/v1';
let csrfToken = '';
let refreshPromise: Promise<void> | null = null;

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    public data?: unknown,
  ) {
    super(message);
  }
}

export async function initializeCsrf(): Promise<void> {
  const response = await fetch(`${base}/auth/csrf`, { credentials: 'include' });
  if (!response.ok) throw new ApiError(response.status, 'No se pudo conectar con el servicio');
  const data = (await response.json()) as { csrf_token: string };
  csrfToken = data.csrf_token;
}

async function send(path: string, options: RequestInit): Promise<Response> {
  const headers = new Headers(options.headers);
  if (options.body) headers.set('Content-Type', 'application/json');
  if (options.method && !['GET', 'HEAD'].includes(options.method)) {
    if (!csrfToken) await initializeCsrf();
    headers.set('X-CSRF-Token', csrfToken);
  }
  return fetch(`${base}${path}`, { ...options, credentials: 'include', headers });
}

export async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  let response = await send(path, options);
  if (response.status === 401 && !path.startsWith('/auth/')) {
    refreshPromise ??= api('/auth/refresh', { method: 'POST' })
      .then(() => undefined)
      .finally(() => {
        refreshPromise = null;
      });
    await refreshPromise;
    response = await send(path, options);
  }
  if (!response.ok) {
    const data = await response.json().catch(() => ({}));
    const message =
      typeof data.detail === 'string'
        ? data.detail
        : data.detail?.message || 'Revisa los campos del formulario';
    if (response.status === 401 && !path.startsWith('/auth/mfa/') && path !== '/auth/login') {
      window.dispatchEvent(new Event('sgsi:session-expired'));
    }
    throw new ApiError(response.status, message, data);
  }
  return response.json() as Promise<T>;
}

export function dateLabel(value: string | null): string {
  if (!value) return 'Sin acceso';
  const date = new Date(
    value.endsWith('Z') || /[+-]\d{2}:\d{2}$/.test(value) ? value : `${value}Z`,
  );
  return date.toLocaleString('es-PE', { dateStyle: 'short', timeStyle: 'short' });
}
