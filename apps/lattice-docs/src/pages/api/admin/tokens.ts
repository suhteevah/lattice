import type { APIRoute } from 'astro';

const HOME_URL = import.meta.env.LATTICE_SERVER_URL;
const ADMIN_KEY = import.meta.env.LATTICE_ADMIN_API_KEY;

if (!HOME_URL || !ADMIN_KEY) {
  console.warn('LATTICE_SERVER_URL or LATTICE_ADMIN_API_KEY not set');
}

const forward = async (
  method: 'GET' | 'POST',
  path: string,
  body?: unknown,
): Promise<Response> => {
  const init: RequestInit = {
    method,
    headers: {
      'X-Lattice-Admin-Key': ADMIN_KEY ?? '',
      'Content-Type': 'application/json',
    },
  };
  if (body !== undefined) {
    init.body = JSON.stringify(body);
  }
  return await fetch(`${HOME_URL}${path}`, init);
};

export const POST: APIRoute = async ({ request }) => {
  const body = await request.json().catch(() => ({}));
  const upstream = await forward('POST', '/admin/tokens', body);
  return new Response(await upstream.text(), {
    status: upstream.status,
    headers: { 'Content-Type': 'application/json' },
  });
};

export const GET: APIRoute = async () => {
  const upstream = await forward('GET', '/admin/tokens');
  return new Response(await upstream.text(), {
    status: upstream.status,
    headers: { 'Content-Type': 'application/json' },
  });
};

export const prerender = false;
