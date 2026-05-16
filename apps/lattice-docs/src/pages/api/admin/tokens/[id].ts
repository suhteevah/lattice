import type { APIRoute } from 'astro';

const HOME_URL = import.meta.env.LATTICE_SERVER_URL;
const ADMIN_KEY = import.meta.env.LATTICE_ADMIN_API_KEY;

export const DELETE: APIRoute = async ({ params }) => {
  if (!params.id) {
    return new Response('missing token id', { status: 400 });
  }
  const upstream = await fetch(
    `${HOME_URL}/admin/tokens/${encodeURIComponent(params.id)}`,
    {
      method: 'DELETE',
      headers: { 'X-Lattice-Admin-Key': ADMIN_KEY ?? '' },
    },
  );
  return new Response(null, { status: upstream.status });
};

export const prerender = false;
