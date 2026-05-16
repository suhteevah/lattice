import { clerkMiddleware, createRouteMatcher } from '@clerk/astro/server';

const isAdminRoute = createRouteMatcher(['/admin(.*)', '/api/admin/(.*)']);

const allowedUserIds = (import.meta.env.LATTICE_ADMIN_USER_IDS ?? '')
  .split(',')
  .map((s: string) => s.trim())
  .filter(Boolean);

export const onRequest = clerkMiddleware((auth, context) => {
  if (!isAdminRoute(context.request)) {
    return;
  }
  const { userId } = auth();
  if (!userId) {
    return context.redirect(
      `/sign-in?next=${encodeURIComponent(context.url.pathname)}`,
    );
  }
  if (allowedUserIds.length > 0 && !allowedUserIds.includes(userId)) {
    return new Response('forbidden — not on the admin allowlist', {
      status: 403,
    });
  }
});
