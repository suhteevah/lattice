import { clerkClient, clerkMiddleware, createRouteMatcher } from '@clerk/astro/server';

const isAdminRoute = createRouteMatcher(['/admin(.*)', '/api/admin/(.*)']);

const allowedUserIds = (import.meta.env.LATTICE_ADMIN_USER_IDS ?? '')
  .split(',')
  .map((s: string) => s.trim())
  .filter(Boolean);

const adminOrgId = (import.meta.env.LATTICE_ADMIN_ORG_ID ?? '').trim();

// Per-process cache so we don't hit the Clerk Backend API on every
// admin-route request. Membership state changes are rare; refresh
// after 5 minutes.
const orgMembershipCache = new Map<string, { isMember: boolean; expiresAt: number }>();
const CACHE_TTL_MS = 5 * 60 * 1000;

async function isOrgMember(
  context: Parameters<Parameters<typeof clerkMiddleware>[0]>[1],
  userId: string,
): Promise<boolean> {
  if (!adminOrgId) {
    return false;
  }
  const cached = orgMembershipCache.get(userId);
  if (cached && cached.expiresAt > Date.now()) {
    return cached.isMember;
  }
  try {
    const memberships = await clerkClient(context).users.getOrganizationMembershipList({
      userId,
    });
    const isMember = memberships.data.some(
      (m: any) => m.organization?.id === adminOrgId,
    );
    orgMembershipCache.set(userId, { isMember, expiresAt: Date.now() + CACHE_TTL_MS });
    return isMember;
  } catch (err: any) {
    console.warn(`Clerk org membership lookup failed for ${userId}: ${err?.message ?? err}`);
    return false;
  }
}

export const onRequest = clerkMiddleware(async (auth, context) => {
  if (!isAdminRoute(context.request)) {
    return;
  }
  const { userId } = auth();
  if (!userId) {
    return context.redirect(
      `/sign-in?next=${encodeURIComponent(context.url.pathname)}`,
    );
  }

  // Two acceptable paths to admin: flat user_id allowlist OR membership
  // in the Clerk admin org. Either succeeds; only require both gates if
  // both env vars are set AND deliberately tightened (not the case in
  // the current shipping config — they're alternatives).
  if (allowedUserIds.includes(userId)) {
    return;
  }
  if (await isOrgMember(context, userId)) {
    return;
  }

  return new Response(
    'forbidden — not on the admin allowlist and not a member of the admin org',
    { status: 403 },
  );
});
