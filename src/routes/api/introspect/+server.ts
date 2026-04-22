import type { RequestHandler } from './$types';
import { json } from '@sveltejs/kit';
import { jwtVerify, createLocalJWKSet } from 'jose';
import { db, schema } from '$lib/server/db';
import { and, eq } from 'drizzle-orm';
import { getPublicJwks } from '$lib/server/keys';

/**
 * Server-to-server introspection: consumer app sends a bastion JWT, gets back
 * fresh user + grant + perm info. Lets consumers bypass JWT staleness for
 * sensitive checks (e.g. revoke grant → next introspect returns granted=false
 * even though the existing JWT is still valid).
 */
export const GET: RequestHandler = async ({ request, url }) => {
	const auth = request.headers.get('authorization') ?? '';
	const match = auth.match(/^Bearer\s+(.+)$/i);
	if (!match) return json({ active: false, error: 'missing bearer token' }, { status: 401 });
	const token = match[1];

	const jwks = await getPublicJwks();
	const keySet = createLocalJWKSet(jwks);

	let payload: Awaited<ReturnType<typeof jwtVerify>>['payload'];
	try {
		const result = await jwtVerify(token, keySet, { issuer: url.origin });
		payload = result.payload;
	} catch (err) {
		return json(
			{ active: false, error: err instanceof Error ? err.message : 'invalid token' },
			{ status: 401 }
		);
	}

	// `sub` is now a stable hash (see identityHash); bastion looks up its own
	// user row via the non-standard `bastion_uid` claim.
	const userId = typeof payload.bastion_uid === 'number' ? payload.bastion_uid : NaN;
	if (!Number.isFinite(userId)) {
		return json({ active: false, error: 'missing bastion_uid claim' }, { status: 401 });
	}

	const user = await db.select().from(schema.users).where(eq(schema.users.id, userId)).get();
	if (!user || user.status !== 'active') {
		return json({ active: false, error: 'user not active' }, { status: 401 });
	}

	const svcSlug = typeof payload.svc === 'string' ? payload.svc : null;
	let granted = false;
	let serviceId: number | null = null;
	if (svcSlug) {
		const svc = await db
			.select()
			.from(schema.services)
			.where(eq(schema.services.slug, svcSlug))
			.get();
		if (svc) {
			serviceId = svc.id;
			const g = await db
				.select()
				.from(schema.grants)
				.where(and(eq(schema.grants.userId, userId), eq(schema.grants.serviceId, svc.id)))
				.get();
			granted = !!g;
		}
	}

	const perms = serviceId
		? await db
				.select({ key: schema.permissions.key })
				.from(schema.userPerms)
				.innerJoin(
					schema.permissions,
					eq(schema.permissions.id, schema.userPerms.permissionId)
				)
				.where(
					and(
						eq(schema.userPerms.userId, userId),
						eq(schema.permissions.serviceId, serviceId)
					)
				)
				.all()
		: [];

	return json({
		active: true,
		sub: payload.sub, // stable identity hash, echoed from the token
		bastion_uid: user.id,
		username: user.username,
		email: user.email,
		avatar: user.avatar,
		is_admin: user.isAdmin,
		svc: svcSlug,
		granted,
		perms: perms.map((p) => p.key),
		exp: payload.exp
	});
};
