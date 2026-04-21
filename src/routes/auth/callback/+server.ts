import type { RequestHandler } from './$types';
import { error, redirect } from '@sveltejs/kit';
import { OAuth2RequestError } from 'arctic';
import { and, count, eq } from 'drizzle-orm';
import { db, schema } from '$lib/server/db';
import { github, fetchGithubUser } from '$lib/server/github';
import { readOAuthStateCookie, clearOAuthStateCookie } from '$lib/server/oauthState';
import { createSession, generateSessionToken, setSessionCookie } from '$lib/server/session';

export const GET: RequestHandler = async (event) => {
	const code = event.url.searchParams.get('code');
	const stateParam = event.url.searchParams.get('state');
	const stored = readOAuthStateCookie(event);
	clearOAuthStateCookie(event);

	if (!code || !stateParam || !stored || stateParam !== stored.state) {
		throw error(400, 'Invalid OAuth state');
	}

	let accessToken: string;
	try {
		const client = await github(event.url.origin);
		const tokens = await client.validateAuthorizationCode(code);
		accessToken = tokens.accessToken();
	} catch (err) {
		if (err instanceof OAuth2RequestError) throw error(400, `OAuth error: ${err.code}`);
		throw err;
	}

	const gh = await fetchGithubUser(accessToken);

	// Decide if this login is the first-admin claim from the setup wizard.
	let claimAdmin = false;
	if (stored.claimAdmin) {
		const [adminRow] = await db
			.select({ c: count() })
			.from(schema.users)
			.where(eq(schema.users.isAdmin, true));
		if (adminRow.c === 0) claimAdmin = true;
	}

	const existing = await db
		.select()
		.from(schema.users)
		.where(eq(schema.users.githubId, gh.id))
		.get();

	let userId: number;
	let wasCreated = false;

	if (!existing) {
		const inserted = await db
			.insert(schema.users)
			.values({
				githubId: gh.id,
				login: gh.login,
				email: gh.email,
				avatar: gh.avatar_url,
				status: claimAdmin ? 'active' : 'pending',
				isAdmin: claimAdmin,
				lastLoginAt: new Date()
			})
			.returning({ id: schema.users.id })
			.get();
		userId = inserted.id;
		wasCreated = true;

		await db.insert(schema.auditLog).values({
			actorId: userId,
			action: claimAdmin ? 'setup.claim_admin' : 'user.signup_pending',
			target: `user:${userId}`,
			meta: { login: gh.login }
		});
	} else {
		userId = existing.id;
		await db
			.update(schema.users)
			.set({
				login: gh.login,
				email: gh.email ?? existing.email,
				avatar: gh.avatar_url ?? existing.avatar,
				lastLoginAt: new Date(),
				...(claimAdmin && !existing.isAdmin
					? { isAdmin: true, status: 'active' as const }
					: {})
			})
			.where(eq(schema.users.id, userId));
		if (claimAdmin && !existing.isAdmin) {
			await db.insert(schema.auditLog).values({
				actorId: userId,
				action: 'setup.claim_admin',
				target: `user:${userId}`,
				meta: { login: gh.login }
			});
		}
	}

	// If user tried to reach a specific service, record a request for admin review.
	if (stored.service && !claimAdmin) {
		const svc = await db
			.select()
			.from(schema.services)
			.where(eq(schema.services.slug, stored.service))
			.get();
		if (svc) {
			const alreadyGranted = await db
				.select()
				.from(schema.grants)
				.where(and(eq(schema.grants.userId, userId), eq(schema.grants.serviceId, svc.id)))
				.get();
			if (!alreadyGranted) {
				const existingPending = await db
					.select()
					.from(schema.accessRequests)
					.where(
						and(
							eq(schema.accessRequests.userId, userId),
							eq(schema.accessRequests.serviceId, svc.id)
						)
					)
					.all();
				const hasPending = existingPending.some((r) => r.resolvedAt === null);
				if (!hasPending) {
					await db.insert(schema.accessRequests).values({
						userId,
						serviceId: svc.id,
						note: `Requested via login redirect from ${stored.returnTo ?? svc.slug}`
					});
				}
			}
		}
	}

	const user = await db.select().from(schema.users).where(eq(schema.users.id, userId)).get();
	if (!user) throw error(500, 'User vanished');

	if (user.status === 'denied') throw redirect(303, '/denied');

	const token = generateSessionToken();
	const { expiresAt } = await createSession(token, userId, {
		userAgent: event.request.headers.get('user-agent'),
		ip: event.getClientAddress()
	});
	setSessionCookie(event, token, expiresAt);

	if (claimAdmin) throw redirect(303, '/setup');

	if (user.status === 'pending') throw redirect(303, '/pending');

	// Active user arriving via service redirect.
	if (stored.service && stored.returnTo) {
		const svc = await db
			.select()
			.from(schema.services)
			.where(eq(schema.services.slug, stored.service))
			.get();
		if (svc) {
			const grant = await db
				.select()
				.from(schema.grants)
				.where(and(eq(schema.grants.userId, userId), eq(schema.grants.serviceId, svc.id)))
				.get();
			if (grant) throw redirect(303, stored.returnTo);
			throw redirect(303, `/pending?service=${encodeURIComponent(svc.slug)}`);
		}
	}

	throw redirect(303, '/');
};
