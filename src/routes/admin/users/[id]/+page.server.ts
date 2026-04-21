import type { Actions, PageServerLoad } from './$types';
import { db, schema } from '$lib/server/db';
import { and, eq, isNull } from 'drizzle-orm';
import { error, fail } from '@sveltejs/kit';
import { requireAdmin, audit } from '$lib/server/authz';

export const load: PageServerLoad = async ({ params }) => {
	const id = Number(params.id);
	if (!Number.isFinite(id)) throw error(400, 'bad id');

	const user = await db.select().from(schema.users).where(eq(schema.users.id, id)).get();
	if (!user) throw error(404, 'not found');

	const services = await db.select().from(schema.services).all();
	const grantRows = await db
		.select()
		.from(schema.grants)
		.where(eq(schema.grants.userId, id))
		.all();
	const grantedServiceIds = new Set(grantRows.map((g) => g.serviceId));

	const requests = await db
		.select({
			req: schema.accessRequests,
			service: schema.services
		})
		.from(schema.accessRequests)
		.leftJoin(schema.services, eq(schema.services.id, schema.accessRequests.serviceId))
		.where(eq(schema.accessRequests.userId, id))
		.all();

	const sessions = await db
		.select()
		.from(schema.sessions)
		.where(eq(schema.sessions.userId, id))
		.all();

	return {
		u: user,
		services: services.map((s) => ({ ...s, granted: grantedServiceIds.has(s.id) })),
		requests,
		sessionCount: sessions.filter((s) => !s.revokedAt && s.expiresAt.getTime() > Date.now()).length
	};
};

export const actions: Actions = {
	toggleGrant: async (event) => {
		const admin = requireAdmin(event);
		const form = await event.request.formData();
		const userId = Number(form.get('userId'));
		const serviceId = Number(form.get('serviceId'));
		const grant = form.get('grant') === '1';
		if (!userId || !serviceId) return fail(400, { error: 'bad input' });

		if (grant) {
			await db
				.insert(schema.grants)
				.values({ userId, serviceId, grantedBy: admin.id })
				.onConflictDoNothing();
			// Auto-resolve any pending access requests for this user+service.
			await db
				.update(schema.accessRequests)
				.set({
					resolvedAt: new Date(),
					resolvedBy: admin.id,
					decision: 'approved'
				})
				.where(
					and(
						eq(schema.accessRequests.userId, userId),
						eq(schema.accessRequests.serviceId, serviceId),
						isNull(schema.accessRequests.resolvedAt)
					)
				);
		} else {
			await db
				.delete(schema.grants)
				.where(and(eq(schema.grants.userId, userId), eq(schema.grants.serviceId, serviceId)));
		}
		await audit(admin.id, grant ? 'grant.add' : 'grant.remove', `user:${userId}`, { serviceId });
		return { ok: true };
	},

	revokeSessions: async (event) => {
		const admin = requireAdmin(event);
		const form = await event.request.formData();
		const userId = Number(form.get('userId'));
		if (!userId) return fail(400, { error: 'bad input' });
		await db.delete(schema.sessions).where(eq(schema.sessions.userId, userId));
		await audit(admin.id, 'session.revoke_all', `user:${userId}`);
		return { ok: true };
	}
};
