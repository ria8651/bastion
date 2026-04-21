import type { Actions, PageServerLoad } from './$types';
import { db, schema } from '$lib/server/db';
import { desc, eq, isNull } from 'drizzle-orm';
import { fail } from '@sveltejs/kit';
import { requireAdmin, audit } from '$lib/server/authz';

export const load: PageServerLoad = async () => {
	const pending = await db
		.select({
			req: schema.accessRequests,
			user: schema.users,
			service: schema.services
		})
		.from(schema.accessRequests)
		.leftJoin(schema.users, eq(schema.users.id, schema.accessRequests.userId))
		.leftJoin(schema.services, eq(schema.services.id, schema.accessRequests.serviceId))
		.where(isNull(schema.accessRequests.resolvedAt))
		.orderBy(desc(schema.accessRequests.requestedAt))
		.all();

	const recent = await db
		.select({
			req: schema.accessRequests,
			user: schema.users,
			service: schema.services
		})
		.from(schema.accessRequests)
		.leftJoin(schema.users, eq(schema.users.id, schema.accessRequests.userId))
		.leftJoin(schema.services, eq(schema.services.id, schema.accessRequests.serviceId))
		.orderBy(desc(schema.accessRequests.resolvedAt))
		.limit(25)
		.all();
	const resolved = recent.filter((r) => r.req.resolvedAt !== null);

	return { pending, resolved };
};

export const actions: Actions = {
	approve: async (event) => {
		const admin = requireAdmin(event);
		const form = await event.request.formData();
		const id = Number(form.get('id'));
		if (!id) return fail(400, { error: 'bad input' });

		const req = await db
			.select()
			.from(schema.accessRequests)
			.where(eq(schema.accessRequests.id, id))
			.get();
		if (!req || req.resolvedAt) return fail(400, { error: 'already resolved' });

		// Promote user to active (first approval is effectively the whitelist gate).
		await db
			.update(schema.users)
			.set({ status: 'active' })
			.where(eq(schema.users.id, req.userId));

		// If request targets a specific service, insert grant.
		if (req.serviceId) {
			await db
				.insert(schema.grants)
				.values({ userId: req.userId, serviceId: req.serviceId, grantedBy: admin.id })
				.onConflictDoNothing();
		}

		await db
			.update(schema.accessRequests)
			.set({ resolvedAt: new Date(), resolvedBy: admin.id, decision: 'approved' })
			.where(eq(schema.accessRequests.id, id));

		await audit(admin.id, 'request.approve', `request:${id}`, {
			userId: req.userId,
			serviceId: req.serviceId
		});
		return { ok: true };
	},

	deny: async (event) => {
		const admin = requireAdmin(event);
		const form = await event.request.formData();
		const id = Number(form.get('id'));
		if (!id) return fail(400, { error: 'bad input' });

		const req = await db
			.select()
			.from(schema.accessRequests)
			.where(eq(schema.accessRequests.id, id))
			.get();
		if (!req || req.resolvedAt) return fail(400, { error: 'already resolved' });

		await db
			.update(schema.accessRequests)
			.set({ resolvedAt: new Date(), resolvedBy: admin.id, decision: 'denied' })
			.where(eq(schema.accessRequests.id, id));

		await audit(admin.id, 'request.deny', `request:${id}`, {
			userId: req.userId,
			serviceId: req.serviceId
		});
		return { ok: true };
	}
};
