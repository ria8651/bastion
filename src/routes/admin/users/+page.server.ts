import type { Actions, PageServerLoad } from './$types';
import { db, schema } from '$lib/server/db';
import { desc, eq } from 'drizzle-orm';
import { fail } from '@sveltejs/kit';
import { requireAdmin, audit } from '$lib/server/authz';

export const load: PageServerLoad = async () => {
	const users = await db.select().from(schema.users).orderBy(desc(schema.users.createdAt)).all();
	return { users };
};

export const actions: Actions = {
	setStatus: async (event) => {
		const admin = requireAdmin(event);
		const form = await event.request.formData();
		const id = Number(form.get('id'));
		const status = String(form.get('status'));
		if (!id || !['active', 'pending', 'denied'].includes(status)) {
			return fail(400, { error: 'bad input' });
		}
		if (id === admin.id && status !== 'active') {
			return fail(400, { error: "can't change your own status" });
		}
		await db
			.update(schema.users)
			.set({ status: status as 'active' | 'pending' | 'denied' })
			.where(eq(schema.users.id, id));
		await audit(admin.id, 'user.status', `user:${id}`, { status });
		return { ok: true };
	},

	setAdmin: async (event) => {
		const admin = requireAdmin(event);
		const form = await event.request.formData();
		const id = Number(form.get('id'));
		const isAdmin = form.get('isAdmin') === '1';
		if (!id) return fail(400, { error: 'bad input' });
		if (id === admin.id && !isAdmin) {
			return fail(400, { error: "can't demote yourself" });
		}
		await db.update(schema.users).set({ isAdmin }).where(eq(schema.users.id, id));
		await audit(admin.id, 'user.admin', `user:${id}`, { isAdmin });
		return { ok: true };
	}
};
