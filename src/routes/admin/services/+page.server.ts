import type { Actions, PageServerLoad } from './$types';
import { db, schema } from '$lib/server/db';
import { count, eq } from 'drizzle-orm';
import { fail } from '@sveltejs/kit';
import { requireAdmin, audit } from '$lib/server/authz';

export const load: PageServerLoad = async () => {
	const services = await db.select().from(schema.services).all();
	const grantCounts = await Promise.all(
		services.map(async (s) => {
			const [r] = await db
				.select({ c: count() })
				.from(schema.grants)
				.where(eq(schema.grants.serviceId, s.id));
			return { serviceId: s.id, c: r.c };
		})
	);
	const byId = new Map(grantCounts.map((g) => [g.serviceId, g.c]));
	return {
		services: services.map((s) => ({ ...s, userCount: byId.get(s.id) ?? 0 }))
	};
};

function validate(
	form: FormData
): { ok: true; slug: string; name: string; returnUrl: string } | { ok: false; error: string } {
	const slug = String(form.get('slug') ?? '').trim();
	const name = String(form.get('name') ?? '').trim() || slug;
	const returnUrl = String(form.get('returnUrl') ?? '').trim();
	if (!slug || !returnUrl) return { ok: false, error: 'slug and return url required' };
	if (!/^[a-z0-9-]+$/.test(slug)) return { ok: false, error: 'slug must be lowercase alphanumeric + dashes' };
	try {
		new URL(returnUrl);
	} catch {
		return { ok: false, error: 'return url must be a valid URL' };
	}
	return { ok: true, slug, name, returnUrl };
}

export const actions: Actions = {
	add: async (event) => {
		const admin = requireAdmin(event);
		const form = await event.request.formData();
		const v = validate(form);
		if (!v.ok) return fail(400, { error: v.error });

		const inserted = await db
			.insert(schema.services)
			.values({ slug: v.slug, name: v.name, returnUrl: v.returnUrl })
			.onConflictDoNothing()
			.returning({ id: schema.services.id })
			.get();
		if (!inserted) return fail(400, { error: 'slug already exists' });

		await db
			.insert(schema.grants)
			.values({ userId: admin.id, serviceId: inserted.id, grantedBy: admin.id })
			.onConflictDoNothing();

		await audit(admin.id, 'service.add', `service:${inserted.id}`, { slug: v.slug });
		return { ok: true };
	},

	update: async (event) => {
		const admin = requireAdmin(event);
		const form = await event.request.formData();
		const id = Number(form.get('id'));
		if (!id) return fail(400, { error: 'bad id' });
		const v = validate(form);
		if (!v.ok) return fail(400, { error: v.error });

		await db
			.update(schema.services)
			.set({ slug: v.slug, name: v.name, returnUrl: v.returnUrl })
			.where(eq(schema.services.id, id));
		await audit(admin.id, 'service.update', `service:${id}`, { slug: v.slug });
		return { ok: true };
	},

	remove: async (event) => {
		const admin = requireAdmin(event);
		const form = await event.request.formData();
		const id = Number(form.get('id'));
		if (!id) return fail(400, { error: 'bad id' });
		await db.delete(schema.services).where(eq(schema.services.id, id));
		await audit(admin.id, 'service.remove', `service:${id}`);
		return { ok: true };
	}
};
