import { error } from '@sveltejs/kit';
import type { RequestEvent } from '@sveltejs/kit';
import { db, schema } from './db';

export function requireAdmin(event: RequestEvent) {
	const u = event.locals.user;
	if (!u) throw error(401, 'Not signed in');
	if (!u.isAdmin) throw error(403, 'Admin only');
	return u;
}

export async function audit(
	actorId: number | null,
	action: string,
	target: string | null,
	meta?: unknown
) {
	await db.insert(schema.auditLog).values({
		actorId,
		action,
		target,
		meta: (meta ?? null) as never
	});
}
