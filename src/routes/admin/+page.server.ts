import type { PageServerLoad } from './$types';
import { db, schema } from '$lib/server/db';
import { count, desc, eq, isNull } from 'drizzle-orm';

export const load: PageServerLoad = async () => {
	const [userCount] = await db.select({ c: count() }).from(schema.users);
	const [pendingUsers] = await db
		.select({ c: count() })
		.from(schema.users)
		.where(eq(schema.users.status, 'pending'));
	const [pendingRequests] = await db
		.select({ c: count() })
		.from(schema.accessRequests)
		.where(isNull(schema.accessRequests.resolvedAt));
	const [serviceCount] = await db.select({ c: count() }).from(schema.services);

	const recentAudit = await db
		.select()
		.from(schema.auditLog)
		.orderBy(desc(schema.auditLog.at))
		.limit(20);

	return {
		counts: {
			users: userCount.c,
			pendingUsers: pendingUsers.c,
			pendingRequests: pendingRequests.c,
			services: serviceCount.c
		},
		recentAudit
	};
};
