import { db, schema } from './db';
import { count, eq } from 'drizzle-orm';

export async function getGithubOAuthConfig(): Promise<{
	clientId: string;
	clientSecret: string;
} | null> {
	const row = await db
		.select()
		.from(schema.oauthProviders)
		.where(eq(schema.oauthProviders.provider, 'github'))
		.get();
	if (!row || !row.enabled) return null;
	return { clientId: row.clientId, clientSecret: row.clientSecret };
}

export async function setGithubOAuthConfig(clientId: string, clientSecret: string) {
	await db
		.insert(schema.oauthProviders)
		.values({ provider: 'github', clientId, clientSecret, enabled: true, updatedAt: new Date() })
		.onConflictDoUpdate({
			target: schema.oauthProviders.provider,
			set: { clientId, clientSecret, enabled: true, updatedAt: new Date() }
		});
}

/**
 * Setup is complete when we have:
 *   - GitHub OAuth configured
 *   - at least one admin user
 *   - at least one service
 * Wipe the DB to restart setup.
 */
export async function getSetupState() {
	const gh = await db
		.select()
		.from(schema.oauthProviders)
		.where(eq(schema.oauthProviders.provider, 'github'))
		.get();
	const [adminRow] = await db
		.select({ c: count() })
		.from(schema.users)
		.where(eq(schema.users.isAdmin, true));
	const [svcRow] = await db.select({ c: count() }).from(schema.services);

	return {
		hasGithub: !!gh,
		hasAdmin: adminRow.c > 0,
		hasServices: svcRow.c > 0,
		complete: !!gh && adminRow.c > 0 && svcRow.c > 0
	};
}
