import { sql } from 'drizzle-orm';
import { sqliteTable, integer, text, uniqueIndex, index } from 'drizzle-orm/sqlite-core';

export const users = sqliteTable(
	'users',
	{
		id: integer('id').primaryKey({ autoIncrement: true }),
		githubId: integer('github_id').notNull(),
		login: text('login').notNull(),
		email: text('email'),
		avatar: text('avatar'),
		status: text('status', { enum: ['active', 'pending', 'denied'] })
			.notNull()
			.default('pending'),
		isAdmin: integer('is_admin', { mode: 'boolean' }).notNull().default(false),
		createdAt: integer('created_at', { mode: 'timestamp' })
			.notNull()
			.default(sql`(unixepoch())`),
		lastLoginAt: integer('last_login_at', { mode: 'timestamp' })
	},
	(t) => ({
		githubIdx: uniqueIndex('users_github_id_idx').on(t.githubId),
		loginIdx: uniqueIndex('users_login_idx').on(t.login)
	})
);

export const services = sqliteTable(
	'services',
	{
		id: integer('id').primaryKey({ autoIncrement: true }),
		slug: text('slug').notNull(),
		name: text('name').notNull(),
		returnUrlPrefix: text('return_url_prefix').notNull(),
		createdAt: integer('created_at', { mode: 'timestamp' })
			.notNull()
			.default(sql`(unixepoch())`)
	},
	(t) => ({
		slugIdx: uniqueIndex('services_slug_idx').on(t.slug)
	})
);

export const permissions = sqliteTable(
	'permissions',
	{
		id: integer('id').primaryKey({ autoIncrement: true }),
		serviceId: integer('service_id')
			.notNull()
			.references(() => services.id, { onDelete: 'cascade' }),
		key: text('key').notNull(),
		description: text('description')
	},
	(t) => ({
		serviceKeyIdx: uniqueIndex('permissions_service_key_idx').on(t.serviceId, t.key)
	})
);

export const grants = sqliteTable(
	'grants',
	{
		userId: integer('user_id')
			.notNull()
			.references(() => users.id, { onDelete: 'cascade' }),
		serviceId: integer('service_id')
			.notNull()
			.references(() => services.id, { onDelete: 'cascade' }),
		grantedAt: integer('granted_at', { mode: 'timestamp' })
			.notNull()
			.default(sql`(unixepoch())`),
		grantedBy: integer('granted_by').references(() => users.id, { onDelete: 'set null' })
	},
	(t) => ({
		pk: uniqueIndex('grants_pk').on(t.userId, t.serviceId)
	})
);

export const userPerms = sqliteTable(
	'user_perms',
	{
		userId: integer('user_id')
			.notNull()
			.references(() => users.id, { onDelete: 'cascade' }),
		permissionId: integer('permission_id')
			.notNull()
			.references(() => permissions.id, { onDelete: 'cascade' })
	},
	(t) => ({
		pk: uniqueIndex('user_perms_pk').on(t.userId, t.permissionId)
	})
);

export const sessions = sqliteTable(
	'sessions',
	{
		id: text('id').primaryKey(),
		userId: integer('user_id')
			.notNull()
			.references(() => users.id, { onDelete: 'cascade' }),
		userAgent: text('user_agent'),
		ip: text('ip'),
		createdAt: integer('created_at', { mode: 'timestamp' })
			.notNull()
			.default(sql`(unixepoch())`),
		expiresAt: integer('expires_at', { mode: 'timestamp' }).notNull(),
		revokedAt: integer('revoked_at', { mode: 'timestamp' })
	},
	(t) => ({
		userIdx: index('sessions_user_idx').on(t.userId)
	})
);

export const accessRequests = sqliteTable(
	'access_requests',
	{
		id: integer('id').primaryKey({ autoIncrement: true }),
		userId: integer('user_id')
			.notNull()
			.references(() => users.id, { onDelete: 'cascade' }),
		serviceId: integer('service_id').references(() => services.id, { onDelete: 'cascade' }),
		note: text('note'),
		requestedAt: integer('requested_at', { mode: 'timestamp' })
			.notNull()
			.default(sql`(unixepoch())`),
		resolvedAt: integer('resolved_at', { mode: 'timestamp' }),
		resolvedBy: integer('resolved_by').references(() => users.id, { onDelete: 'set null' }),
		decision: text('decision', { enum: ['approved', 'denied'] })
	},
	(t) => ({
		userIdx: index('access_requests_user_idx').on(t.userId),
		pendingIdx: index('access_requests_pending_idx').on(t.resolvedAt)
	})
);

export const auditLog = sqliteTable(
	'audit_log',
	{
		id: integer('id').primaryKey({ autoIncrement: true }),
		actorId: integer('actor_id').references(() => users.id, { onDelete: 'set null' }),
		action: text('action').notNull(),
		target: text('target'),
		meta: text('meta', { mode: 'json' }),
		at: integer('at', { mode: 'timestamp' })
			.notNull()
			.default(sql`(unixepoch())`)
	},
	(t) => ({
		atIdx: index('audit_log_at_idx').on(t.at),
		actorIdx: index('audit_log_actor_idx').on(t.actorId)
	})
);

/**
 * Per-provider OAuth credentials. One row per provider slug ('github', eventually
 * 'google', 'gitlab' etc.). Populated by the first-run setup wizard; editable
 * later from the admin panel.
 */
export const oauthProviders = sqliteTable(
	'oauth_providers',
	{
		provider: text('provider').primaryKey(), // 'github'
		clientId: text('client_id').notNull(),
		clientSecret: text('client_secret').notNull(),
		enabled: integer('enabled', { mode: 'boolean' }).notNull().default(true),
		updatedAt: integer('updated_at', { mode: 'timestamp' })
			.notNull()
			.default(sql`(unixepoch())`)
	}
);

export type User = typeof users.$inferSelect;
export type Service = typeof services.$inferSelect;
export type Session = typeof sessions.$inferSelect;
