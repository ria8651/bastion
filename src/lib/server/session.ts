import { sha256 } from '@oslojs/crypto/sha2';
import { encodeBase32LowerCaseNoPadding, encodeHexLowerCase } from '@oslojs/encoding';
import { eq } from 'drizzle-orm';
import { db, schema } from './db';
import type { RequestEvent } from '@sveltejs/kit';

const SESSION_COOKIE = 'bastion_session';
const SESSION_TTL_DAYS = 30;

export function generateSessionToken(): string {
	const bytes = new Uint8Array(20);
	crypto.getRandomValues(bytes);
	return encodeBase32LowerCaseNoPadding(bytes);
}

function hashToken(token: string): string {
	return encodeHexLowerCase(sha256(new TextEncoder().encode(token)));
}

export async function createSession(
	token: string,
	userId: number,
	meta: { userAgent?: string | null; ip?: string | null }
) {
	const id = hashToken(token);
	const expiresAt = new Date(Date.now() + SESSION_TTL_DAYS * 24 * 60 * 60 * 1000);
	await db.insert(schema.sessions).values({
		id,
		userId,
		userAgent: meta.userAgent ?? null,
		ip: meta.ip ?? null,
		expiresAt
	});
	return { id, expiresAt };
}

export async function validateSessionToken(token: string) {
	const id = hashToken(token);
	const row = await db
		.select({
			session: schema.sessions,
			user: schema.users
		})
		.from(schema.sessions)
		.innerJoin(schema.users, eq(schema.users.id, schema.sessions.userId))
		.where(eq(schema.sessions.id, id))
		.get();
	if (!row) return null;
	const now = Date.now();
	if (row.session.revokedAt) return null;
	if (row.session.expiresAt.getTime() < now) {
		await db.delete(schema.sessions).where(eq(schema.sessions.id, id));
		return null;
	}
	// Sliding renewal: if within 15 days of expiry, extend.
	const fifteenDays = 15 * 24 * 60 * 60 * 1000;
	if (row.session.expiresAt.getTime() - now < fifteenDays) {
		const newExpiry = new Date(now + SESSION_TTL_DAYS * 24 * 60 * 60 * 1000);
		await db
			.update(schema.sessions)
			.set({ expiresAt: newExpiry })
			.where(eq(schema.sessions.id, id));
		row.session.expiresAt = newExpiry;
	}
	return row;
}

export async function invalidateSession(token: string) {
	const id = hashToken(token);
	await db.delete(schema.sessions).where(eq(schema.sessions.id, id));
}

export function setSessionCookie(event: RequestEvent, token: string, expiresAt: Date) {
	event.cookies.set(SESSION_COOKIE, token, {
		path: '/',
		httpOnly: true,
		sameSite: 'lax',
		secure: !event.url.hostname.startsWith('localhost') && event.url.hostname !== '127.0.0.1',
		expires: expiresAt
	});
}

export function clearSessionCookie(event: RequestEvent) {
	event.cookies.delete(SESSION_COOKIE, { path: '/' });
}

export function readSessionCookie(event: RequestEvent): string | null {
	return event.cookies.get(SESSION_COOKIE) ?? null;
}
