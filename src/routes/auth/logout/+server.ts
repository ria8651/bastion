import type { RequestHandler } from './$types';
import { redirect } from '@sveltejs/kit';
import { invalidateSession, clearSessionCookie, readSessionCookie } from '$lib/server/session';

export const POST: RequestHandler = async (event) => {
	const token = readSessionCookie(event);
	if (token) await invalidateSession(token);
	clearSessionCookie(event);
	throw redirect(303, '/');
};
