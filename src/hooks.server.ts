import type { Handle } from '@sveltejs/kit';
import { redirect } from '@sveltejs/kit';
import { readSessionCookie, validateSessionToken, clearSessionCookie } from '$lib/server/session';
import { getSetupState } from '$lib/server/config';

export const handle: Handle = async ({ event, resolve }) => {
	event.locals.user = null;
	event.locals.sessionId = null;

	const token = readSessionCookie(event);
	if (token) {
		const row = await validateSessionToken(token);
		if (row) {
			event.locals.user = {
				id: row.user.id,
				githubId: row.user.githubId,
				login: row.user.login,
				email: row.user.email,
				avatar: row.user.avatar,
				status: row.user.status,
				isAdmin: row.user.isAdmin
			};
			event.locals.sessionId = row.session.id;
		} else {
			clearSessionCookie(event);
		}
	}

	// Setup mode gate: if setup is incomplete, route everything to /setup
	// except the wizard itself and the OAuth round-trip it uses.
	const path = event.url.pathname;
	const inSetupFlow =
		path.startsWith('/setup') ||
		path.startsWith('/auth/callback') ||
		path.startsWith('/auth/login') ||
		path.startsWith('/auth/logout');
	if (!inSetupFlow) {
		const setup = await getSetupState();
		if (!setup.complete) throw redirect(303, '/setup');
	}

	return resolve(event);
};
