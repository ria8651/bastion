import type { RequestEvent } from '@sveltejs/kit';

const STATE_COOKIE = 'bastion_oauth_state';
const TTL_SECONDS = 10 * 60;

export type OAuthState = {
	state: string;
	service: string | null;
	/** If true, the returning user becomes the first admin (setup wizard only). */
	claimAdmin?: boolean;
};

export function setOAuthStateCookie(event: RequestEvent, data: OAuthState) {
	event.cookies.set(STATE_COOKIE, JSON.stringify(data), {
		path: '/',
		httpOnly: true,
		sameSite: 'lax',
		secure: !event.url.hostname.startsWith('localhost') && event.url.hostname !== '127.0.0.1',
		maxAge: TTL_SECONDS
	});
}

export function readOAuthStateCookie(event: RequestEvent): OAuthState | null {
	const raw = event.cookies.get(STATE_COOKIE);
	if (!raw) return null;
	try {
		return JSON.parse(raw) as OAuthState;
	} catch {
		return null;
	}
}

export function clearOAuthStateCookie(event: RequestEvent) {
	event.cookies.delete(STATE_COOKIE, { path: '/' });
}
