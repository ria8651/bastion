import { GitHub } from 'arctic';
import { getGithubOAuthConfig } from './config';

/**
 * Build a GitHub OAuth client using credentials from the DB and the request's
 * own origin to form the callback URL. No env vars, no cached client — cheap
 * enough to reconstruct per request and avoids stale creds after wizard edits.
 */
export async function github(origin: string): Promise<GitHub> {
	const cfg = await getGithubOAuthConfig();
	if (!cfg) throw new Error('GitHub OAuth not configured yet (run setup wizard).');
	return new GitHub(cfg.clientId, cfg.clientSecret, `${origin}/auth/callback`);
}

export type GithubUser = {
	id: number;
	login: string;
	email: string | null;
	avatar_url: string | null;
};

export async function fetchGithubUser(accessToken: string): Promise<GithubUser> {
	const res = await fetch('https://api.github.com/user', {
		headers: {
			Authorization: `Bearer ${accessToken}`,
			Accept: 'application/vnd.github+json',
			'User-Agent': 'bastion'
		}
	});
	if (!res.ok) throw new Error(`GitHub /user failed: ${res.status}`);
	const u = (await res.json()) as GithubUser;

	if (!u.email) {
		const emailsRes = await fetch('https://api.github.com/user/emails', {
			headers: {
				Authorization: `Bearer ${accessToken}`,
				Accept: 'application/vnd.github+json',
				'User-Agent': 'bastion'
			}
		});
		if (emailsRes.ok) {
			const emails = (await emailsRes.json()) as Array<{
				email: string;
				primary: boolean;
				verified: boolean;
			}>;
			const primary = emails.find((e) => e.primary && e.verified) ?? emails.find((e) => e.verified);
			if (primary) u.email = primary.email;
		}
	}
	return u;
}
