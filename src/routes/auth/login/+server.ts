import type { RequestHandler } from './$types';
import { redirect } from '@sveltejs/kit';
import { generateState } from 'arctic';
import { github } from '$lib/server/github';
import { setOAuthStateCookie } from '$lib/server/oauthState';
import { db, schema } from '$lib/server/db';
import { getSetupState } from '$lib/server/config';
import { count, eq } from 'drizzle-orm';

export const GET: RequestHandler = async (event) => {
	const service = event.url.searchParams.get('service');
	const returnTo = event.url.searchParams.get('return');
	const claimAdminFlag = event.url.searchParams.get('claim_admin') === '1';

	// "claim_admin" is only honored while setup is incomplete AND no admin exists yet.
	let claimAdmin = false;
	if (claimAdminFlag) {
		const setup = await getSetupState();
		if (!setup.hasAdmin) claimAdmin = true;
	}

	if (service) {
		const row = await db
			.select()
			.from(schema.services)
			.where(eq(schema.services.slug, service))
			.get();
		if (!row) throw redirect(303, '/?error=unknown_service');
		if (returnTo && !returnTo.startsWith(row.returnUrlPrefix)) {
			throw redirect(303, '/?error=bad_return_url');
		}
	}

	const state = generateState();
	const client = await github(event.url.origin);
	const url = client.createAuthorizationURL(state, ['read:user', 'user:email']);

	setOAuthStateCookie(event, { state, service, returnTo, claimAdmin });
	throw redirect(303, url.toString());
};
