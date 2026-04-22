import type { Actions, PageServerLoad } from './$types';
import { error, redirect } from '@sveltejs/kit';
import { generateState } from 'arctic';
import { eq } from 'drizzle-orm';
import { db, schema } from '$lib/server/db';
import { github } from '$lib/server/github';
import { setOAuthStateCookie } from '$lib/server/oauthState';
import { getSetupState } from '$lib/server/config';

export const load: PageServerLoad = async ({ url }) => {
	const service = url.searchParams.get('service');
	const claimAdmin = url.searchParams.get('claim_admin') === '1';

	let serviceRow: { slug: string; name: string } | null = null;
	if (service) {
		const row = await db
			.select({ slug: schema.services.slug, name: schema.services.name })
			.from(schema.services)
			.where(eq(schema.services.slug, service))
			.get();
		if (!row) {
			throw error(400, `Unknown service "${service}". Register it at /admin/services.`);
		}
		serviceRow = row;
	}

	return { service: serviceRow, claimAdmin };
};

export const actions: Actions = {
	github: async (event) => {
		const form = await event.request.formData();
		const service = (String(form.get('service') ?? '').trim() || null) as string | null;
		const claimAdminFlag = form.get('claim_admin') === '1';

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
			if (!row) throw error(400, `Unknown service "${service}"`);
		}

		const state = generateState();
		const client = await github(event.url.origin);
		const authUrl = client.createAuthorizationURL(state, ['read:user', 'user:email']);

		setOAuthStateCookie(event, { state, service, claimAdmin });
		throw redirect(303, authUrl.toString());
	}
};
