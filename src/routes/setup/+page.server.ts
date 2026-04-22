import type { Actions, PageServerLoad } from './$types';
import { fail, redirect } from '@sveltejs/kit';
import { db, schema } from '$lib/server/db';
import { getSetupState, setGithubOAuthConfig } from '$lib/server/config';
import { eq } from 'drizzle-orm';

export const load: PageServerLoad = async ({ locals }) => {
	const setup = await getSetupState();
	if (setup.complete) throw redirect(303, '/');

	// Decide current step:
	// 1 = configure GitHub OAuth
	// 2 = claim admin (complete OAuth as yourself)
	// 3 = add services
	let step: 1 | 2 | 3 = 1;
	if (setup.hasGithub) step = 2;
	if (setup.hasGithub && setup.hasAdmin) step = 3;

	const services = setup.hasGithub ? await db.select().from(schema.services).all() : [];

	return {
		step,
		setup,
		services,
		// Show who's signed in so step 2/3 can confirm identity.
		signedInAs: locals.user
	};
};

export const actions: Actions = {
	saveGithub: async (event) => {
		const setup = await getSetupState();
		if (setup.hasGithub && setup.hasAdmin) return fail(400, { error: 'setup already past this step' });

		const form = await event.request.formData();
		const clientId = String(form.get('clientId') ?? '').trim();
		const clientSecret = String(form.get('clientSecret') ?? '').trim();
		if (!clientId || !clientSecret) {
			return fail(400, {
				error: 'Both client id and secret are required',
				clientId
			});
		}
		await setGithubOAuthConfig(clientId, clientSecret);
		return { ok: true };
	},

	// Back from step 2 → step 1: clear GitHub creds so the user can re-enter
	// them (useful when the claim-admin OAuth roundtrip failed due to a typo
	// or a callback-URL mismatch in the GitHub app settings).
	resetGithub: async () => {
		const setup = await getSetupState();
		if (setup.hasAdmin) return fail(400, { error: "can't reset creds after an admin has been claimed" });
		await db.delete(schema.oauthProviders).where(eq(schema.oauthProviders.provider, 'github'));
		return { ok: true };
	},

	addService: async (event) => {
		const form = await event.request.formData();
		const slug = String(form.get('slug') ?? '').trim();
		const name = String(form.get('name') ?? '').trim() || slug;
		const returnUrl = String(form.get('returnUrl') ?? '').trim();
		if (!slug || !returnUrl) {
			return fail(400, { error: 'slug and return url required', slug, returnUrl });
		}
		if (!/^[a-z0-9-]+$/.test(slug)) {
			return fail(400, { error: 'slug must be lowercase alphanumeric + dashes', slug });
		}
		try {
			new URL(returnUrl);
		} catch {
			return fail(400, { error: 'return url must be a valid URL', slug, returnUrl });
		}

		// Grant this new service to the current admin automatically.
		const result = await db
			.insert(schema.services)
			.values({ slug, name, returnUrl })
			.onConflictDoNothing()
			.returning({ id: schema.services.id })
			.get();
		if (result && event.locals.user) {
			await db
				.insert(schema.grants)
				.values({ userId: event.locals.user.id, serviceId: result.id, grantedBy: event.locals.user.id })
				.onConflictDoNothing();
		}
		return { ok: true };
	},

	removeService: async (event) => {
		const form = await event.request.formData();
		const id = Number(form.get('id'));
		if (!id) return fail(400, { error: 'bad id' });
		await db.delete(schema.services).where(eq(schema.services.id, id));
		return { ok: true };
	},

	finish: async () => {
		const setup = await getSetupState();
		if (!setup.complete) return fail(400, { error: 'setup not complete yet' });
		throw redirect(303, '/admin');
	}
};
