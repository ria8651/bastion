import type { RequestHandler } from './$types';
import { json } from '@sveltejs/kit';
import { getPublicJwks } from '$lib/server/keys';

export const GET: RequestHandler = async () => {
	const jwks = await getPublicJwks();
	return json(jwks, {
		headers: {
			// JWKS is cacheable but short — clients should re-fetch during key rotation.
			'cache-control': 'public, max-age=300'
		}
	});
};
