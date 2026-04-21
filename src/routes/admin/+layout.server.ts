import type { LayoutServerLoad } from './$types';
import { error, redirect } from '@sveltejs/kit';

export const load: LayoutServerLoad = async ({ locals }) => {
	if (!locals.user) throw redirect(303, '/auth/login');
	if (!locals.user.isAdmin) throw error(403, 'Admin only');
	return { user: locals.user };
};
