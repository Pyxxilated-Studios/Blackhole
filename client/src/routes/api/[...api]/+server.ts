import type { RequestHandler } from '@sveltejs/kit';

export const GET: RequestHandler = async ({ url }) => {
	return await fetch(`http://localhost:5000${url.pathname}`);
};
