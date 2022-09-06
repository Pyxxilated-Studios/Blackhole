import type { RequestHandler } from '@sveltejs/kit';

export const GET: RequestHandler = async ({ url }) => {
	console.debug(url);
	return new Response('Hello!');
};
