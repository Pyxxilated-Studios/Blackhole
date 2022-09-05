export async function load({ depends }: any) {
	const api = 'http://localhost:5000/api';
	depends(api);
	const resp = await fetch(`${api}/requests`);
	const json = await resp.json();

	console.debug('RECEIVED LOAD: ', json);
	return {
		requests: json
	};
}
