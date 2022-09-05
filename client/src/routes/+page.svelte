<script lang="ts">
	import Navigation from '../components/Navigation.svelte';

	export let data: Record<string, [string, number][]>;
	let error: string | undefined = undefined;
	console.debug('Requests: ', data.requests);
</script>

<Navigation />

<main>
	{#if data.requests}
		{#each Array.from(data.requests) as entry}
			<p>{entry[0]}: {entry[1]}</p>
		{/each}
	{:else if error}
		<p>Error: {error}</p>
	{/if}
</main>

<style global>
	html {
		color: #ecf0f1;
		background-color: rgb(17, 17, 34);
		font-size: 1.25rem;
		line-height: 1.75rem;
		width: 100%;
		font-family: Helvetica, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, Segoe UI,
			Roboto, Helvetica Neue, Arial, Noto Sans, sans-serif, 'Apple Color Emoji', 'Segoe UI Emoji',
			Segoe UI Symbol, 'Noto Color Emoji';
		line-height: 1.5;
	}

	* {
		box-sizing: border-box;
		border-width: 0;
		border-style: solid;
	}

	body {
		margin: 0;
		width: 100%;
	}

	main {
		width: 100%;
		margin-left: auto;
		margin-right: auto;
		padding-bottom: 4rem;
		padding-left: 1.5rem;
		padding-right: 1.5rem;
	}
</style>
