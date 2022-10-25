<script lang="ts">
    import type { Average, Cache } from "src/types";
    import { onMount } from "svelte";

    let cache: Cache;
    let average: Average;
    let error: unknown | undefined = undefined;

    const refetch = async () => {
        try {
            const resp = await fetch("/api/statistics/cache");
            if (resp.ok) {
                cache = (await resp.json()).Cache;
                error = undefined;
            } else {
                error = resp.statusText;
            }
        } catch (err: unknown) {
            error = err;
        }

        try {
            const resp = await fetch("/api/statistics/average");
            if (resp.ok) {
                average = (await resp.json()).Average;
                error = undefined;
            } else {
                error = resp.statusText;
            }
        } catch (err: unknown) {
            error = err;
        }
    };

    onMount(() => {
        refetch();
    });
</script>

<svelte:head>
    <title>Blackhole: Statistics</title>
</svelte:head>

{#if cache}
    <h2>Cache:</h2>
    <p>
        Hits: {cache.hits}
    </p>
    <p>
        Misses: {cache.misses}
    </p>
    <p>
        Size: {cache.size} Bytes
    </p>
{:else if error}
    <p>{error}</p>
{/if}

{#if average}
    <h2>Requests:</h2>
    <p>
        Count: {average.count}
    </p>
    <p>
        Average Time: {(average.average / 1000000).toFixed(3)} ms
    </p>
{/if}

<button class="btn btn-wide" on:click={refetch}>Refresh</button>
