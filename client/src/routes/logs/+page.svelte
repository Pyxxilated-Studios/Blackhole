<script lang="ts">
    import type { Requests } from "src/types";
    import { onMount, onDestroy } from "svelte";
    import Record from "./Record.svelte";

    let requests: Requests;
    let error: unknown | undefined = undefined;

    const refetch = async () => {
        try {
            const resp = await fetch("/api/statistics/requests");
            if (resp.ok) {
                const json = await resp.json();
                requests = ((json.Requests ?? []) as Requests).sort(
                    (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
                );
                error = undefined;
            } else {
                error = resp.statusText;
            }
        } catch (err: unknown) {
            error = err;
        }
    };

    const interval = setInterval(refetch, 30000);

    onMount(() => {
        refetch();
    });

    onDestroy(() => {
        clearInterval(interval);
    });
</script>

<svelte:head>
    <title>Blackhole: Query Log</title>
</svelte:head>

<h2>Query Log</h2>

<div class="overflow-x-auto">
    <table class="table table-zebra w-full">
        <thead>
            <tr>
                <th class="sticky top-0">Time</th>
                <th class="sticky top-0">Request</th>
                <th class="sticky top-0">Client</th>
            </tr>
        </thead>
        <tbody>
            {#if requests}
                {#each Array.from(requests) as request}
                    <tr>
                        <td class="flex flex-col font-mono">
                            <span class="countdown">
                                {new Date(request.timestamp).toLocaleTimeString()}
                            </span>
                            <span class="text-sm text-neutral-content">
                                {new Date(request.timestamp).toLocaleDateString()}
                            </span>
                        </td>
                        <td>
                            <div tabindex="-1" class="collapse collapse-plus">
                                <div class="collapse-title">
                                    <span>{request.question.name}</span>
                                    <span class="text-sm text-neutral-content">
                                        {request.question.qtype}
                                    </span>
                                    {#if request.cached}
                                        (Cached)
                                    {/if}
                                </div>
                                <div class="collapse-content text-sm text-neutral-content">
                                    <p>{request.status}</p>
                                    <p>Elapsed: {(request.elapsed / 1000000).toFixed(3)} ms</p>
                                    {#each Array.from(request.answers) as answer}
                                        {#each Object.entries(answer) as [ty, record]}
                                            <Record {ty} {record} />
                                        {/each}
                                    {/each}
                                </div>
                            </div>
                        </td>
                        <td>{request.client}</td>
                    </tr>
                {/each}
            {:else if error}
                <p>Error: {error}</p>
            {:else}
                <td />
                <td>Loading ...</td>
                <td />
            {/if}
        </tbody>
    </table>
</div>
