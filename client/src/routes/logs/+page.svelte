<script lang="ts">
    import Request from "./Request.svelte";

    import type { Requests } from "../../types";
    import { onMount } from "svelte";

    import { inview } from "svelte-inview";

    import { toast } from "@zerodevx/svelte-toast";

    let requests: Requests;

    let count = 25;
    let shownRequests: Requests;

    $: {
        if (requests) shownRequests = requests.slice(0, count);
    }

    const refetch = async () => {
        try {
            const resp = await fetch("/api/statistics/requests");
            if (resp.ok) {
                const json = await resp.json();
                requests = Array.from(
                    ((json.Requests ?? []) as Requests).sort(
                        (a, b) => b.timestamp.secs_since_epoch - a.timestamp.secs_since_epoch
                    )
                );
            } else {
                toast.push((await resp.json()).reason, {
                    classes: ["error"],
                });
            }
        } catch (err: unknown) {
            toast.push(String(err), {
                classes: ["error"],
            });
        }
    };

    onMount(() => {
        refetch();
    });
</script>

<svelte:head>
    <title>Blackhole: Query Log</title>
</svelte:head>

<div class="flex flex-row">
    <h2 class="basis-5/6">Query Log</h2>
    <button class="btn basis-1/6 mt-14" on:click={refetch}>Refresh</button>
</div>

{#if requests}
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
                {#each shownRequests as request, idx (request.timestamp)}
                    {#if idx == shownRequests.length - 1}
                        <tr
                            use:inview
                            on:inview_enter={() => {
                                count += 25;
                            }}
                        >
                            <Request {request} />
                        </tr>
                    {:else}
                        <tr>
                            <Request {request} />
                        </tr>
                    {/if}
                {/each}
            </tbody>
        </table>
    </div>
{/if}
