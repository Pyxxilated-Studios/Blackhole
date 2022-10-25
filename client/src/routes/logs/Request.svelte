<script lang="ts">
    import type { Request } from "src/types";
    import Record from "./Record.svelte";

    export let request: Request;
</script>

<td class="flex flex-col text-sm">
    <span class="countdown">
        {new Date(request.timestamp).toLocaleTimeString()}
    </span>
    <span class="text-sm text-neutral-content">
        {new Date(request.timestamp).toLocaleDateString()}
    </span>
</td>
<td>
    <div tabindex="-1" class="collapse">
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
