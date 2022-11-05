<script lang="ts">
    import type { Request } from "src/types";
    import Record from "./Record.svelte";

    export let request: Request;

    let ruleClass =
        request.rule?.ty === "Deny"
            ? "border-l-2 border-l-error"
            : request.rule?.ty === "Allow"
            ? "border-l-2 border-l-success"
            : "";
</script>

<td class="text-xs md:text-sm">
    <span class="countdown">
        {new Date(request.timestamp).toLocaleTimeString()}
    </span>
    <br />
    <span class="text-accent">
        {new Date(request.timestamp).toLocaleDateString()}
    </span>
</td>
<td class={`${ruleClass} text-xs md:text-sm`}>
    <div tabindex="-1" class="collapse">
        <div class="collapse-title">
            <span>{request.question.name}</span>
            <span class="text-accent">
                {request.question.qtype}
            </span>
            {#if request.cached}
                (Cached)
            {/if}
        </div>
        <div class="collapse-content text-accent">
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
<td class="text-xs md:text-sm">{request.client}</td>
