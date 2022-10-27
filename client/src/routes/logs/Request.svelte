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

<td>
    <span class="countdown text-xl">
        {new Date(request.timestamp).toLocaleTimeString()}
    </span>
    <p class="text-sm text-accent">
        {new Date(request.timestamp).toLocaleDateString()}
    </p>
</td>
<td class={ruleClass}>
    <div tabindex="-1" class="collapse">
        <div class="collapse-title">
            <span>{request.question.name}</span>
            <span class="text-sm text-accent">
                {request.question.qtype}
            </span>
            {#if request.cached}
                (Cached)
            {/if}
        </div>
        <div class="collapse-content text-sm text-accent">
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
