<script lang="ts">
    import type { Request } from "../../types";
    import Record from "./Record.svelte";

    export let request: Request;

    let ruleClass =
        request.rule?.ty === "Deny"
            ? "border-l-2 border-l-error"
            : request.rule?.ty === "Allow"
              ? "border-l-2 border-l-success"
              : "";

    let timestamp = new Date(request.timestamp.secs_since_epoch * 1_000);
</script>

<td class="text-xs md:text-sm">
    <span class="countdown">
        {timestamp.toLocaleTimeString()}
    </span>
    <br />
    <span class="text-accent">
        {timestamp.toLocaleDateString()}
    </span>
</td>
<td class={`${ruleClass} text-xs md:text-sm`}>
    <div tabindex="-1" class="collapse">
        <div class="collapse-title">
            <span>{request.question}</span>
            {#if request.cached}
                <span class="text-accent">(Cached)</span>
            {/if}
        </div>
        <div class="collapse-content text-accent">
            <p>{request.status}</p>
            <p>Elapsed: {(request.elapsed / 1000000).toFixed(3)} ms</p>
            {#each request.answers as answer}
                <Record {answer} />
            {/each}
        </div>
    </div>
</td>
<td class="text-xs md:text-sm">{request.client}</td>
