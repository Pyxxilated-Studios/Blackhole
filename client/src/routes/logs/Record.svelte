<script lang="ts">
    import type { Answer } from "../../types";

    export let answer: Answer;
</script>

<p>
    {#each Object.entries(answer.rdata) as [ty, data] (data)}
        {#if data.txt_data}
            {ty}: {new TextDecoder().decode(new Uint8Array(data.txt_data[0]))}
        {:else}
            {ty}: {data}
        {/if}
    {/each}
    (ttl={answer.ttl})
</p>
