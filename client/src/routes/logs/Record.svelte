<script lang="ts">
    export let ty: string;
    export let record: Record<string, Record<string, unknown>>;
</script>

<p>
    {ty}:
    {#if ty === "MX"}
        {record.host} Priority: {record.priority}
    {:else if ty === "TXT"}
        {record.data}
    {:else if ty === "A" || ty === "AAAA"}
        {record.addr}
    {:else if ty === "CNAME"}
        {record.data}
    {/if}
    (ttl={record.record.ttl})
</p>
