<script lang="ts">
    import type { Config } from "../../types";
    import { onMount } from "svelte";

    import { getNotificationsContext } from "svelte-notifications";
    const { addNotification } = getNotificationsContext();

    let config: Config;

    const refetch = async () => {
        try {
            const configResponse = await fetch("/api/config");
            if (configResponse.ok) {
                config = await configResponse.json();
            } else {
                addNotification({
                    type: "error",
                    text: (await configResponse.json()).reason,
                    removeAfter: 3000,
                    position: "bottom-center",
                });
            }
        } catch (err: unknown) {
            addNotification({
                type: "error",
                text: err,
                removeAfter: 3000,
                position: "bottom-center",
            });
        }
    };

    const update = async () => {
        try {
            let response = await fetch("/api/config", {
                method: "POST",
                body: JSON.stringify(config),
            });

            if (response.ok) {
                addNotification({
                    type: "success",
                    text: "Updated Config",
                    removeAfter: 3000,
                    position: "bottom-center",
                });
            } else {
                addNotification({
                    type: "error",
                    text: (await response.json()).reason,
                    removeAfter: 3000,
                    position: "bottom-center",
                });
            }
        } catch (err: unknown) {
            addNotification({
                type: "error",
                text: err,
                removeAfter: 3000,
                position: "bottom-center",
            });
        }
    };

    onMount(refetch);
</script>

<svelte:head>
    <title>Blackhole: Config</title>
</svelte:head>

<div class="flex flex-row">
    <h2 class="basis-5/6">Config:</h2>

    <button class="btn basis-1/6 mt-14" on:click={refetch}>Refresh</button>
</div>
{#if config}
    <h3>Filters</h3>

    {#each config.filter as filter}
        <div class="grid grid-cols-2 gap-4 my-4" id={filter.name + filter.url}>
            <p>{filter.name}</p>
            <p>{filter.url}</p>
        </div>
    {/each}

    <h3>Schedules</h3>
    {#each config.schedule as schedule}
        <div class="grid grid-cols-2" id={schedule.name}>
            <p>For: {schedule.name}</p>
            <p>Timer: {schedule.schedule}</p>
        </div>
    {/each}

    <button class="btn float-right" on:click={update}>Update</button>
{/if}
