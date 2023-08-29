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
            config.upstream = config.upstream.map(({ ip, port }) => ({
                ip,
                port: Number.parseInt(port.toString()),
            }));

            config.filter = config.filter.filter((filter) => {
                filter.name !== "" && filter.url !== "";
            });

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

    <div class="overflow-x-auto">
        <table class="table w-full">
            <!-- head -->
            <thead>
                <tr>
                    <th>List</th>
                    <th>URL</th>
                    <th>Enabled</th>
                </tr>
            </thead>
            <tbody>
                {#each config.filter as filter (filter.name + " " + filter.url)}
                    <tr>
                        <td>
                            <input
                                type="text"
                                placeholder="Filter Name"
                                class="input w-full max-w-xs input-bordered input-primary"
                                bind:value={filter.name}
                            />
                        </td>
                        <td>
                            <input
                                type="text"
                                placeholder="Filter URL"
                                class="input w-full max-w-xs input-bordered input-primary"
                                bind:value={filter.url}
                            />
                        </td>
                        <td>
                            <input type="checkbox" bind:checked={filter.enabled} class="checkbox" />
                        </td>
                    </tr>
                {/each}
            </tbody>
        </table>
    </div>

    <button
        class="btn float-right"
        on:click={() => {
            config.filter = [
                ...config.filter,
                {
                    name: "",
                    url: "",
                    enabled: true,
                },
            ];
        }}>Add Filter</button
    >

    <h3>Upstreams</h3>

    <div class="overflow-x-auto">
        <table class="table w-full">
            <!-- head -->
            <thead>
                <tr>
                    <th>Upstream</th>
                    <th>Port</th>
                </tr>
            </thead>
            <tbody>
                {#each config.upstream as upstream (upstream.ip + " " + upstream.port)}
                    <tr>
                        <td>
                            <input
                                type="text"
                                placeholder="IP"
                                class="input w-full max-w-xs input-bordered input-primary"
                                bind:value={upstream.ip}
                            />
                        </td>
                        <td>
                            <input
                                type="text"
                                placeholder="Port"
                                class="input w-full max-w-xs input-bordered input-primary"
                                bind:value={upstream.port}
                            />
                        </td>
                    </tr>
                {/each}
            </tbody>
        </table>
    </div>

    <h3>Schedules</h3>
    {#each config.schedule as schedule (schedule.name)}
        <div class="grid grid-cols-2" id={schedule.name}>
            <p>{schedule.name}</p>
            <input
                type="text"
                placeholder="Interval"
                class="input w-full max-w-xs input-bordered input-primary"
                bind:value={schedule.schedule}
            />
        </div>
    {/each}

    <button class="btn float-right" on:click={update}>Update</button>
{/if}
