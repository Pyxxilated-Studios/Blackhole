<script lang="ts">
    import type { Config } from "../../types";
    import { onMount } from "svelte";

    import { toast } from "@zerodevx/svelte-toast";

    let config: Config;

    const refetch = async () => {
        try {
            const configResponse = await fetch("/api/config");
            if (configResponse.ok) {
                config = await configResponse.json();
            } else {
                toast.push((await configResponse.json()).reason, {
                    classes: ["error"],
                });
            }
        } catch (err: unknown) {
            toast.push(String(err), {
                classes: ["error"],
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
                return filter.name.length > 0 && filter.url.length > 0;
            });

            let response = await fetch("/api/config", {
                method: "POST",
                body: JSON.stringify(config),
            });

            if (response.ok) {
                toast.push("Updated Config", {
                    classes: ["success"],
                });
            } else {
                toast.push((await response.json()).reason, {
                    classes: ["error"],
                });
            }
        } catch (err: unknown) {
            toast.push(String(err), {
                classes: ["error"],
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
