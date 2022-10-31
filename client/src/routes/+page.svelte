<script lang="ts">
    import Chart from "svelte-frappe-charts";
    import type { Average, Cache, Requests } from "src/types";
    import { onMount } from "svelte";

    type Data = { labels: string[]; datasets: { values: number[] }[] };

    const MAX_TIME_SERIES = 20;
    const TIME_SERIES = 1000 * 60 * 60;

    let cache: Cache;
    let average: Average;
    let requests: Requests;
    let error: unknown | undefined = undefined;

    let queryTypes: Data = {
        labels: [],
        datasets: [
            {
                values: [],
            },
        ],
    };

    let requestsTimeSeries: Data = {
        labels: [],
        datasets: [
            {
                values: [],
            },
        ],
    };

    let blockedRequestCount = 0;
    let blockedRequests: Data = {
        labels: [],
        datasets: [
            {
                values: [],
            },
        ],
    };

    const byteString = (bytes: number): string => {
        if (bytes < 1000) {
            return `${bytes} B`;
        } else if (bytes < 1000000) {
            return `${(bytes / 1000).toFixed(3)} KB`;
        } else if (bytes < 1000000000) {
            return `${(bytes / 1000000).toFixed(3)} MB`;
        } else {
            return `${(bytes / 1000000000).toFixed(3)} GB`;
        }
    };

    const refetch = async () => {
        try {
            const [cacheResponse, averageResponse, requestsResponse] = await Promise.all([
                fetch("/api/statistics/cache"),
                fetch("/api/statistics/average"),
                fetch("/api/statistics/requests"),
            ]);

            error = undefined;

            if (cacheResponse.ok) {
                cache = (await cacheResponse.json()).Cache;

                error = undefined;
            } else {
                error = cacheResponse.statusText;
            }

            if (averageResponse.ok) {
                average = (await averageResponse.json()).Average;
                error = undefined;
            } else {
                error = averageResponse.statusText;
            }

            if (requestsResponse.ok) {
                requests = (await requestsResponse.json()).Requests;

                let data: Record<string, number> = {};
                let timeSeries: Record<string, number> = {};
                let blockedTimeSeries: Record<string, number> = {};

                blockedRequestCount = 0;

                requests.forEach((request) => {
                    data[request.question.qtype] = (data[request.question.qtype] ?? 0) + 1;

                    let time = new Date(
                        ~~(new Date(request.timestamp).getTime() / TIME_SERIES) * TIME_SERIES
                    ).toLocaleString();

                    if (request.rule?.ty === "Deny") {
                        blockedRequestCount++;
                        blockedTimeSeries[time] = (blockedTimeSeries[time] ?? 0) + 1;
                    }

                    timeSeries[time] = (timeSeries[time] ?? 0) + 1;
                });

                queryTypes.labels = Array.from(Object.keys(data));
                queryTypes.datasets[0].values.length = queryTypes.labels.length;
                queryTypes.labels.forEach((label, idx) => {
                    queryTypes.datasets[0].values[idx] = data[label];
                });

                requestsTimeSeries.labels = Array.from(Object.keys(timeSeries));
                requestsTimeSeries.labels.sort(
                    (a, b) => new Date(a).getTime() - new Date(b).getTime()
                );
                requestsTimeSeries.datasets[0].values.length = requestsTimeSeries.labels.length;
                requestsTimeSeries.labels.forEach((label, idx) => {
                    requestsTimeSeries.datasets[0].values[idx] = timeSeries[label];
                });

                if (requestsTimeSeries.labels.length > MAX_TIME_SERIES) {
                    requestsTimeSeries.labels = requestsTimeSeries.labels.slice(-MAX_TIME_SERIES);
                }

                blockedRequests.labels = Array.from(Object.keys(blockedTimeSeries));
                blockedRequests.labels.sort(
                    (a, b) => new Date(a).getTime() - new Date(b).getTime()
                );
                blockedRequests.datasets[0].values.length = blockedRequests.labels.length;
                blockedRequests.labels.forEach((label, idx) => {
                    blockedRequests.datasets[0].values[idx] = blockedTimeSeries[label];
                });

                if (blockedRequests.labels.length > MAX_TIME_SERIES) {
                    blockedRequests.labels = blockedRequests.labels.slice(-MAX_TIME_SERIES);
                }
            } else {
                error = requestsResponse.statusText;
            }
        } catch (err: unknown) {
            error = err;
        }
    };

    onMount(refetch);
</script>

<svelte:head>
    <title>Blackhole: Statistics</title>
</svelte:head>

{#if error}
    <p>Error: {error}</p>
{:else if cache || requests}
    <div class="flex flex-row">
        <h2 class="basis-5/6">Statistics:</h2>

        <button class="btn basis-1/6 mt-14" on:click={refetch}>Refresh</button>
    </div>

    <div class="stats stats-vertical lg:stats-horizontal w-full">
        {#if cache}
            <div class="stat">
                <div class="stat-title">Cache Size</div>
                <div class="stat-value">{byteString(cache.size)}</div>
            </div>
        {/if}

        {#if average}
            <div class="stat">
                <div class="stat-title">Average Response Time</div>
                <div class="stat-value">{(average.average / 1000000).toFixed(3)} ms</div>
            </div>
        {/if}
    </div>

    <div class="stats stats-vertical lg:stats-horizontal gap-1 w-full">
        <div class="stat">
            <div class="stat-title">Request Count</div>
            <div class="stat-value">{average?.count}</div>
            <div class="stat-desc">
                <Chart
                    data={requestsTimeSeries}
                    title="Requests per Hour"
                    type="line"
                    lineOptions={{ heatline: 1, hideDots: 1, xIsSeries: true }}
                />
            </div>
        </div>

        <div class="stat">
            <div class="stat-title">Blocked Requests</div>
            <div class="stat-value">
                {blockedRequestCount} ({(
                    (blockedRequestCount / (requests?.length ?? 1)) *
                    100
                ).toFixed(2)}%)
            </div>
            <div class="stat-desc">
                <Chart
                    data={blockedRequests}
                    title="Blocked Requests per Hour"
                    type="line"
                    lineOptions={{ heatline: 1, hideDots: 1, xIsSeries: true }}
                />
            </div>
        </div>
    </div>

    <Chart
        data={{
            labels: ["Hits", "Misses"],
            datasets: [
                {
                    values: [cache?.hits ?? 0, cache?.misses ?? 0],
                },
            ],
        }}
        title="Cache Effictiveness"
        type="pie"
    />

    <Chart data={queryTypes} title="Requests by Query Type" type="pie" maxSlices={5} />
{:else}
    <p>Loading ...</p>
{/if}

<style>
    :global(.chart-container .title),
    :global(.chart-container .legend-dataset-text),
    :global(g text) {
        fill: hsla(var(--bc) / var(--tw-text-opacity, 1));
    }
</style>
