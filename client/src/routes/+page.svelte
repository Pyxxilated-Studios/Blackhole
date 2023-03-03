<script lang="ts">
    import Chart from "svelte-frappe-charts";
    import type { Average, Cache, Requests } from "../types";
    import { onMount } from "svelte";

    import { getNotificationsContext } from "svelte-notifications";
    const { addNotification } = getNotificationsContext();

    type Data = { labels: string[]; datasets: { values: number[] }[] };

    const MAX_TIME_SERIES = 20;
    const TIME_SERIES = 1000 * 60 * 60;

    let cache: Cache;
    let average: Average;
    let requests: Requests;

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
        if (bytes < 1_000) {
            return `${bytes} B`;
        } else if (bytes < 1_000_000) {
            return `${(bytes / 1000).toFixed(3)} KB`;
        } else if (bytes < 1_000_000_000) {
            return `${(bytes / 1_000_000).toFixed(3)} MB`;
        } else {
            return `${(bytes / 1_000_000_000).toFixed(3)} GB`;
        }
    };

    const refetch = async () => {
        try {
            const [cacheResponse, averageResponse, requestsResponse] = await Promise.all([
                fetch("/api/statistics/cache"),
                fetch("/api/statistics/average"),
                fetch("/api/statistics/requests"),
            ]);

            if (cacheResponse.ok) {
                cache = (await cacheResponse.json()).Cache;
            } else {
                addNotification({
                    type: "error",
                    text: (await cacheResponse.json()).reason,
                    removeAfter: 3000,
                    position: "bottom-center",
                });
            }

            if (averageResponse.ok) {
                average = (await averageResponse.json()).Average;
            } else {
                addNotification({
                    type: "error",
                    text: (await averageResponse.json()).reason,
                    removeAfter: 3000,
                    position: "bottom-center",
                });
            }

            if (requestsResponse.ok) {
                requests = (await requestsResponse.json()).Requests;

                if (!requests) return;

                let data: Record<string, number> = {};
                let timeSeries: Record<string, number> = {};
                let blockedTimeSeries: Record<string, number> = {};

                blockedRequestCount = 0;

                requests.forEach((request) => {
                    data[request.answers[0].rr_type] = (data[request.answers[0].rr_type] ?? 0) + 1;

                    let time = new Date(
                        ~~(new Date(request.timestamp.secs_since_epoch).getTime() / TIME_SERIES) *
                            TIME_SERIES
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
                addNotification({
                    type: "error",
                    text: (await requestsResponse.json()).reason,
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
    <title>Blackhole: Statistics</title>
</svelte:head>

<div class="flex flex-row">
    <h2 class="basis-5/6">Statistics:</h2>

    <button class="btn basis-1/6 mt-14" on:click={refetch}>Refresh</button>
</div>
<div class="grid stats stats-vertical md:grid-cols-2 xs:grid-cols-1 lg:stats-horizontal">
    <div class="stat">
        <div class="stat-title">Cache Size</div>
        <div class="stat-value">{byteString(cache?.size ?? 0)}</div>
    </div>

    <div class="stat">
        <div class="stat-title">Average Response Time</div>
        <div class="stat-value">{((average?.average ?? 0) / 1000000).toFixed(3)} ms</div>
    </div>
</div>

<div class="grid stats stats-vertical md:grid-cols-2 xs:grid-cols-1 lg:stats-horizontal">
    <div class="stat">
        <div class="stat-title">Request Count</div>
        <div class="stat-value">{average?.count ?? 0}</div>
        <div class="stat-desc">
            <Chart
                data={requestsTimeSeries}
                title="Requests per Hour"
                type="line"
                lineOptions={{ heatline: 1, hideDots: 1, xIsSeries: true }}
            />
        </div>
    </div>

    <div class="stat flex-1">
        <div class="stat-title">Blocked Requests</div>
        <div class="stat-value">
            {blockedRequestCount} ({((blockedRequestCount / (requests?.length ?? 1)) * 100).toFixed(
                2
            )}%)
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

<div class="grid md:grid-cols-2 xs:grid-cols-1">
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
</div>

<style>
    :global(.chart-container .title),
    :global(.chart-container .legend-dataset-text),
    :global(g text) {
        fill: hsla(var(--bc) / var(--tw-text-opacity, 1));
    }
</style>
