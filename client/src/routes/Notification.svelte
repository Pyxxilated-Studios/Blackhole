<script lang="ts">
    import type { DefaultNotificationOptions } from "svelte-notifications";

    export let notification: DefaultNotificationOptions;
    export let onRemove: (notificationId: string) => void;

    const handleButtonClick = () => {
        onRemove(notification.id ?? "");
    };

    let alert = notification.type === "error" ? "alert-error" : "alert-success";
</script>

<div class="flex justify-center">
    <div class={`alert shadow-lg ${alert} z-50 absolute top-4 w-2/12`}>
        {#if notification.type === "success"}
            <svg
                xmlns="http://www.w3.org/2000/svg"
                class="stroke-current flex-shrink-0 h-6 w-6"
                fill="none"
                viewBox="0 0 24 24"
            >
                <path
                    stroke-linecap="round"
                    stroke-linejoin="round"
                    stroke-width="2"
                    d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"
                />
            </svg>
        {:else}
            <svg
                xmlns="http://www.w3.org/2000/svg"
                class="stroke-current flex-shrink-0 h-6 w-6"
                fill="none"
                viewBox="0 0 24 24"
            >
                <path
                    stroke-linecap="round"
                    stroke-linejoin="round"
                    stroke-width="2"
                    d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z"
                />
            </svg>
        {/if}
        <span>{notification.text}</span>
        <button on:click={handleButtonClick}>x</button>
    </div>
</div>
