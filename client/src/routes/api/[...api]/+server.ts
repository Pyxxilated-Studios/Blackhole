import type { RequestHandler } from "@sveltejs/kit";

export const GET: RequestHandler = async ({ url }) => {
    return await fetch(`http://127.0.0.1:5000${url.pathname}`, {
        headers: new Headers({
            Accept: "application/json",
            "Content-Type": "application/json",
        }),
    });
};
