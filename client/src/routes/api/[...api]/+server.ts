import type { RequestHandler } from "@sveltejs/kit";

export const GET: RequestHandler = async ({ url }) => {
    return await fetch(`http://192.168.1.195:5000${url.pathname}`, {
        headers: new Headers({
            Accept: "application/json",
            "Content-Type": "application/json",
        }),
    });
};
