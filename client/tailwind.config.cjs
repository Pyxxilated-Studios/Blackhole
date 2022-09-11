module.exports = {
    mode: "jit",
    future: {
        purgeLayersByDefault: true,
        removeDeprecatedGapUtilities: true,
    },
    content: ["./src/**/*.svelte", "./src/**/*.html"],
    theme: {},
    plugins: [require("@tailwindcss/typography"), require("daisyui")],
};
