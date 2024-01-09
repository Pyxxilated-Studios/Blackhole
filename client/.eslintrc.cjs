module.exports = {
    root: true,
    parser: "@typescript-eslint/parser",
    extends: [
        "eslint:recommended",
        "plugin:@typescript-eslint/recommended",
        "plugin:svelte/recommended",
        "prettier",
    ],
    plugins: ["@typescript-eslint", "svelte"],
    ignorePatterns: ["*.cjs"],
    overrides: [
        {
            files: ["*.svelte"],
            parser: "svelte-eslint-parser",
            // Parse the `<script>` in `.svelte` as TypeScript by adding the following configuration.
            parserOptions: {
                parser: "@typescript-eslint/parser",
            },
        },
    ],
    parserOptions: {
        sourceType: "module",
        ecmaVersion: 2020,
        extraFileExtensions: [".svelte"],
    },
    env: {
        browser: true,
        es2017: true,
        node: true,
    },
};
