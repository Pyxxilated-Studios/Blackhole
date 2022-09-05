import { sveltekit } from '@sveltejs/kit/vite';
import type { UserConfig } from 'vite';

const config: UserConfig = {
	plugins: [sveltekit()],
	optimizeDeps: {
		esbuildOptions: {
			minify: true
		}
	},
	build: {
		rollupOptions: {
			treeshake: 'recommended'
		}
	}
};

export default config;
