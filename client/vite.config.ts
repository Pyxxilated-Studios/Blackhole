import { sveltekit } from '@sveltejs/kit/vite';
import type { UserConfig } from 'vite';
import { uglify } from 'rollup-plugin-uglify';

const config: UserConfig = {
	plugins: [sveltekit()],
	optimizeDeps: {
		esbuildOptions: {
			minify: true
		}
	},
	build: {
		rollupOptions: {
			treeshake: 'recommended',
			plugins: [uglify()]
		}
	}
};

export default config;
