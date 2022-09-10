<nav class="navbar bg-base-300 px-4 sticky top-0 z-30">
	<div class="flex-1">
		<a
			href="/"
			class="text-primary text-xl hover:text-secondary transition-colors duration-300 text-lg md:text-3xl"
		>
			Blackhole
		</a>
	</div>

	<div class="flex-none">
		<ul class="menu menu-horizontal p-0 text-l md:text-xl">
			<li>
				<a href="/config/" class="hover:text-secondary transition-colors duration-300">
					Configuration
				</a>
			</li>
			<li>
				<a href="/stats/" class="hover:text-secondary transition-colors duration-300">Statistics</a>
			</li>
			<li>
				<a href="/logs/" class="hover:text-secondary transition-colors duration-300">Logs</a>
			</li>
		</ul>
	</div>
</nav>

<main class="w-full mx-auto prose-xl pb-12 px-8">
	<slot />
</main>

<footer class="footer z-50 w-full footer-center space-x-4 p-4 bg-base-300 fixed bottom-0">
	<a href="https://www.github.com/pyxxil/blackhole">
		<svg
			aria-label="Github"
			xmlns="http://www.w3.org/2000/svg"
			class="stroke-accent fill-base-300 hover:fill-accent stroke-2 h-8 w-8 transition-all duration-300 hover:scale-125"
		>
			<path
				d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22"
			/>
		</svg>
	</a>
</footer>

<style global lang="postcss">
	@tailwind base;
	@tailwind components;
	@tailwind utilities;
</style>
