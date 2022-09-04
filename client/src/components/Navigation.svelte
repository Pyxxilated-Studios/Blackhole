<header>
	<nav>
		<a href="/" class="title"> Blackhole </a>

		<div>
			<a href="/about/"> About </a>
			<a href="/blog/"> Blog </a>
			<a href="/projects/"> Projects </a>
		</div>
	</nav>
</header>

<style>
	header {
		width: 100%;
		position: sticky;
		padding: 1rem;
		margin-left: auto;
		margin-right: auto;
		z-index: 50;
		top: 0;
	}

	header nav {
		display: flex;
		justify-content: space-between;
		align-items: center;
		margin-left: 0.75rem;
		margin-right: 0.75rem;
	}

	header nav a {
		color: #ffcdb2;
		text-decoration: none;
		transition-property: background-color, border-color, color, fill, stroke;
		transition-timing-function: cubic-bezier(0.4, 0, 0.2, 1);
		transition-duration: 0.3s;
	}

	header nav a:hover {
		color: #b5838d;
	}

	header nav div {
		display: flex;
		flex-direction: row-reverse;
		justify-content: space-between;
	}

	header nav div :not([hidden]) ~ :not([hidden]) {
		margin-right: 1rem;
	}

	.title {
		font-size: 1.5rem;
	}
</style>
