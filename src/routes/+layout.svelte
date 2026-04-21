<script lang="ts">
	let { data, children } = $props();
</script>

<header class="bar">
	<a href="/" class="brand">bastion</a>
	<nav>
		{#if data.user}
			<span class="who">
				{#if data.user.avatar}<img src={data.user.avatar} alt="" />{/if}
				{data.user.login}
				{#if data.user.isAdmin}<span class="tag">admin</span>{/if}
				{#if data.user.status !== 'active'}<span class="tag warn">{data.user.status}</span>{/if}
			</span>
			{#if data.user.isAdmin}<a href="/admin">admin</a>{/if}
			<form method="POST" action="/auth/logout">
				<button type="submit">log out</button>
			</form>
		{:else}
			<a href="/auth/login">log in with GitHub</a>
		{/if}
	</nav>
</header>

<main>
	{@render children()}
</main>

<style>
	:global(body) {
		font-family:
			ui-sans-serif,
			system-ui,
			-apple-system,
			sans-serif;
		background: #0f1115;
		color: #e6e8eb;
		margin: 0;
	}
	:global(a) {
		color: #7cb7ff;
	}
	.bar {
		display: flex;
		align-items: center;
		justify-content: space-between;
		padding: 0.75rem 1.25rem;
		border-bottom: 1px solid #23262d;
	}
	.brand {
		font-weight: 700;
		text-decoration: none;
		color: #e6e8eb;
	}
	nav {
		display: flex;
		align-items: center;
		gap: 0.75rem;
	}
	.who {
		display: inline-flex;
		align-items: center;
		gap: 0.4rem;
	}
	.who img {
		width: 20px;
		height: 20px;
		border-radius: 50%;
	}
	.tag {
		font-size: 0.7rem;
		padding: 0.05rem 0.4rem;
		border-radius: 999px;
		background: #2a3342;
	}
	.tag.warn {
		background: #5a3a1a;
	}
	button {
		background: transparent;
		color: #e6e8eb;
		border: 1px solid #2a2e36;
		padding: 0.3rem 0.6rem;
		border-radius: 6px;
		cursor: pointer;
	}
	main {
		max-width: 720px;
		margin: 2rem auto;
		padding: 0 1.25rem;
	}
</style>
