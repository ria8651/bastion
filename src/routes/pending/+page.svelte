<script lang="ts">
	import { page } from '$app/state';
	let { data } = $props();
	const service = $derived(page.url.searchParams.get('service'));
</script>

<h1>Awaiting approval</h1>

{#if data.user}
	<p>
		Hey <strong>{data.user.username}</strong> — your account has been created but isn't active yet.
	</p>

	{#if service}
		<p>
			A request for access to <strong>{service}</strong> has been logged. An admin will review it.
		</p>
	{:else}
		<p>An admin will review and grant access to one or more services.</p>
	{/if}

	<form method="POST" action="/auth/logout">
		<button type="submit">Sign out</button>
	</form>
{:else}
	<p><a href="/auth/login">Sign in</a></p>
{/if}
