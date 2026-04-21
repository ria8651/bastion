<script lang="ts">
	let { data } = $props();
</script>

<h1>bastion</h1>
<p>Central authentication for boom and binkflix.</p>

{#if !data.user}
	<p><a href="/auth/login">Sign in with GitHub</a> to continue.</p>
{:else if data.user.status === 'pending'}
	<p>Your account is awaiting approval. <a href="/pending">See status</a>.</p>
{:else if data.user.status === 'denied'}
	<p>Access denied.</p>
{:else}
	<p>You're signed in as <strong>{data.user.login}</strong>.</p>
	{#if data.user.isAdmin}
		<p><a href="/admin">Open admin panel →</a></p>
	{/if}
{/if}
