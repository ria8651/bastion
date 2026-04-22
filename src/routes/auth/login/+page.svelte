<script lang="ts">
	let { data } = $props();
</script>

<div class="wrap">
	<h1>Sign in</h1>

	{#if data.claimAdmin}
		<p class="sub">
			You're signing in as the <strong>root admin</strong> of this bastion instance.
		</p>
	{:else if data.service}
		<p class="sub">
			Continue to <strong>{data.service.name}</strong>.
		</p>
	{:else}
		<p class="sub">Continue to bastion.</p>
	{/if}

	<form method="POST" action="?/github">
		{#if data.service}<input type="hidden" name="service" value={data.service.slug} />{/if}
		{#if data.claimAdmin}<input type="hidden" name="claim_admin" value="1" />{/if}
		<button type="submit" class="gh">
			<svg viewBox="0 0 16 16" width="18" height="18" aria-hidden="true">
				<path
					fill="currentColor"
					d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0 0 16 8c0-4.42-3.58-8-8-8Z"
				/>
			</svg>
			Continue with GitHub
		</button>
	</form>
</div>

<style>
	.wrap {
		max-width: 420px;
		margin: 6rem auto 3rem;
		padding: 0 1.25rem;
		text-align: center;
	}
	h1 {
		margin-bottom: 0.4rem;
	}
	.sub {
		color: #9aa4af;
		margin-top: 0;
		margin-bottom: 1.75rem;
	}
	.gh {
		display: inline-flex;
		align-items: center;
		gap: 0.55rem;
		background: #24292e;
		color: #fff;
		border: 1px solid #2f363d;
		padding: 0.65rem 1.1rem;
		border-radius: 8px;
		font-size: 0.95rem;
		cursor: pointer;
	}
	.gh:hover {
		background: #2d333b;
	}
</style>
