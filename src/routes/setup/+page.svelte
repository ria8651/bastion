<script lang="ts">
	import { enhance } from '$app/forms';
	import { page } from '$app/state';
	let { data, form } = $props();

	const callbackUrl = $derived(`${page.url.origin}/auth/callback`);
	const homepageUrl = $derived(page.url.origin);
</script>

<div class="wrap">
	<h1>bastion setup</h1>

	<ol class="steps">
		<li class:done={data.setup.hasGithub} class:active={data.step === 1}>1. GitHub OAuth</li>
		<li class:done={data.setup.hasAdmin} class:active={data.step === 2}>2. Claim admin</li>
		<li class:done={data.setup.hasServices} class:active={data.step === 3}>3. Services</li>
	</ol>

	{#if form?.error}
		<div class="err">{form.error}</div>
	{/if}

	{#if data.step === 1}
		<section class="card">
			<h2>Create a GitHub OAuth app</h2>
			<p>
				Go to <a href="https://github.com/settings/developers" target="_blank" rel="noopener"
					>github.com/settings/developers</a
				> → <strong>New OAuth App</strong>. Use these values:
			</p>
			<dl>
				<dt>Homepage URL</dt>
				<dd><code>{homepageUrl}</code></dd>
				<dt>Authorization callback URL</dt>
				<dd><code>{callbackUrl}</code></dd>
			</dl>
			<p>Paste the generated client id + secret below.</p>

			<form method="POST" action="?/saveGithub" use:enhance class="stack">
				<label>
					Client ID
					<input name="clientId" required autocomplete="off" />
				</label>
				<label>
					Client Secret
					<input name="clientSecret" type="password" required autocomplete="off" />
				</label>
				<button class="btn primary" type="submit">Save and continue</button>
			</form>
		</section>
	{:else if data.step === 2}
		<section class="card">
			<h2>Claim admin account</h2>
			<p>
				Sign in with GitHub — the first user to complete this step becomes the root admin of this
				bastion instance.
			</p>
			{#if data.signedInAs}
				<p style="color:#9aa4af">
					You're currently signed in as <strong>{data.signedInAs.login}</strong> but that account
					doesn't have admin yet (maybe you signed up before completing this step). Sign in again
					below to claim it.
				</p>
			{/if}
			<a class="btn primary" href="/auth/login?claim_admin=1">Sign in with GitHub as admin</a>
		</section>
	{:else}
		<section class="card">
			<h2>Add services</h2>
			<p>
				Register apps that will use bastion for auth. You can add more later from the admin panel.
			</p>

			{#if data.services.length > 0}
				<table class="admin-table">
					<thead>
						<tr>
							<th>Slug</th>
							<th>Return URL prefix</th>
							<th></th>
						</tr>
					</thead>
					<tbody>
						{#each data.services as s (s.id)}
							<tr>
								<td><code>{s.slug}</code></td>
								<td style="color:#9aa4af"><code>{s.returnUrlPrefix}</code></td>
								<td>
									<form method="POST" action="?/removeService" use:enhance>
										<input type="hidden" name="id" value={s.id} />
										<button class="btn danger" type="submit">Remove</button>
									</form>
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
			{/if}

			<form method="POST" action="?/addService" use:enhance class="stack grid">
				<label>
					Slug
					<input name="slug" placeholder="boom" required pattern="[a-z0-9\-]+" />
				</label>
				<label>
					Display name
					<input name="name" placeholder="Boom" />
				</label>
				<label class="wide">
					Return URL prefix
					<input
						name="returnUrlPrefix"
						placeholder="http://localhost:5173"
						required
						type="url"
					/>
				</label>
				<button class="btn primary wide" type="submit">Add service</button>
			</form>

			{#if data.setup.hasServices}
				<form method="POST" action="?/finish" use:enhance style="margin-top:1.5rem">
					<button class="btn primary big" type="submit">Finish setup →</button>
				</form>
			{/if}
		</section>
	{/if}
</div>

<style>
	.wrap {
		max-width: 640px;
		margin: 3rem auto;
		padding: 0 1.25rem;
	}
	.steps {
		display: flex;
		gap: 0.5rem;
		list-style: none;
		padding: 0;
		margin: 0 0 1.5rem;
	}
	.steps li {
		flex: 1;
		padding: 0.5rem 0.75rem;
		border: 1px solid #23262d;
		border-radius: 6px;
		color: #9aa4af;
		font-size: 0.9rem;
	}
	.steps li.done {
		border-color: #1a4a2a;
		color: #8fd6a2;
	}
	.steps li.active {
		border-color: #1a4a6a;
		color: #a9d3ff;
	}
	.card {
		border: 1px solid #23262d;
		border-radius: 8px;
		padding: 1.25rem;
	}
	.stack {
		display: flex;
		flex-direction: column;
		gap: 0.75rem;
	}
	.grid {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 0.75rem;
	}
	.grid .wide {
		grid-column: 1 / -1;
	}
	label {
		display: flex;
		flex-direction: column;
		gap: 0.25rem;
		font-size: 0.85rem;
		color: #9aa4af;
	}
	input {
		background: #0f1115;
		border: 1px solid #2a2e36;
		border-radius: 6px;
		color: #e6e8eb;
		padding: 0.5rem 0.6rem;
		font-size: 0.95rem;
	}
	input:focus {
		outline: none;
		border-color: #7cb7ff;
	}
	dl {
		background: #15181e;
		padding: 0.75rem 1rem;
		border-radius: 6px;
		margin: 1rem 0;
	}
	dt {
		color: #9aa4af;
		font-size: 0.8rem;
		margin-top: 0.4rem;
	}
	dt:first-child {
		margin-top: 0;
	}
	dd {
		margin: 0.15rem 0 0;
	}
	code {
		background: #0b0d11;
		padding: 0.1rem 0.35rem;
		border-radius: 4px;
	}
	.btn.big {
		padding: 0.55rem 1rem;
		font-size: 1rem;
	}
	.err {
		background: #3a1515;
		color: #ffc2c2;
		border: 1px solid #5a2020;
		padding: 0.6rem 0.8rem;
		border-radius: 6px;
		margin-bottom: 1rem;
	}
</style>
