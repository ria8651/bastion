<script lang="ts">
	import { enhance } from '$app/forms';
	let { data, form } = $props();

	let editingId = $state<number | null>(null);
	const editing = $derived(data.services.find((s) => s.id === editingId) ?? null);
</script>

<h1>Services</h1>

{#if form?.error}
	<div class="err">{form.error}</div>
{/if}

<table class="admin-table">
	<thead>
		<tr>
			<th>Slug</th>
			<th>Name</th>
			<th>Return URL prefix</th>
			<th>Users</th>
			<th></th>
		</tr>
	</thead>
	<tbody>
		{#each data.services as s (s.id)}
			<tr>
				<td><code>{s.slug}</code></td>
				<td>{s.name}</td>
				<td style="color:#9aa4af"><code>{s.returnUrlPrefix}</code></td>
				<td>{s.userCount}</td>
				<td class="row-actions">
					<button class="btn" type="button" onclick={() => (editingId = s.id)}>Edit</button>
					<form
						method="POST"
						action="?/remove"
						use:enhance={({ cancel }) => {
							if (!confirm(`Remove ${s.slug}? Revokes ${s.userCount} grant(s).`)) {
								cancel();
							}
						}}
					>
						<input type="hidden" name="id" value={s.id} />
						<button class="btn danger" type="submit">Remove</button>
					</form>
				</td>
			</tr>
		{/each}
	</tbody>
</table>

{#if editing}
	<section class="panel">
		<h2>Edit <code>{editing.slug}</code></h2>
		<form
			method="POST"
			action="?/update"
			use:enhance={() => {
				return async ({ update }) => {
					await update();
					editingId = null;
				};
			}}
			class="form-grid"
		>
			<input type="hidden" name="id" value={editing.id} />
			<label>
				Slug
				<input name="slug" value={editing.slug} required pattern="[a-z0-9\-]+" />
			</label>
			<label>
				Display name
				<input name="name" value={editing.name} />
			</label>
			<label class="wide">
				Return URL prefix
				<input name="returnUrlPrefix" value={editing.returnUrlPrefix} required type="url" />
			</label>
			<div class="wide row-actions">
				<button class="btn primary" type="submit">Save</button>
				<button class="btn" type="button" onclick={() => (editingId = null)}>Cancel</button>
			</div>
		</form>
	</section>
{/if}

<section class="panel">
	<h2>Add service</h2>
	<form method="POST" action="?/add" use:enhance class="form-grid">
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
			<input name="returnUrlPrefix" placeholder="http://localhost:5173" required type="url" />
		</label>
		<button class="btn primary wide" type="submit">Add</button>
	</form>
</section>

<style>
	.panel {
		margin-top: 1.5rem;
		border: 1px solid #23262d;
		border-radius: 8px;
		padding: 1rem 1.25rem;
		max-width: 560px;
	}
	.panel h2 {
		margin-top: 0;
	}
	.form-grid {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 0.75rem;
	}
	.form-grid .wide {
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
		padding: 0.4rem 0.55rem;
		font-size: 0.9rem;
		width: 100%;
		box-sizing: border-box;
	}
	input:focus {
		outline: none;
		border-color: #7cb7ff;
	}
	.err {
		background: #3a1515;
		color: #ffc2c2;
		border: 1px solid #5a2020;
		padding: 0.5rem 0.75rem;
		border-radius: 6px;
		margin-bottom: 1rem;
	}
</style>
