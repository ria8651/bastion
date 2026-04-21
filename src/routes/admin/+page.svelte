<script lang="ts">
	let { data } = $props();
</script>

<h1>Admin</h1>

<div class="grid">
	<a class="card" href="/admin/requests">
		<div class="big">{data.counts.pendingRequests}</div>
		<div>Pending requests</div>
	</a>
	<a class="card" href="/admin/users">
		<div class="big">{data.counts.pendingUsers}</div>
		<div>Pending users</div>
	</a>
	<a class="card" href="/admin/users">
		<div class="big">{data.counts.users}</div>
		<div>Total users</div>
	</a>
	<a class="card" href="/admin/services">
		<div class="big">{data.counts.services}</div>
		<div>Services</div>
	</a>
</div>

<h2>Recent activity</h2>

{#if data.recentAudit.length === 0}
	<p style="color:#9aa4af">Nothing yet.</p>
{:else}
	<table class="admin-table">
		<thead>
			<tr>
				<th>When</th>
				<th>Actor</th>
				<th>Action</th>
				<th>Target</th>
				<th>Meta</th>
			</tr>
		</thead>
		<tbody>
			{#each data.recentAudit as row (row.id)}
				<tr>
					<td>{row.at.toLocaleString()}</td>
					<td>{row.actorId ?? '—'}</td>
					<td><code>{row.action}</code></td>
					<td>{row.target ?? '—'}</td>
					<td><code>{row.meta ? JSON.stringify(row.meta) : ''}</code></td>
				</tr>
			{/each}
		</tbody>
	</table>
{/if}

<style>
	.grid {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
		gap: 0.75rem;
		margin-bottom: 1.5rem;
	}
	.card {
		display: block;
		padding: 1rem;
		border: 1px solid #23262d;
		border-radius: 8px;
		color: #e6e8eb;
		text-decoration: none;
	}
	.card:hover {
		border-color: #3a3f48;
	}
	.big {
		font-size: 1.8rem;
		font-weight: 700;
	}
	code {
		font-size: 0.8rem;
	}
</style>
