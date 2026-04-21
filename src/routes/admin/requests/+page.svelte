<script lang="ts">
	import { enhance } from '$app/forms';
	let { data } = $props();
</script>

<h1>Access requests</h1>

<h2>Pending <span class="pill warn">{data.pending.length}</span></h2>

{#if data.pending.length === 0}
	<p style="color:#9aa4af">None.</p>
{:else}
	<table class="admin-table">
		<thead>
			<tr>
				<th>User</th>
				<th>Service</th>
				<th>Requested</th>
				<th>Note</th>
				<th></th>
			</tr>
		</thead>
		<tbody>
			{#each data.pending as row (row.req.id)}
				<tr>
					<td>
						{#if row.user}
							<a href="/admin/users/{row.user.id}">{row.user.login}</a>
						{:else}
							—
						{/if}
					</td>
					<td>{row.service?.slug ?? '—'}</td>
					<td style="color:#9aa4af">{row.req.requestedAt.toLocaleString()}</td>
					<td style="color:#9aa4af">{row.req.note ?? ''}</td>
					<td class="row-actions">
						<form method="POST" action="?/approve" use:enhance>
							<input type="hidden" name="id" value={row.req.id} />
							<button class="btn primary" type="submit">Approve</button>
						</form>
						<form method="POST" action="?/deny" use:enhance>
							<input type="hidden" name="id" value={row.req.id} />
							<button class="btn danger" type="submit">Deny</button>
						</form>
					</td>
				</tr>
			{/each}
		</tbody>
	</table>
{/if}

<h2>Recently resolved</h2>

{#if data.resolved.length === 0}
	<p style="color:#9aa4af">None.</p>
{:else}
	<table class="admin-table">
		<thead>
			<tr>
				<th>User</th>
				<th>Service</th>
				<th>Decision</th>
				<th>Resolved</th>
			</tr>
		</thead>
		<tbody>
			{#each data.resolved as row (row.req.id)}
				<tr>
					<td>{row.user?.login ?? '—'}</td>
					<td>{row.service?.slug ?? '—'}</td>
					<td>
						<span class="pill {row.req.decision === 'approved' ? 'good' : 'bad'}"
							>{row.req.decision}</span
						>
					</td>
					<td style="color:#9aa4af">{row.req.resolvedAt?.toLocaleString() ?? ''}</td>
				</tr>
			{/each}
		</tbody>
	</table>
{/if}
