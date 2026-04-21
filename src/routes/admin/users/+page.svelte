<script lang="ts">
	import { enhance } from '$app/forms';
	let { data } = $props();

	const statusClass = (s: string) => (s === 'active' ? 'good' : s === 'pending' ? 'warn' : 'bad');
</script>

<h1>Users</h1>

<table class="admin-table">
	<thead>
		<tr>
			<th></th>
			<th>Login</th>
			<th>Email</th>
			<th>Status</th>
			<th>Admin</th>
			<th>Last login</th>
			<th>Actions</th>
		</tr>
	</thead>
	<tbody>
		{#each data.users as u (u.id)}
			<tr>
				<td>
					{#if u.avatar}<img src={u.avatar} alt="" width="24" height="24" style="border-radius:50%" />{/if}
				</td>
				<td>
					<a href="/admin/users/{u.id}">{u.login}</a>
				</td>
				<td style="color:#9aa4af">{u.email ?? '—'}</td>
				<td><span class="pill {statusClass(u.status)}">{u.status}</span></td>
				<td>{u.isAdmin ? '✓' : ''}</td>
				<td style="color:#9aa4af">{u.lastLoginAt ? u.lastLoginAt.toLocaleString() : '—'}</td>
				<td class="row-actions">
					{#if u.status !== 'active'}
						<form method="POST" action="?/setStatus" use:enhance>
							<input type="hidden" name="id" value={u.id} />
							<input type="hidden" name="status" value="active" />
							<button class="btn primary" type="submit">Approve</button>
						</form>
					{/if}
					{#if u.status !== 'denied'}
						<form method="POST" action="?/setStatus" use:enhance>
							<input type="hidden" name="id" value={u.id} />
							<input type="hidden" name="status" value="denied" />
							<button class="btn danger" type="submit">Deny</button>
						</form>
					{/if}
				</td>
			</tr>
		{/each}
	</tbody>
</table>
