<script lang="ts">
	import { enhance } from '$app/forms';
	let { data } = $props();
	const statusClass = (s: string) => (s === 'active' ? 'good' : s === 'pending' ? 'warn' : 'bad');
</script>

<p><a href="/admin/users">← all users</a></p>

<header class="head">
	{#if data.u.avatar}<img src={data.u.avatar} alt="" />{/if}
	<div>
		<h1>{data.u.login}</h1>
		<div style="color:#9aa4af">{data.u.email ?? 'no email'} · github id {data.u.githubId}</div>
		<div style="margin-top:0.3rem">
			<span class="pill {statusClass(data.u.status)}">{data.u.status}</span>
			{#if data.u.isAdmin}<span class="pill good">admin</span>{/if}
		</div>
	</div>
</header>

<h2>Service grants</h2>

{#if data.services.length === 0}
	<p style="color:#9aa4af">No services registered.</p>
{:else}
	<table class="admin-table">
		<thead>
			<tr>
				<th>Service</th>
				<th>Granted</th>
				<th></th>
			</tr>
		</thead>
		<tbody>
			{#each data.services as s (s.id)}
				<tr>
					<td><code>{s.slug}</code></td>
					<td>{s.granted ? '✓' : ''}</td>
					<td>
						<form method="POST" action="?/toggleGrant" use:enhance>
							<input type="hidden" name="userId" value={data.u.id} />
							<input type="hidden" name="serviceId" value={s.id} />
							<input type="hidden" name="grant" value={s.granted ? '0' : '1'} />
							<button class="btn {s.granted ? 'danger' : 'primary'}" type="submit">
								{s.granted ? 'Revoke' : 'Grant'}
							</button>
						</form>
					</td>
				</tr>
			{/each}
		</tbody>
	</table>
{/if}

<h2>Access requests</h2>

{#if data.requests.length === 0}
	<p style="color:#9aa4af">None.</p>
{:else}
	<table class="admin-table">
		<thead>
			<tr>
				<th>Service</th>
				<th>Requested</th>
				<th>Status</th>
				<th>Note</th>
			</tr>
		</thead>
		<tbody>
			{#each data.requests as r (r.req.id)}
				<tr>
					<td>{r.service?.slug ?? '—'}</td>
					<td>{r.req.requestedAt.toLocaleString()}</td>
					<td>
						{#if r.req.resolvedAt}
							<span class="pill {r.req.decision === 'approved' ? 'good' : 'bad'}"
								>{r.req.decision}</span
							>
						{:else}
							<span class="pill warn">pending</span>
						{/if}
					</td>
					<td style="color:#9aa4af">{r.req.note ?? ''}</td>
				</tr>
			{/each}
		</tbody>
	</table>
{/if}

<h2>Sessions</h2>
<div class="sessions">
	<span class="pill">{data.sessionCount} active</span>
	<form method="POST" action="?/revokeSessions" use:enhance>
		<input type="hidden" name="userId" value={data.u.id} />
		<button class="btn danger" type="submit" disabled={data.sessionCount === 0}
			>Revoke all sessions</button
		>
	</form>
</div>

<style>
	.head {
		display: flex;
		gap: 1rem;
		align-items: center;
		margin: 1rem 0;
	}
	.head img {
		width: 56px;
		height: 56px;
		border-radius: 50%;
	}
	h1 {
		margin: 0;
	}
	.sessions {
		display: flex;
		gap: 0.75rem;
		align-items: center;
	}
</style>
