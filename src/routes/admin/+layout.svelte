<script lang="ts">
	import { page } from '$app/state';
	let { children } = $props();
	const path = $derived(page.url.pathname);
	const tab = (href: string) => (path === href || path.startsWith(href + '/') ? 'active' : '');
</script>

<nav class="tabs">
	<a href="/admin" class={tab('/admin')}>Overview</a>
	<a href="/admin/requests" class={tab('/admin/requests')}>Requests</a>
	<a href="/admin/users" class={tab('/admin/users')}>Users</a>
	<a href="/admin/services" class={tab('/admin/services')}>Services</a>
</nav>

<section>
	{@render children()}
</section>

<style>
	.tabs {
		display: flex;
		gap: 0.25rem;
		border-bottom: 1px solid #23262d;
		margin-bottom: 1.25rem;
	}
	.tabs a {
		padding: 0.5rem 0.9rem;
		color: #9aa4af;
		text-decoration: none;
		border-bottom: 2px solid transparent;
		margin-bottom: -1px;
	}
	.tabs a.active {
		color: #e6e8eb;
		border-bottom-color: #7cb7ff;
	}
	:global(.admin-table) {
		width: 100%;
		border-collapse: collapse;
	}
	:global(.admin-table th),
	:global(.admin-table td) {
		padding: 0.5rem 0.6rem;
		border-bottom: 1px solid #23262d;
		text-align: left;
		vertical-align: middle;
		font-size: 0.9rem;
	}
	:global(.admin-table th) {
		color: #9aa4af;
		font-weight: 500;
	}
	:global(.pill) {
		display: inline-block;
		padding: 0.05rem 0.5rem;
		border-radius: 999px;
		font-size: 0.7rem;
		background: #2a3342;
	}
	:global(.pill.warn) {
		background: #5a3a1a;
	}
	:global(.pill.bad) {
		background: #5a1a1a;
	}
	:global(.pill.good) {
		background: #1a4a2a;
	}
	:global(.btn) {
		background: transparent;
		color: #e6e8eb;
		border: 1px solid #2a2e36;
		padding: 0.3rem 0.6rem;
		border-radius: 6px;
		cursor: pointer;
		font-size: 0.85rem;
	}
	:global(.btn:hover) {
		background: #1a1d22;
	}
	:global(.btn.danger) {
		border-color: #5a1a1a;
		color: #ffbdbd;
	}
	:global(.btn.primary) {
		border-color: #1a4a6a;
		color: #a9d3ff;
	}
	:global(.row-actions) {
		display: inline-flex;
		gap: 0.35rem;
	}
</style>
