import { SignJWT } from 'jose';
import { createHash } from 'node:crypto';
import { getActiveSigningKey } from './keys';

export type ServiceTokenClaims = {
	sub: string; // stable identity hash — see identityHash()
	username: string; // bastion-owned, user-editable display name
	svc: string;
	perms?: string[]; // per-service permission keys (phase 4)
};

const TOKEN_TTL_SECONDS = 15 * 60;

/**
 * Stable-across-wipe user identifier. Hashes the first auth provider + its
 * user id — so if bastion's DB is wiped and the same human signs back in with
 * the same provider, consumer apps see the same `sub` and re-associate data
 * correctly. Adding a second provider later doesn't affect `sub`: only the
 * primary identity is hashed.
 *
 * Unsalted on purpose. The hash is a public identifier (it's in JWTs handed
 * to consumer apps), and we want it deterministic across bastion instances
 * with no shared secret required. Input is also already opaque (GitHub's
 * numeric user id) so there's nothing to protect by salting.
 */
export function identityHash(provider: string, providerUserId: string | number): string {
	return createHash('sha256').update(`${provider}:${providerUserId}`).digest('base64url');
}

export async function issueServiceToken(args: {
	issuer: string;
	userId: number; // bastion's internal user.id — for bastion-internal lookups only
	primaryIdentity: { provider: string; providerUserId: string | number };
	username: string;
	service: string;
	perms?: string[];
}): Promise<{ jwt: string; expiresAt: Date }> {
	const { kid, alg, privateKey } = await getActiveSigningKey();
	const now = Math.floor(Date.now() / 1000);
	const exp = now + TOKEN_TTL_SECONDS;
	const sub = identityHash(args.primaryIdentity.provider, args.primaryIdentity.providerUserId);
	const jwt = await new SignJWT({
		username: args.username,
		svc: args.service,
		perms: args.perms ?? [],
		// Non-standard claim: the bastion-internal integer id. Consumers should
		// treat `sub` as the portable identity; this is for bastion's own
		// introspect endpoint to find the user row without a hash lookup.
		bastion_uid: args.userId
	})
		.setProtectedHeader({ alg, kid, typ: 'JWT' })
		.setIssuer(args.issuer)
		.setAudience(args.service)
		.setSubject(sub)
		.setIssuedAt(now)
		.setExpirationTime(exp)
		.setJti(crypto.randomUUID())
		.sign(privateKey);
	return { jwt, expiresAt: new Date(exp * 1000) };
}
