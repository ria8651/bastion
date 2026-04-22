import { SignJWT } from 'jose';
import { getActiveSigningKey } from './keys';

export type ServiceTokenClaims = {
	sub: string; // user id as string
	gh_login: string;
	svc: string; // service slug this token is issued for
	perms?: string[]; // per-service permission keys (phase 4)
};

const TOKEN_TTL_SECONDS = 15 * 60;

export async function issueServiceToken(args: {
	issuer: string;
	userId: number;
	login: string;
	service: string;
	perms?: string[];
}): Promise<{ jwt: string; expiresAt: Date }> {
	const { kid, alg, privateKey } = await getActiveSigningKey();
	const now = Math.floor(Date.now() / 1000);
	const exp = now + TOKEN_TTL_SECONDS;
	const jwt = await new SignJWT({
		gh_login: args.login,
		svc: args.service,
		perms: args.perms ?? []
	})
		.setProtectedHeader({ alg, kid, typ: 'JWT' })
		.setIssuer(args.issuer)
		.setAudience(args.service)
		.setSubject(String(args.userId))
		.setIssuedAt(now)
		.setExpirationTime(exp)
		.setJti(crypto.randomUUID())
		.sign(privateKey);
	return { jwt, expiresAt: new Date(exp * 1000) };
}
