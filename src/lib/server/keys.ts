import { generateKeyPair, exportJWK, importJWK, type JWK, type KeyLike } from 'jose';
import { encodeBase32LowerCaseNoPadding } from '@oslojs/encoding';
import { db, schema } from './db';
import { isNull } from 'drizzle-orm';

const ALG = 'RS256';

function newKid(): string {
	const bytes = new Uint8Array(12);
	crypto.getRandomValues(bytes);
	return encodeBase32LowerCaseNoPadding(bytes);
}

/** Get the active signing key, generating one on first use. */
export async function getActiveSigningKey(): Promise<{
	kid: string;
	alg: string;
	privateKey: KeyLike;
}> {
	const active = await db
		.select()
		.from(schema.signingKeys)
		.where(isNull(schema.signingKeys.retiredAt))
		.get();

	if (active) {
		const privateKey = (await importJWK(active.privateJwk as JWK, ALG)) as KeyLike;
		return { kid: active.kid, alg: active.alg, privateKey };
	}

	// Generate + persist a fresh keypair.
	const { publicKey, privateKey } = await generateKeyPair(ALG, { extractable: true });
	const [publicJwk, privateJwk] = await Promise.all([exportJWK(publicKey), exportJWK(privateKey)]);
	const kid = newKid();
	publicJwk.kid = kid;
	publicJwk.alg = ALG;
	publicJwk.use = 'sig';
	privateJwk.kid = kid;
	privateJwk.alg = ALG;

	await db.insert(schema.signingKeys).values({
		kid,
		alg: ALG,
		publicJwk: publicJwk as never,
		privateJwk: privateJwk as never
	});

	return { kid, alg: ALG, privateKey };
}

/** Public JWKS (all non-retired public keys). */
export async function getPublicJwks(): Promise<{ keys: JWK[] }> {
	const rows = await db
		.select()
		.from(schema.signingKeys)
		.where(isNull(schema.signingKeys.retiredAt))
		.all();
	return { keys: rows.map((r) => r.publicJwk as JWK) };
}
