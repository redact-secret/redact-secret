/**
 * Deterministic reproducer for the `cloudflare-token-checksum-suffix`
 * grammar-mutation family declared in `synchronous-corpus.json`
 * (`mutation.grammar === "cloudflare-token-checksum-suffix"`, `mutation.seedId
 * === CLOUDFLARE_TOKEN_CHECKSUM_SUFFIX_SEED_ID`), issue #373.
 *
 * Like `huggingface-token-mutations.ts` and `docker-token-mutations.ts`, this
 * module does not generate the corpus: `fixtures/synchronous-corpus.json`
 * stays the independently authored, hand-maintained canonical source. It
 * only proves that the `mutation` provenance recorded there is real — the
 * same seed reproduces the exact same `input` bytes every time — and
 * `schema.test.ts` checks that reproduction against the committed fixtures.
 *
 * The distinguishing properties under test are the reviewed Cloudflare
 * scannable user-token contract frozen by issue #367
 * (`docs/audits/evidence/367/precision-contracts.json`,
 * `families.cloudflare-token`): `cfut_` followed by exactly 40 bytes of
 * `[A-Za-z0-9]` (the body) and then exactly 8 bytes of `[0-9a-f]` (the
 * checksum). The checksum's existence is provider evidence (a bare 40-byte
 * body is malformed); its width and lowercase-hex alphabet are a
 * single-tool-corroborated support-policy adoption, validated lexically
 * only — no checksum algorithm is computed or claimed. The
 * `checksum-non-hex` case below reproduces the beta.4
 * `cloudflare-token-user-plain-twin` regression exactly: an eight-byte
 * alphanumeric tail that is not hexadecimal. Every mutation changes exactly
 * one structural property of the identity case, so silence (or the identity
 * match) follows from construction.
 *
 * Issue #481 adopts the `cfat_` (account-token) prefix into the same family:
 * the provider's token-formats page documents `cfat_` with the identical
 * `[40 characters][checksum]` format cell as `cfut_`, and trufflehog
 * 3.97.4's `cloudflareapitoken` v2 rule (`cf[ua]t_[a-zA-Z0-9]{40}[a-f0-9]{8}`)
 * corroborates the same body and checksum shape for both prefixes.
 * `account-token-prefix` is `cfat_`'s paired positive (the same body and
 * checksum as the identity case, just under the account prefix) and
 * `account-checksum-non-hex` is its paired negative twin, reproducing the
 * same non-hexadecimal eight-byte tail must-not-flag case `checksum-non-hex`
 * already proves for `cfut_`. Both are appended after the existing
 * operations so no previously committed fixture's `mutation.ordinal` shifts.
 *
 * The base literal is an unmistakably synthetic, revoked-shaped value: never
 * a real or real-looking credential.
 */

export const CLOUDFLARE_TOKEN_CHECKSUM_SUFFIX_SEED_ID =
  "cloudflare-token-checksum-suffix-synthetic-seed";

const PREFIX = "cfut_";
/** Issue #481: the account-token namespace, sharing the same reviewed body/checksum shape. */
const ACCOUNT_PREFIX = "cfat_";
/** Exactly the 40-byte, alphanumeric body the reviewed contract's identity case carries. */
const BODY = "SYNTHETICREVOKEDCLOUDFLAREAPITOKENVALUE1";
/** Exactly the 8-byte, lowercase-hex checksum the reviewed contract's identity case carries. */
const CHECKSUM = "deadbeef";
/** The fixed byte (inside `Cloudflare`) the `body-invalid-alphabet` operation mutates. */
const BODY_MUTATED_INDEX = 17;

if (BODY.length !== 40) {
  throw new Error("cloudflare-token-checksum-suffix base body drifted from the reviewed contract");
}
if (!/^[A-Za-z0-9]+$/.test(BODY)) {
  throw new Error("cloudflare-token-checksum-suffix base body is no longer alphanumeric-only");
}
if (CHECKSUM.length !== 8 || !/^[0-9a-f]+$/.test(CHECKSUM)) {
  throw new Error("cloudflare-token-checksum-suffix base checksum drifted from the reviewed contract");
}

export interface CloudflareTokenMutationCase {
  readonly operation: string;
  readonly ordinal: number;
  readonly input: string;
}

/**
 * The ordered, deterministic mutation set this seed produces. Order is
 * significant: `ordinal` is each case's index here, matching the corpus
 * fixtures' `mutation.ordinal`.
 */
export function generateCloudflareTokenMutations(): readonly CloudflareTokenMutationCase[] {
  const operations: readonly (readonly [string, string])[] = [
    ["identity", PREFIX + BODY + CHECKSUM],
    ["body-one-short", PREFIX + BODY.slice(0, -1) + CHECKSUM],
    ["body-one-long", `${PREFIX}${BODY}A${CHECKSUM}`],
    [
      "body-invalid-alphabet",
      PREFIX +
        BODY.slice(0, BODY_MUTATED_INDEX) +
        "_" +
        BODY.slice(BODY_MUTATED_INDEX + 1) +
        CHECKSUM,
    ],
    ["checksum-one-short", PREFIX + BODY + CHECKSUM.slice(0, -1)],
    ["checksum-one-long", `${PREFIX}${BODY}${CHECKSUM}0`],
    ["checksum-non-hex", PREFIX + BODY + "ghijklmn"],
    ["checksum-uppercase-hex", PREFIX + BODY + CHECKSUM.toUpperCase()],
    ["account-token-prefix", ACCOUNT_PREFIX + BODY + CHECKSUM],
    ["account-checksum-non-hex", ACCOUNT_PREFIX + BODY + "ghijklmn"],
  ];

  return operations.map(([operation, input], ordinal) => ({
    operation,
    ordinal,
    input,
  }));
}
