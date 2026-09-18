/**
 * Deterministic reproducer for the `linear-token-api-exact-length`
 * grammar-mutation family declared in `synchronous-corpus.json`
 * (`mutation.grammar === "linear-token-api-exact-length"`, `mutation.seedId
 * === LINEAR_TOKEN_API_EXACT_LENGTH_SEED_ID`), issue #374.
 *
 * Like `huggingface-token-mutations.ts`, `docker-token-mutations.ts`, and
 * `cloudflare-token-mutations.ts`, this module does not generate the corpus:
 * `fixtures/synchronous-corpus.json` stays the independently authored,
 * hand-maintained canonical source. It only proves that the `mutation`
 * provenance recorded there is real — the same seed reproduces the exact
 * same `input` bytes every time — and `schema.test.ts` checks that
 * reproduction against the committed fixtures.
 *
 * The distinguishing properties under test are the reviewed Linear API-key
 * contract frozen by issue #367
 * (`docs/audits/evidence/367/precision-contracts.json`,
 * `families.linear-token`): `lin_api_` followed by exactly 40 bytes of
 * `[A-Za-z0-9]`. gitleaks 8.30.1's `linear-api-key` and trufflehog 3.97.4's
 * `linearapi` rules independently pin the body to this exact length, and
 * both agree the body excludes `_`/`-`. The `one-short` case reproduces the
 * beta.4 `linear-token-api-plain-twin` regression exactly: a 39-byte body,
 * one byte short of the documented length. `lin_oauth_` is unaffected by
 * this family — it keeps beta.4's rule unchanged as a separate interim
 * guard (no consulted source documents its grammar) and is exercised by the
 * ordinary, non-mutation-tracked corpus fixtures instead. Every mutation
 * below changes exactly one structural property of the identity case, so
 * silence (or the identity match) follows from construction.
 *
 * The base literal is an unmistakably synthetic, revoked-shaped value: never
 * a real or real-looking credential.
 */

export const LINEAR_TOKEN_API_EXACT_LENGTH_SEED_ID =
  "linear-token-api-exact-length-synthetic-seed";

const PREFIX = "lin_api_";
/** Exactly the 40-byte, alphanumeric body the reviewed contract's identity case carries. */
const BODY = "SyntheticRevokedLinearApiTokenABCDEF0123";
/** The fixed byte (inside `Linear`) the `invalid-alphabet`, `underscore-in-body`,
 * and `dash-in-body` operations mutate. */
const MUTATED_INDEX = 20;

if (BODY.length !== 40) {
  throw new Error("linear-token-api-exact-length base body drifted from the reviewed contract");
}
if (!/^[A-Za-z0-9]+$/.test(BODY)) {
  throw new Error("linear-token-api-exact-length base body is no longer alphanumeric-only");
}

export interface LinearTokenMutationCase {
  readonly operation: string;
  readonly ordinal: number;
  readonly input: string;
}

/**
 * The ordered, deterministic mutation set this seed produces. Order is
 * significant: `ordinal` is each case's index here, matching the corpus
 * fixtures' `mutation.ordinal`.
 */
export function generateLinearTokenMutations(): readonly LinearTokenMutationCase[] {
  const operations: readonly (readonly [string, string])[] = [
    ["identity", PREFIX + BODY],
    ["one-short", PREFIX + BODY.slice(0, -1)],
    ["one-long", `${PREFIX}${BODY}9`],
    [
      "invalid-alphabet",
      PREFIX + BODY.slice(0, MUTATED_INDEX) + "!" + BODY.slice(MUTATED_INDEX + 1),
    ],
    [
      "underscore-in-body",
      PREFIX + BODY.slice(0, MUTATED_INDEX) + "_" + BODY.slice(MUTATED_INDEX + 1),
    ],
    [
      "dash-in-body",
      PREFIX + BODY.slice(0, MUTATED_INDEX) + "-" + BODY.slice(MUTATED_INDEX + 1),
    ],
  ];

  return operations.map(([operation, input], ordinal) => ({
    operation,
    ordinal,
    input,
  }));
}
