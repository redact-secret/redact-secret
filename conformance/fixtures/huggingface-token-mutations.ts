/**
 * Deterministic reproducer for the `huggingface-token-exact-length`
 * grammar-mutation family declared in `synchronous-corpus.json`
 * (`mutation.grammar === "huggingface-token-exact-length"`, `mutation.seedId
 * === HUGGINGFACE_TOKEN_EXACT_LENGTH_SEED_ID`), issue #372.
 *
 * Like `docker-token-mutations.ts`, this module does not generate the
 * corpus: `fixtures/synchronous-corpus.json` stays the independently
 * authored, hand-maintained canonical source. It only proves that the
 * `mutation` provenance recorded there is real — the same seed reproduces the
 * exact same `input` bytes every time — and `schema.test.ts` checks that
 * reproduction against the committed fixtures.
 *
 * The distinguishing properties under test are the reviewed Hugging Face
 * user-access-token contract frozen by issue #367
 * (`docs/audits/evidence/367/precision-contracts.json`,
 * `families.huggingface-token`): `hf_` followed by exactly 34 bytes, and a
 * body alphabet resolved from the two tools' disagreement as the support-
 * policy union `[A-Za-z0-9]` rather than either tool's narrower reading —
 * gitleaks 8.30.1 accepts letters only, trufflehog 3.97.4 accepts letters and
 * digits, and both agree the body excludes `_`/`-`. `BODY` itself is
 * letters-only so the `identity` case sits on the letters-only intersection
 * both tools agree the reviewed positive uses; `digit-bearing` separately
 * exercises the union the default rule accepts as a support-policy choice
 * (unscored, T0-pending in the benchmark corpus, but a real accepted match
 * here). Every mutation below changes exactly one structural property of the
 * identity case, so silence (or the identity match) follows from
 * construction.
 *
 * Issue #485 adopts the `api_org_` (organization-token) prefix into the same
 * family, re-tiering it from T0 to T2
 * (`docs/audits/evidence/367/precision-contracts.json`,
 * `families.huggingface-token`): gitleaks 8.30.1 registers `api_org_` as its
 * own letters-only rule and trufflehog 3.97.4 matches it under the same
 * `(?:hf_|api_org_)[a-zA-Z0-9]{34}` rule it uses for `hf_` — the identical
 * dual-tool 34-byte-exact-length agreement `hf_` itself was tiered on.
 * `organization-token-prefix` is `api_org_`'s paired positive (the same body
 * as the identity case, just under the organization prefix) and
 * `organization-token-one-short` is its paired negative twin, reproducing
 * the same one-byte-short must-not-flag case `one-short` already proves for
 * `hf_`. Both are appended after the existing operations so no previously
 * committed fixture's `mutation.ordinal` shifts.
 *
 * The base literal is an unmistakably synthetic, revoked-shaped value: never
 * a real or real-looking credential.
 */

export const HUGGINGFACE_TOKEN_EXACT_LENGTH_SEED_ID =
  "huggingface-token-exact-length-synthetic-seed";

const PREFIX = "hf_";
/** Issue #485: the organization-token namespace, sharing the same reviewed body shape. */
const ORGANIZATION_PREFIX = "api_org_";
/** Exactly the 34-byte, letters-only body the reviewed contract's identity case carries. */
const BODY = "SyntheticRevokedHuggingFaceTokenAB";
/** The fixed byte (inside `Hugging`) the `invalid-alphabet`, `underscore-in-body`,
 * and `dash-in-body` operations mutate. */
const MUTATED_INDEX = 17;
/** The fixed two bytes (`Sy`) the `digit-bearing` operation replaces with digits. */
const DIGIT_INDEX = 0;

if (BODY.length !== 34) {
  throw new Error("huggingface-token-exact-length base literal drifted from the reviewed contract");
}
if (!/^[A-Za-z]+$/.test(BODY)) {
  throw new Error("huggingface-token-exact-length base literal is no longer letters-only");
}

export interface HuggingFaceTokenMutationCase {
  readonly operation: string;
  readonly ordinal: number;
  readonly input: string;
}

/**
 * The ordered, deterministic mutation set this seed produces. Order is
 * significant: `ordinal` is each case's index here, matching the corpus
 * fixtures' `mutation.ordinal`.
 */
export function generateHuggingFaceTokenMutations(): readonly HuggingFaceTokenMutationCase[] {
  const operations: readonly (readonly [string, string])[] = [
    ["identity", PREFIX + BODY],
    ["one-short", PREFIX + BODY.slice(0, -1)],
    ["one-long", `${PREFIX}${BODY}C`],
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
    [
      "digit-bearing",
      PREFIX + "42" + BODY.slice(DIGIT_INDEX + 2),
    ],
    ["organization-token-prefix", ORGANIZATION_PREFIX + BODY],
    ["organization-token-one-short", ORGANIZATION_PREFIX + BODY.slice(0, -1)],
  ];

  return operations.map(([operation, input], ordinal) => ({
    operation,
    ordinal,
    input,
  }));
}
