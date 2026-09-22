/**
 * Deterministic reproducer for the `docker-token-exact-length`
 * grammar-mutation family declared in `synchronous-corpus.json`
 * (`mutation.grammar === "docker-token-exact-length"`, `mutation.seedId ===
 * DOCKER_TOKEN_EXACT_LENGTH_SEED_ID`), issue #370.
 *
 * Like `github-classic-mutations.ts`, this module does not generate the
 * corpus: `fixtures/synchronous-corpus.json` stays the independently
 * authored, hand-maintained canonical source. It only proves that the
 * `mutation` provenance recorded there is real — the same seed reproduces the
 * exact same `input` bytes every time — and `schema.test.ts` checks that
 * reproduction against the committed fixtures.
 *
 * The distinguishing property under test is the reviewed Docker Hub contract
 * (`decision-freeze-precision-contracts-seven-provider-families`): a personal access
 * token is `dckr_pat_` + exactly 27 bytes of `[A-Za-z0-9_-]`, an organization
 * access token is `dckr_oat_` + exactly 32 bytes of the same alphabet, and the
 * two segment names do not share a length. Every mutation below changes
 * exactly one structural property of its identity case, so silence (or the
 * identity match) follows from construction.
 *
 * Both base literals are unmistakably synthetic, revoked-shaped values: never
 * real or real-looking credentials.
 */

export const DOCKER_TOKEN_EXACT_LENGTH_SEED_ID = "docker-token-exact-length-synthetic-seed";

const PAT_PREFIX = "dckr_pat_";
const OAT_PREFIX = "dckr_oat_";
/** Exactly the 27-byte suffix a Docker Hub personal access token carries. */
const PAT_BODY = "SYNTHETIC_REVOKED_KEY_VALUE";
/** Exactly the 32-byte suffix a Docker Hub organization access token carries. */
const OAT_BODY = "SYNTHETIC_REVOKED_OAT_KEY_VALUE3";
/** The fixed byte (the `C` closing `SYNTHETIC`) the `invalid-alphabet` and
 * `whitespace-insertion` operations mutate. */
const MUTATED_INDEX = 8;

if (PAT_BODY.length !== 27 || OAT_BODY.length !== 32) {
  throw new Error("docker-token-exact-length base literals drifted from the reviewed contract");
}

export interface DockerTokenMutationCase {
  readonly operation: string;
  readonly ordinal: number;
  readonly input: string;
}

/**
 * The ordered, deterministic mutation set this seed produces. Order is
 * significant: `ordinal` is each case's index here, matching the corpus
 * fixtures' `mutation.ordinal`.
 */
export function generateDockerTokenMutations(): readonly DockerTokenMutationCase[] {
  const operations: readonly (readonly [string, string])[] = [
    ["pat-identity", PAT_PREFIX + PAT_BODY],
    ["pat-one-short", PAT_PREFIX + PAT_BODY.slice(0, -1)],
    ["pat-one-long", `${PAT_PREFIX}${PAT_BODY}0`],
    ["oat-identity", OAT_PREFIX + OAT_BODY],
    ["oat-one-short", OAT_PREFIX + OAT_BODY.slice(0, -1)],
    ["oat-one-long", `${OAT_PREFIX}${OAT_BODY}0`],
    ["pat-length-under-oat-prefix", OAT_PREFIX + PAT_BODY],
    ["oat-length-under-pat-prefix", PAT_PREFIX + OAT_BODY],
    [
      "pat-invalid-alphabet",
      PAT_PREFIX + PAT_BODY.slice(0, MUTATED_INDEX) + "!" + PAT_BODY.slice(MUTATED_INDEX + 1),
    ],
    [
      "oat-whitespace-insertion",
      OAT_PREFIX + OAT_BODY.slice(0, MUTATED_INDEX) + " " + OAT_BODY.slice(MUTATED_INDEX),
    ],
  ];

  return operations.map(([operation, input], ordinal) => ({
    operation,
    ordinal,
    input,
  }));
}
