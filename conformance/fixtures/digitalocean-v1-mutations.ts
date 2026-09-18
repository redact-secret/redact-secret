/**
 * Deterministic reproducer for the `digitalocean-v1` grammar-mutation family
 * declared in `synchronous-corpus.json` (`mutation.grammar ===
 * "digitalocean-v1"`, `mutation.seedId === DIGITALOCEAN_V1_SEED_ID`).
 *
 * Like `github-classic-mutations.ts`, this module does not generate the
 * corpus: `fixtures/synchronous-corpus.json` stays the independently
 * authored, hand-maintained canonical source (see `conformance/README.md`).
 * Its only job is to prove the fixtures' `mutation` provenance is real:
 * given the same seed, the same bounded, ordered set of `(operation,
 * ordinal)` pairs reproduces the exact same `input` bytes every time, and
 * `schema.test.ts` checks that reproduction against the committed fixtures.
 *
 * The grammar under mutation is the reviewed DigitalOcean v1 token contract
 * (issue #369): one of the documented prefixes `dop_v1_` (personal access
 * token), `doo_v1_` (OAuth access token), or `dor_v1_` (OAuth refresh token),
 * followed by exactly 64 lowercase hexadecimal bytes. Sources: DigitalOcean's
 * API release notes (2022-03-29) for the prefixes; gitleaks v8.30.1
 * (`digitalocean-pat` / `digitalocean-access-token` /
 * `digitalocean-refresh-token`) and trufflehog v3.97.4 (`digitaloceanv2`) for
 * the `[a-f0-9]{64}` body. Each operation changes exactly one structural
 * property of the identity case, so an accepted or rejected outcome follows
 * from construction.
 *
 * The bodies are the locally constructed synthetic values from the issue's
 * self-contained snapshot. They were never provider-issued.
 */

export const DIGITALOCEAN_V1_SEED_ID = "digitalocean-v1-synthetic-seed";

const PAT_PREFIX = "dop_v1_";
const OAUTH_ACCESS_PREFIX = "doo_v1_";
const OAUTH_REFRESH_PREFIX = "dor_v1_";

/** Exactly 64 lowercase hex bytes each; index 8 (the `d` in the PAT body) is
 * the fixed byte the `uppercase-hex`, `invalid-alphabet`, and
 * `whitespace-insertion` operations mutate. */
const PAT_BODY = "1f24601fd1e661dc9b0a5f6e206888cac4ba0147c46563ccd2d81004e954cad9";
const OAUTH_ACCESS_BODY = "025343c0555235768c29735f523ad644fbfe1569b1d88f46b4f506628ae8b08a";
const OAUTH_REFRESH_BODY = "686b232b8722f7ab110b24d01fd9a96539cdec166f27e643ae9852b28d2b0da5";

const TOKEN = PAT_PREFIX + PAT_BODY;

export interface DigitaloceanV1MutationCase {
  readonly operation: string;
  readonly ordinal: number;
  readonly input: string;
}

/**
 * The ordered, deterministic mutation set this seed produces. Order is
 * significant: `ordinal` is each case's index here, matching the corpus
 * fixtures' `mutation.ordinal`.
 */
export function generateDigitaloceanV1Mutations(): readonly DigitaloceanV1MutationCase[] {
  const operations: readonly (readonly [string, string])[] = [
    ["identity", TOKEN],
    ["oauth-access-prefix", OAUTH_ACCESS_PREFIX + OAUTH_ACCESS_BODY],
    ["oauth-refresh-prefix", OAUTH_REFRESH_PREFIX + OAUTH_REFRESH_BODY],
    ["short-length", PAT_PREFIX + PAT_BODY.slice(0, -1)],
    ["long-length", `${TOKEN}0`],
    ["uppercase-hex", PAT_PREFIX + PAT_BODY.slice(0, 8) + "D" + PAT_BODY.slice(9)],
    ["invalid-alphabet", PAT_PREFIX + PAT_BODY.slice(0, 8) + "g" + PAT_BODY.slice(9)],
    ["whitespace-insertion", PAT_PREFIX + PAT_BODY.slice(0, 8) + " " + PAT_BODY.slice(8)],
    ["invalid-prefix", `dov_v1_${PAT_BODY}`],
    ["uppercase-prefix", `DOP_V1_${PAT_BODY}`],
    ["version-lookalike", `dop_v2_${PAT_BODY}`],
    ["leading-embedding", `legacy${TOKEN}`],
    ["trailing-embedding", `${TOKEN}_backup`],
    ["dash-embedding", `${TOKEN}-1`],
    ["punctuation-boundary", `${TOKEN},`],
    ["quoted", `"${TOKEN}"`],
    ["markdown-code-span", `\`${TOKEN}\``],
    ["encoded-prefix", `dop%5Fv1%5F${PAT_BODY}`],
    ["host-embedding", `https://example.test/?token=${TOKEN}&x=1`],
    ["repeated", `${TOKEN} ${TOKEN}`],
    // Issue #375: the `_v1_` separator itself was never mutated (only the
    // prefix and body were). Appended after `repeated` so every existing
    // fixture's `mutation.ordinal` stays stable.
    ["missing-separator", `dopv1${PAT_BODY}`],
    ["replaced-separator", `dop-v1-${PAT_BODY}`],
  ];

  return operations.map(([operation, input], ordinal) => ({
    operation,
    ordinal,
    input,
  }));
}
