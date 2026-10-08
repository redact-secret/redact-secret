# Public site feed v2

`feed.json` is generated from the immutable canonical qualification-view support
matrix and the existing release record. Its `sources` bind the exact input bytes.
The generator emits v1 beside v2; v1 retains the historical matrix and its original
non-null timestamp contract until its consumers migrate.

The canonical view records policy, populations and released scanner versions. It
does not record a measurement timestamp or a product source commit. Therefore
`supportMatrix.generatedAt` and `measuredProductRevision` are null, and
`supportMatrix.source` carries the native policy and population identities.
`gatedLatestRelease` is false unless a future contract binds an actual release
gate to that canonical measurement. The top-level timestamp is the existing
release record's observed date, converted by the existing release projection;
it is never a substitute measurement time.

Run `python3 -B scripts/generate-site-feed.py --version 2` to regenerate this
contract, or omit `--version` to generate both contracts after canonical adoption.
Public consumers must explicitly select v2 and handle the nullable timestamp.
The v1 contract and compatibility policy remain unchanged.

`sourceReportedProviderCount` preserves the upstream count of distinct family
provider identities, including the null bucket for generic families.
`providerCount` recounts distinct non-null named providers represented by the
listed families. Neither field counts registered taxonomy providers.
