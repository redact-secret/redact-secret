# #1012 research: confirm-only rows

[Research index](README.md) ·
[Issue #1012](https://github.com/redact-secret/redact-secret/issues/1012)

Frozen 2026-09-29. Desk research only. These three support-matrix rows are
`unsupported` on purpose; this record confirms the reason and proposes no
contract.

| Family | Verdict | Basis |
| --- | --- | --- |
| `mailgun:public-validation-key` | **NOT-A-SECRET** | Mailgun's validation docs (archived 2019-04-28, `documentation.mailgun.com/en/latest/api-email-validation.html`): "Do not use your Mailgun private API key on publicly accessible code. Instead, use your Mailgun public key". Mailgun Help Center, "Email Validations" (updated 2026-05-17): "The public endpoint is meant to be used within front-end applications … To protect the public API Key it has an initial monthly limit". The "Where can I find my API keys" article (updated 2025-08-12) lists the "Verifications Public Key" apart from API keys. The product `mailgun-api-key` detector excludes `pubkey-` by construction (`crates/secret-scan-core/src/detectors/mailgun.rs`). |
| `mailgun:legacy-signing-key-triplet` | **OWNED-ELSEWHERE** (`mailgun-api-key`, type `mailgun_api_key`) | Since #701 the product reports the triplet shape when `mailgun` appears on the same line (medium) or under a Mailgun-named key (high); see the `mailgun.rs` module doc and the support-matrix reason. |
| `pinecone:legacy-api-key` | **OWNED-ELSEWHERE** (`pinecone-api-key`, type `pinecone_api_key`) | Since #702 the product claims the UUID only under Pinecone API-key names, high (`crates/secret-scan-core/src/detectors/pinecone.rs`, and [the ADR](../../../decisions/2026-09-24-claim-a-legacy-pinecone-uuid-key-only-under-its-api-key-name.md)). A bare UUID stays unclaimed. |
