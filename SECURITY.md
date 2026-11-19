# Security policy

Report suspected vulnerabilities privately to the repository owner; do not
open public issues for them.

## Handling rules for contributors

- Never commit real keys, tokens, KEKs, token keys or database URLs. `./secrets/` is
  gitignored for local development; tests generate fake keys.
- Secret values must be wrapped in `broker_core::Secret` and must never be
  logged, put into span fields, metric labels, error messages or audit rows.
- Request and response bodies of the LLM proxy are never logged.
- Upstream hosts come only from configuration. Do not add code paths that
  derive a URL, host or port from a request.
- New proxy endpoints must be allowlisted explicitly and must either report
  usage the proxy can account or be free.
- No `unsafe` (`#![forbid(unsafe_code)]`), no `unwrap()`/`expect()` outside
  tests (clippy deny).
- Dependencies must pass `cargo deny check` and `cargo audit`; new versions
  must be at least 14 days old.

## Rotation

- **KEK:** generate a new key (`otter-credential-broker keygen`), make it the
  current `[kek]`, move the old one to `[[kek.previous]]`, roll out, call
  `POST /v1/admin/kek/rewrap` until `remaining` is 0, then remove the old
  key and roll out again.
- **Token key:** replacing `token_key_file` invalidates every issued LLM and
  job token at once; roll out and let the platform issue new tokens. Use it
  when the key may have leaked.
- **Admin tokens:** add the new line to the tokens file, roll out, switch the
  caller, remove the old line, roll out.
- **Provider keys:** `PATCH /v1/admin/tenants/{t}/secrets/llm.<provider>`
  with the new value; the next proxied request uses it. Revoke the old key at
  the provider.
- **Suspected LLM token leak:** `POST /v1/admin/tenants/{t}/llm-tokens/{id}/revoke`
  (effective on the next request) and issue a new token.

See docs/THREAT_MODEL.md.
