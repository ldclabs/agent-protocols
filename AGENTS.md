# Repository guidance

## Agent Workflow

- Work independently as the current agent. Do not spawn or delegate work to
  subagents.
- Before editing, run `git status --short`, confirm the current branch, and
  inspect existing diffs in the files you intend to change. Preserve the user's
  existing work; do not overwrite or revert unrelated files or changes.
- Use `rg` for search and focused reads before editing. Do not assume module
  boundaries from filenames alone.
- Before committing, review the final diff and stage only the files or hunks
  belonging to the requested task.
- At completion, briefly summarize the changes, the checks actually run and
  their results, and any checks not run or blocked. Never report an unrun check
  as passing. When committing, include the branch and commit ID in the summary.

## Scope and working style

- This repository holds the Agent Protocols draft specifications and three SDKs (Rust, TypeScript, Python) that implement them. The specs in `docs/protocols/` are the source of truth; SDKs, schemas, and vectors follow them.
- Keep changes focused on the requested outcome. Prefer a small, direct fix over new mechanisms, fields, or abstraction layers for hypothetical edge cases. Draft changes should avoid unnecessary churn.
- Preserve unrelated working-tree changes. Do not commit, tag, publish packages, or bump SDK versions unless the task authorizes it.
- Follow the user's language in explanations. State concrete evidence, impact, and verification; distinguish confirmed bugs from optimization suggestions.
- Commit messages use Conventional Commits with protocol scopes, for example `feat(identity,mail): ...`, `refactor(knowledge): ...`, `docs: ...`.

## Repository map

- `docs/protocols/<protocol>/`: one directory per protocol (`agent-identity`, `agent-profile`, `agent-delegation`, `agent-discourse`, `agent-knowledge`, `agent-mail`) with `1.0.md`, `1.0.zh-CN.md`, and its machine-readable files (`1.0.schema.json`, `1.0.vectors.json`, Discourse `1.0.packs.json`). `docs/protocols/README.md` is the index and reading guide.
- `docs/mcp/local-connector/`: the local MCP connector, an adapter over the protocols rather than a protocol. It is the only supported MCP surface; do not add per-service MCP interface specs.
- `docs/index.html`: the standalone vanilla HTML/CSS/JS landing page. English copy lives in the DOM under `data-i18n` keys; Chinese is the `ZH` object and runtime strings for both languages are the `DYN` object in the inline script. Its demos compute real hashes, signatures, and HPKE in the browser from fixed seeds that reproduce the published vectors. `DESIGN.md` is the design system for the docs and site.
- `crates/agent-protocols/`: Rust SDK. Optional features `http-client` and `local-connector`.
- `packages/agent-protocols/`: TypeScript SDK (pnpm workspace package), including the local connector under `src/local-connector/`.
- `python/agent-protocols/`: Python SDK. It has no local connector.
- `tests/`: cross-language Mail interop (`mail_interop.py`, with adapters in each SDK) and the Mail vector generator (`gen_mail_vectors.py`).
- The sibling `../alink` repository consumes the SDKs (for example `alink-mail` pins a released version). Do not modify another repository implicitly.

## Specification rules

- Edit English and Simplified Chinese documents together, with matching section numbers. The English text is the cross-implementation review text; the Chinese text must keep the same normative requirements.
- Follow the chapter order and authoring rules in `CONTRIBUTING.md` (Overview, Normative Language, protocol body, Security and Privacy, Conformance, lettered appendices). Specs describe the current draft only: no "changes from the previous draft" sections.
- Changing `MUST`, `SHOULD`, or `MAY` wording is a behavior change. Update the schema, vectors, all three SDKs, their tests, and their READMEs in the same change.
- Test vectors are normative. When a wire shape changes, regenerate the affected vectors instead of patching signatures or hashes by hand, and keep each vector file's existing JSON formatting.
- Agent Identity defines the shared HTTP conventions, signed envelopes, origins, and Agent URLs that the other protocols reference. Check cross-document references when changing them.
- "ADP" abbreviates only the Agent Discourse Protocol. Spell out Agent Delegation Protocol.
- Keep `docs/protocols/README.md`, the root `README.md` / `README.zh-CN.md`, and the landing page consistent when adding a protocol or changing its scope.

## SDK rules

- The three SDKs must stay in parity: same behavior, same error codes, and parallel names (camelCase in TypeScript, snake_case in Rust and Python, for example `parseAgentUrl` / `parse_agent_url`).
- SDK tests read the shared vectors from `docs/protocols/` at test time; do not copy vectors into SDK directories.
- Bundled schema copies must stay equivalent to `docs/protocols/<protocol>/1.0.schema.json`: Rust `src/{knowledge,mail}/schema.json`, Python `agent_protocols/{knowledge,mail}.schema.json`, and TypeScript `src/{knowledge,mail}-schema.ts`. Tests compare them against the docs copy.
- Rust verifies envelopes by re-serializing typed payloads, so any struct reachable from a signed event must round-trip exactly. Optional collections there are `Option<Vec<_>>` / `Option<BTreeMap<_, _>>` with `skip_serializing_if = "Option::is_none"`, never `is_empty`, and open objects keep unknown members via `#[serde(flatten)]`. `tests/typed_round_trip.rs` guards this.
- TypeScript production code must run in Node, browsers, and Workers: no `node:*` imports or `Buffer` outside tests.
- Production encryption always uses fresh randomness; deterministic keys and seeds belong only in tests and vector generators.
- SDK versions in `packages/agent-protocols/package.json`, `crates/agent-protocols/Cargo.toml`, and `python/agent-protocols/pyproject.toml` must match. Releases are the owner's call: do not bump versions unless asked. A `v<version>` tag triggers `.github/workflows/publish-sdks.yml`. Change the version with `make version VERSION=X.Y.Z`, which also updates the SDK note in `docs/index.html` (English and `ZH`) and keeps each file's final newline.
- Never print or commit credentials, tokens, or private keys. Test keys come from fixed, published seeds.

## Commands and verification

Run commands from the repository root. Install TypeScript dependencies with `pnpm install`; set up Python with `python3 -m venv .venv && .venv/bin/pip install -e './python/agent-protocols[test]'`. The Makefile uses `.venv/bin/python` when it exists.

| Area                          | Commands                                                                                   |
| ----------------------------- | ------------------------------------------------------------------------------------------ |
| All SDKs and Mail interop     | `make test`                                                                                |
| Rust format and lint          | `make lint` (`cargo fmt` plus `cargo clippy --all-targets --all-features`)                 |
| Rust tests                    | `cargo test --workspace --all-features`; `cargo test --workspace` for the no-feature build |
| TypeScript tests              | `pnpm -r test`                                                                             |
| TypeScript type check / build | `pnpm -r build`                                                                            |
| Python tests                  | `.venv/bin/python -m pytest python/agent-protocols/tests`                                  |
| Cross-language Mail interop   | `make test-mail-interop`                                                                   |
| Regenerate Mail vectors       | `make mail-vectors`                                                                        |
| Set the SDK version           | `make version VERSION=X.Y.Z`                                                               |
| Landing page preview          | `python3 -m http.server 8899 --directory docs` (the `docs-site` launch config)             |

- CI (`.github/workflows/test.yml`) runs clippy, Rust tests with all features, `pnpm -r test`, `pnpm -r build`, pytest, and the Mail interop test.
- `make test` does not type-check TypeScript: `pnpm -r test` runs through tsx with types erased. Run `pnpm -r build` after TypeScript changes.
- Match verification to the change. Spec or vector changes need all three SDK suites; a single-SDK fix needs that SDK's suite and, if it touches shared behavior, the vectors in the other two. Landing page changes need a browser check of both languages and the demos.
- There is no Prettier config. Format TypeScript files you edit with `npx -y prettier@3 --write <files>`, except `identity.ts` and `identity.test.ts`, which are not Prettier-formatted. Do not reformat unrelated files. Python follows the surrounding style.
- Report checks actually run and any failures or environment blockers. A passing test suite does not by itself prove cross-SDK interoperability; the shared vectors and the Mail interop test do.
