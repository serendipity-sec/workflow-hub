# Worker layout

`src/cli.ts` remains the command entry (`dist/cli.js`). Implementation modules are grouped by responsibility:

| Directory         | Responsibility                                                                          |
| ----------------- | --------------------------------------------------------------------------------------- |
| `src/contracts/`  | Legacy SQL, static inspection and assessment schemas and limits                         |
| `src/workflow/`   | n8n parsing, safe locations, node profiles and bounded value/code/binary provenance     |
| `src/rules/`      | Content, settings, SQL, egress, AI and other static security rules                      |
| `src/analysis/`   | Legacy SQL and static orchestration and comparison                                      |
| `src/assessment/` | Evidence, environment, policy, child definitions, remediation and assessment comparison |
| `src/runtime/`    | Trusted I/O, API client, subprocesses, Docker launcher and native scanner adapters      |
| `src/service/`    | Coverage explanations, Korean service presentation and optional LLM explanation         |

TypeScript preserves this structure under `dist/`. The Docker entry is `dist/runtime/assessment-entry.js`; the native Python helper stays in `tools/`. Permission-limited analysis children can read the compiled worker tree and their declared dependencies, without permission to execute workflow code or write files. Artifact verification hashes every compiled module recursively.

`test/` contains domain-named regression suites. `fixtures/` holds synthetic inputs; `validation/` holds reproducible commands and immutable historical measurements. Existing measurements keep the paths and hashes of the code they actually measured. Fresh runs write to ignored `evidence-local/` or a newly selected output, and do not rewrite historical receipts. See [validation](validation.md) and [assessment validation](assessment-validation.md).

The source organization does not establish a production job API. Actual backend integration remains #18.
