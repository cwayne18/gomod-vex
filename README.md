# gomod-vex

`gomod-vex` checks whether a given CVE in a Go module is **actually present in
the binaries shipped inside a container image**, rather than merely being
listed as a dependency. It is a generic, Go rewrite of the
`vex_candidates.py` triage script from
[`cwayne18/rke2-toolbox`](https://github.com/cwayne18/rke2-toolbox): instead of
parsing a Trivy scan report, you point it directly at an image, a module, and
(optionally) a list of CVEs.

Package/CVE scanners flag a module as vulnerable whenever the *module* is a
dependency, even if the linker dead-code-eliminated the vulnerable *package* or
the vulnerable functions are never reachable. `gomod-vex` distinguishes those
cases so you can produce accurate [VEX](https://www.cisa.gov/resources-tools/resources/minimum-requirements-vulnerability-exploitability-exchange-vex)
statements.

## How it works

For every Go binary in the image that links the target module, `gomod-vex`:

1. **Resolves the vulnerable packages** from the [OSV](https://osv.dev) Go
   database, keyed by module + the version embedded in the binary's build info.
2. **govulncheck (binary mode)** — for non-stripped binaries, a linked but
   unreachable package is reported `vulnerable_code_not_in_execute_path`.
3. **pclntab presence test** — a Go binary keeps its function-name table even
   when fully stripped (`-ldflags=-s -w`). If none of a CVE's vulnerable
   packages appear in it, the linker eliminated them:
   `vulnerable_code_not_present`.
4. **LLM exploitability check (optional, `--llm`)** — for CVEs whose vulnerable
   package really is linked, a [GitHub Models](https://github.com/marketplace/models)
   chat model gives an advisory `likely` / `unlikely` / `unknown` exploitability
   verdict.

Module versions are read straight from each binary's embedded build info
(`debug/buildinfo`), so no Trivy report or manual version input is required.

## Requirements

- Go 1.23+
- [`skopeo`](https://github.com/containers/skopeo) on `PATH` (image pull + flatten)
- [`govulncheck`](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) on `PATH`
  (optional; reachability analysis is skipped if absent)
- `GITHUB_TOKEN` (or `GH_TOKEN`) when using `--llm`

## Install

```sh
go install github.com/cwayne18/gomod-vex@latest
```

Or build from source:

```sh
git clone https://github.com/cwayne18/gomod-vex
cd gomod-vex
go build -o gomod-vex .
```

### Container image (GHCR)

A self-contained image bundling `skopeo` and `govulncheck` is published to
[`ghcr.io/cwayne18/gomod-vex`](https://github.com/cwayne18/gomod-vex/pkgs/container/gomod-vex)
on every push to `main` and every `v*` tag:

```sh
docker run --rm ghcr.io/cwayne18/gomod-vex:latest \
  --image rancher/hardened-coredns:v1.14.6 \
  --module golang.org/x/net --cves CVE-2023-39325
```

Pass a token through the environment to enable `--llm`:

```sh
docker run --rm -e GITHUB_TOKEN ghcr.io/cwayne18/gomod-vex:latest \
  --image myorg/myapp:latest --module golang.org/x/crypto --llm
```

## Usage

```sh
gomod-vex --image REF --module PATH [--cves LIST] [flags]
```

Check two specific `x/net` CVEs in an image:

```sh
gomod-vex \
  --image rancher/hardened-kubernetes:v1.30.1-rke2r1 \
  --module golang.org/x/net \
  --cves CVE-2023-39325,CVE-2023-44487
```

Check every advisory OSV knows for `x/crypto`, as JSON, with the LLM layer:

```sh
export GITHUB_TOKEN=...    # a token with models:read
gomod-vex \
  --image myorg/myapp:latest \
  --module golang.org/x/crypto \
  --llm --format json
```

### Flags

| Flag | Default | Description |
|---|---|---|
| `--image` | *(required)* | Container image reference to inspect |
| `--module` | *(required)* | Go module import path to evaluate |
| `--cves` | *(all)* | Comma-separated CVE / GHSA / GO ids; empty checks every advisory for the version |
| `--cves-file` | | File with one id per line (merged with `--cves`; `#` comments allowed) |
| `--version` | *(auto)* | Override the module version instead of reading build info |
| `--os` / `--arch` | `linux` / `amd64` | Image platform variant to pull |
| `--llm` | `false` | Consult a GitHub Models LLM on genuinely-linked CVEs |
| `--llm-model` | `openai/gpt-4o` | GitHub Models model id for `--llm` |
| `--format` | `text` | `text` or `json` |
| `--out` | *(stdout)* | Write output to a file |
| `--quiet` | `false` | Suppress progress logging on stderr |

## Output statuses

| Status | Meaning | Suggested VEX justification |
|---|---|---|
| `not_present` | Vulnerable package absent from the binary's pclntab | `vulnerable_code_not_present` |
| `not_in_execute_path` | Linked but govulncheck marks it unreachable | `vulnerable_code_not_in_execute_path` |
| `linked` | Vulnerable package is genuinely linked (real finding) | *(none — treat as affected)* |
| `undetermined` | OSV has no package mapping for the id at this version | *(manual review)* |

When OSV publishes no package-level import paths for an advisory (e.g. some
GitHub-only GHSA records), presence is asserted at **module** granularity
instead; these are coarser, so validate before transferring.

## Caveats

- The LLM verdict is advisory only. Never auto-file a VEX statement solely on an
  LLM verdict; it supplements, and does not replace, the deterministic checks.
- pclntab matching is a heuristic. It is deliberately conservative (a
  genuinely-linked package is never reported absent), but validate candidates
  before publishing VEX.

## License

MIT — see [LICENSE](./LICENSE).
