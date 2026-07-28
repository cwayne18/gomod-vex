# gomod-vex

`gomod-vex` checks whether a given CVE in a Go module is **actually present and
reachable**, rather than merely being listed as a dependency. Point it at either:

- a **container image** (`--image`) — inspects the shipped Go binaries, or
- a **source repository** (`--repo`) — clones it and runs govulncheck's
  call-graph reachability analysis.

It is a generic, Go rewrite of the `vex_candidates.py` triage script from
[`cwayne18/rke2-toolbox`](https://github.com/cwayne18/rke2-toolbox): instead of
parsing a Trivy scan report, you point it directly at a target, a module, and
(optionally) a list of CVEs.

Package/CVE scanners flag a module as vulnerable whenever the *module* is a
dependency, even if the linker dead-code-eliminated the vulnerable *package* or
the vulnerable functions are never reachable. `gomod-vex` distinguishes those
cases so you can produce accurate [VEX](https://www.cisa.gov/resources-tools/resources/minimum-requirements-vulnerability-exploitability-exchange-vex)
statements.

## How it works

### Image mode (`--image`)

For every Go binary in the image that links the target module, `gomod-vex`:

1. **Resolves the vulnerable packages** from the [OSV](https://osv.dev) Go
   database, keyed by module + the version embedded in the binary's build info.
2. **govulncheck (binary mode)** — for non-stripped binaries, a linked but
   unreachable package is reported `vulnerable_code_not_in_execute_path`.
3. **pclntab presence test** — a Go binary keeps its function-name table even
   when fully stripped (`-ldflags=-s -w`). If none of a CVE's vulnerable
   packages appear in it, the linker eliminated them:
   `vulnerable_code_not_present`.

Module versions are read straight from each binary's embedded build info
(`debug/buildinfo`), so no Trivy report or manual version input is required.

### Repo mode (`--repo`)

The repo is cloned (shallow) and analyzed with **govulncheck source mode**,
whose call-graph reachability is authoritative for a source tree — strictly
better than the pclntab heuristic (which only exists because shipped binaries
are stripped). Each advisory in the dependency graph is classified as
`reachable` (the vulnerable symbol is actually called),
`not_in_execute_path` (imported but unreachable) or `not_present` (unused).
A local checkout path or `file://` URL is scanned in place without cloning.

### LLM exploitability check (optional, `--llm`)

For CVEs whose vulnerable code is genuinely linked (image mode) or reachable
(repo mode), a [GitHub Models](https://github.com/marketplace/models) chat model
gives an advisory `likely` / `unlikely` / `unknown` exploitability verdict.

## Requirements

- A Go toolchain on `PATH` (also required at **runtime** for `--repo` source
  analysis). Repo mode builds and runs `govulncheck` itself via `go run` with
  `GOTOOLCHAIN=auto`, so Go will fetch whatever toolchain the scanned module
  requires — no manual version matching needed.
- [`skopeo`](https://github.com/containers/skopeo) on `PATH` — image mode
- `git` on `PATH` — repo mode (unless scanning a local path)
- [`govulncheck`](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) on `PATH`
  — used only in image (binary) mode; optional. Repo mode does not need it
  preinstalled.
- Network access for `--repo` (to clone, download the module graph, and fetch a
  toolchain if the module needs a newer Go than is installed)
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

A self-contained image bundling `skopeo`, `git`, `govulncheck` and a Go
toolchain (so both image and repo modes work) is published to
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
gomod-vex --image REF  --module PATH [--cves LIST] [flags]   # image mode
gomod-vex --repo  REPO --module PATH [--cves LIST] [flags]   # repo mode
```

Check two specific `x/net` CVEs in an image:

```sh
gomod-vex \
  --image rancher/hardened-kubernetes:v1.30.1-rke2r1 \
  --module golang.org/x/net \
  --cves CVE-2023-39325,CVE-2023-44487
```

Check a CVE against a source repo via reachability analysis:

```sh
gomod-vex \
  --repo github.com/rancher/rancher \
  --module golang.org/x/net \
  --cves CVE-2023-45288
```

`--repo` accepts `github.com/owner/repo`, a full clone URL, a bare
`owner/repo` (assumed GitHub), or a local checkout path / `file://` URL. Use
`--ref` for a branch, tag or commit and `--repo-path` for a module in a
subdirectory.

Check every advisory known for `x/crypto`, as JSON, with the LLM layer:

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
| `--image` | | Container image to inspect (mutually exclusive with `--repo`) |
| `--repo` | | Git source repo to analyze via govulncheck source mode |
| `--ref` | *(default branch)* | Branch, tag, or commit to check out for `--repo` |
| `--repo-path` | `.` | Module subdirectory within `--repo` to scan |
| `--module` | *(required)* | Go module import path to evaluate |
| `--cves` | *(all)* | Comma-separated CVE / GHSA / GO ids; empty checks every advisory for the version |
| `--cves-file` | | File with one id per line (merged with `--cves`; `#` comments allowed) |
| `--version` | *(auto)* | Override the module version (image mode) instead of reading build info |
| `--os` / `--arch` | `linux` / `amd64` | Image platform variant to pull (image mode) |
| `--llm` | `false` | Consult a GitHub Models LLM on genuinely-affected CVEs |
| `--llm-model` | `openai/gpt-4o` | GitHub Models model id for `--llm` |
| `--format` | `text` | `text` or `json` |
| `--out` | *(stdout)* | Write output to a file |
| `--quiet` | `false` | Suppress progress logging on stderr |

Exactly one of `--image` or `--repo` is required.

## Output statuses

| Status | Meaning | Suggested VEX justification |
|---|---|---|
| `not_present` | Vulnerable package absent (pclntab / govulncheck source) | `vulnerable_code_not_present` |
| `not_in_execute_path` | Linked/imported but govulncheck marks it unreachable | `vulnerable_code_not_in_execute_path` |
| `linked` | Vulnerable package genuinely linked, image mode (real finding) | *(none — treat as affected)* |
| `reachable` | Vulnerable symbol is called, repo mode (real finding) | *(none — treat as affected)* |
| `undetermined` | No mapping for the id at this version | *(manual review)* |

In image mode, when OSV publishes no package-level import paths for an advisory
(e.g. some GitHub-only GHSA records), presence is asserted at **module**
granularity instead; these are coarser, so validate before transferring.

## Caveats

- The LLM verdict is advisory only. Never auto-file a VEX statement solely on an
  LLM verdict; it supplements, and does not replace, the deterministic checks.
- pclntab matching (image mode) is a heuristic. It is deliberately conservative
  (a genuinely-linked package is never reported absent), but validate candidates
  before publishing VEX.
- Repo mode needs a Go toolchain, `git` and network access at runtime. It runs
  `govulncheck` via `go run` from inside the target module with
  `GOTOOLCHAIN=auto`, so Go automatically fetches a newer toolchain when the
  scanned module requires one. Override the govulncheck version with
  `GOMODVEX_GOVULNCHECK_VERSION` if needed.

## License

MIT — see [LICENSE](./LICENSE).
