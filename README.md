# github-actions-reusable-workflows

Versioned reusable workflows and composite actions shared across this portfolio's
repositories. Terraform validate/plan/apply, Python quality, container build-scan-sign, and
language-agnostic security scanning.

## Problem

CI starts as one workflow file and ends as five copies. They begin identical and then
diverge: one pins Terraform 1.9, another 1.7; one uploads SARIF, another only prints to the
log; one remembered to gate registry push on the event type and one did not.

The divergence is not the real cost. The real cost is that a security fix has to be applied
five times and will be applied three times, and nobody can tell you which repositories got
it without opening all five.

## Objective

One implementation per concern, versioned by tag, consumed by reference. A change to plan
rendering, a Terraform version bump, or a new scanner lands once and reaches every consumer
on their next run — or on their next tag bump, if they pin conservatively.

## Available workflows

| Workflow | Purpose | Needs OIDC |
|---|---|---|
| [`terraform-validate.yml`](.github/workflows/terraform-validate.yml) | fmt, validate (matrix over directories), tflint | no |
| [`terraform-plan.yml`](.github/workflows/terraform-plan.yml) | plan with a read-only role, sticky PR comment, `has_changes` output | yes |
| [`terraform-apply.yml`](.github/workflows/terraform-apply.yml) | apply behind a GitHub Environment, optional smoke test | yes |
| [`python-quality.yml`](.github/workflows/python-quality.yml) | ruff, mypy, pytest matrix, bandit, pip-audit | no |
| [`container-build.yml`](.github/workflows/container-build.yml) | build, Trivy, smoke test, UID assertion, SBOM, multi-arch push, cosign | no (registry uses `GITHUB_TOKEN`) |
| [`security-scan.yml`](.github/workflows/security-scan.yml) | Checkov, Trivy config, gitleaks — all reporting SARIF | no |
| [`terraform-policy.yml`](.github/workflows/terraform-policy.yml) | evaluates `devsecops-pipeline`'s Rego policies against a real `terraform plan`, exceptions resolved at evaluation time | yes |
| [`image-update.yml`](.github/workflows/image-update.yml) | writes a published image digest into a GitOps repository's Kustomize overlay, direct-commit or PR mode | no (needs a `gitops_token` secret with `contents:write` on the target repo) |

Composite action: [`actions/aws-oidc`](actions/aws-oidc) — assume a role with a
CloudTrail-traceable session name and confirm the resulting identity.

## Usage

### Terraform repository

```yaml
jobs:
  validate:
    uses: Saikiran6650/github-actions-reusable-workflows/.github/workflows/terraform-validate.yml@v1
    with:
      working_directories: '["modules/three-tier", "environments/dev", "environments/prod"]'

  plan:
    needs: [validate]
    if: github.event_name == 'pull_request'
    strategy:
      matrix:
        environment: [dev, prod]
    uses: Saikiran6650/github-actions-reusable-workflows/.github/workflows/terraform-plan.yml@v1
    permissions:
      contents: read
      id-token: write
      pull-requests: write
    with:
      environment: ${{ matrix.environment }}
      working_directory: environments/${{ matrix.environment }}
      role_arn: ${{ vars.AWS_PLAN_ROLE_ARN }}
```

### Containerised service

```yaml
jobs:
  quality:
    uses: Saikiran6650/github-actions-reusable-workflows/.github/workflows/python-quality.yml@v1
    with:
      python_versions: '["3.11", "3.12"]'

  image:
    needs: [quality]
    uses: Saikiran6650/github-actions-reusable-workflows/.github/workflows/container-build.yml@v1
    permissions:
      contents: read
      packages: write
      security-events: write
      id-token: write
    with:
      image_name: saikiran6650/sample-service
      expected_uid: 10001
```

Full examples: [`examples/`](examples).

## Permissions a caller must grant

A reusable workflow cannot raise its own permissions above what the caller grants. If a job
fails with a 403, this table is usually the reason.

| Workflow | Required in the caller |
|---|---|
| `terraform-validate.yml` | none beyond the default |
| `terraform-plan.yml` | `id-token: write`, `pull-requests: write` |
| `terraform-apply.yml` | `id-token: write` |
| `python-quality.yml` | `security-events: write` |
| `container-build.yml` | `packages: write`, `security-events: write`, `id-token: write` |
| `security-scan.yml` | `security-events: write` |
| `terraform-policy.yml` | `id-token: write`, `pull-requests: write` |
| `image-update.yml` | none beyond the default (pass the `gitops_token` secret) |

## Versioning

Tags follow semver, with a moving major tag:

- `@v1` — recommended. Receives fixes and backward-compatible additions automatically.
- `@v1.2.0` — exact pin. Nothing changes until you bump it.
- `@main` — **do not.** A branch reference means someone else's push changes what your
  pipeline does between two runs of the same commit.

Breaking changes — removing an input, changing a default that alters behaviour, raising a
required permission — get a new major tag. `v1` is never repointed across a major.

## Design decisions

**Role ARNs are inputs, not secrets.** An ARN is inert without a matching OIDC trust policy
in the target account. Treating it as a secret adds friction and encourages the belief that
its secrecy is what protects the account, which is the wrong mental model to build a
pipeline on.

**Plan and apply are separate workflows with separate roles.** "Can propose a change" and
"can make a change" should not be the same permission. Plan is read-only and assumable from
any pull request; apply is scoped and assumable only from the protected branch.

**The gate lives in repository settings, not in YAML.** `terraform-apply.yml` runs inside a
GitHub Environment whose required-reviewer rule is the actual promotion gate. Nothing in the
workflow can bypass it — which matters, because the pull request being reviewed could
otherwise edit the file containing its own gate.

**Plan output reaches `github-script` through `env:`, never string interpolation.** A
resource name containing a backtick or `${` would otherwise break the script, or worse.

**The PR comment is sticky.** It updates in place instead of appending one comment per push.
A pull request with fifteen stale plan comments is a pull request nobody reads.

**`-detailed-exitcode` on plan.** Without it, "no changes" and "changes" share an exit code,
and drift detection is impossible. With it, the same workflow serves both pull-request
planning and scheduled drift checks via `fail_on_changes`.

**The container is scanned and started before it is published.** An image that has not been
proven to boot never acquires a tag something downstream might deploy. The non-root UID is
asserted by running `id -u` inside it, because a dropped `USER` instruction is not reliably
caught by static scanning.

**No `latest` tag, ever.** A mutable tag makes the running revision unknowable from a
manifest, which turns rollback into a guess.

**Unfixed CVEs do not block.** They are reported to the Security tab but cannot be actioned
by the consuming repository — the only remedy is waiting for upstream. A gate nobody can
satisfy teaches people to ignore red.

**This repository lints itself.** `ci.yml` runs actionlint with shellcheck, parses every
file, and enforces a contract: every workflow is callable, declares
`permissions: contents: read` at the top level, gives every job a `timeout-minutes`, and
accepts no static AWS credential. A workflow library that ships broken YAML ships it to
every consumer at once.

## Known limitations

- **Actions are pinned by tag, not by SHA.** Tags are mutable. The migration plan, and why
  it is sequenced after Dependabot rather than before, is in
  [`docs/security.md`](docs/security.md#known-gap-actions-are-pinned-by-tag-not-by-sha).
- **No self-hosted runner support.** `runs-on: ubuntu-latest` is hard-coded. Making it an
  input is straightforward when a consumer needs it.
- **AWS only.** The OIDC pattern generalises to Azure and GCP; only the AWS path is built.
- **Not executed.** These workflows have not run against real infrastructure — no AWS
  account was connected during authoring. They are statically validated: YAML parsed,
  workflow contract enforced, and every input referenced by a consumer checked to exist.
  Confidence should come from the first real run, not from this README.

## Consumers

| Repository | Uses |
|---|---|
| `terraform-modules-library` | validate, security-scan |
| `terraform-aws-network-foundation` | validate, plan, policy, apply, security-scan |
| `terraform-aws-three-tier-app` | validate, plan, policy, apply, security-scan |
| `terraform-aws-eks-platform` | validate, plan, policy, apply, security-scan |
| `sample-service` | python-quality, container-build, image-update, security-scan |
| `azure-landing-zone` | security-scan |
| `cicd-jenkins-argocd-pipeline` | security-scan |
| `devsecops-pipeline` | security-scan |
| `observability-stack` | security-scan |

`gitops-argocd-platform` is the one repository in the portfolio with no CI workflow — it's
ArgoCD-managed manifests, verified offline, never applied to a cluster, so there's nothing
here for it to consume.

## License

MIT — see [LICENSE](LICENSE).
