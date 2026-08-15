# Security model

A shared workflow library is a supply-chain component. Every repository that calls it
inherits whatever it does, so its own security properties matter more than those of any
single consumer.

## Threat model

What this library is defending against, in rough order of likelihood:

1. **A leaked cloud credential.** Historically the most common route from "someone got a
   repository" to "someone got the AWS account".
2. **A pull request from a fork exfiltrating secrets or publishing an artifact.**
3. **A compromised third-party action** running arbitrary code with the job's token.
4. **Over-broad `GITHUB_TOKEN` permissions** letting a compromised step rewrite the
   repository, its releases, or its workflows.
5. **Untrusted input reaching a shell or a script**, giving command injection in CI.

## Controls

### No long-lived cloud credentials, anywhere

Every AWS interaction authenticates by OIDC. The workflow presents a short-lived token,
AWS exchanges it for temporary credentials, and the role's trust policy constrains which
repository and which ref may do so.

The role ARN is an **input**, not a secret. An ARN is inert without a matching trust
policy — publishing it costs nothing, and treating it as a secret encourages the belief
that its secrecy is what protects the account.

`ci.yml` enforces this: the contract job fails the build if any reusable workflow declares
a secret whose name resembles an access key.

### Plan and apply are separate roles

`terraform-plan.yml` and `terraform-apply.yml` take different `role_arn` inputs on purpose.
Plan is read-only plus state access and is assumable from any pull request. Apply is scoped
to the resources the stack owns and is assumable only from the protected branch — with
`StringEquals` on the `sub` claim, never `StringLike`, because a wildcard would let a
fork's pull-request branch assume it.

### Fork pull requests cannot publish

`container-build.yml` gates registry login, push and signing on
`github.event_name == 'push'`. A pull request builds the image, scans it, starts it and
throws it away. There is no path by which a fork obtains a registry credential.

### Least-privilege tokens

Every workflow declares `permissions: contents: read` at the top level, and individual jobs
raise only what they need — `id-token: write` for OIDC, `packages: write` to publish,
`security-events: write` for SARIF. The contract job in `ci.yml` fails the build if a
workflow's top-level permissions are anything other than exactly `{contents: read}`.

### Untrusted input never reaches a shell

Plan output is passed to `github-script` through the `env:` block rather than interpolated
into the script body. Interpolating text that contains a backtick, a `${`, or a newline into
a JavaScript template literal is how a resource name becomes code execution. The same rule
applies to any `${{ github.event.* }}` value, none of which appear inside a `run:` block
here.

### Every job has a timeout

Enforced by the contract job. The default is six hours; a hung job without a timeout burns
runner minutes and tells nobody why.

## Known gap: actions are pinned by tag, not by SHA

`uses: actions/checkout@v4` resolves a **mutable** tag. The owner of an action can move `v4`
to point at different code at any time, and a compromised popular action would then run in
every job that references it. Pinning to a full commit SHA removes that.

This repository has not pinned yet, and the reason is honest rather than principled: pinning
requires resolving every action to a current, verified SHA, and stale pinned SHAs are worse
than tags because they silently miss security releases. The migration is only safe once
Dependabot is running to move the pins.

**The order to do it in:**

1. Merge `.github/dependabot.yml` (already present) and confirm it opens pull requests.
2. Run `pin-github-action` or `ratchet` across `.github/workflows/` to rewrite every `uses:`
   to `owner/action@<sha> # vX.Y.Z`.
3. Add the repository to an allowlist under Settings → Actions → General → *Allow specified
   actions*, so an unreviewed action cannot be introduced by a pull request.
4. Add a contract check asserting every `uses:` matches a 40-character SHA.

Until then, third-party actions used here are limited to well-known publishers
(`actions/*`, `docker/*`, `aws-actions/*`, `hashicorp/*`, `aquasecurity/*`, `github/*`,
`sigstore/*`, `anchore/*`, `gitleaks/*`, `bridgecrewio/*`, `terraform-linters/*`,
`raven-actions/*`), which reduces the exposure without eliminating it.

## Which gates block, and why

A gate that cannot be actioned by the repository it runs in should not block, because
people learn to ignore red and then ignore it everywhere.

| Gate | Blocks | Reasoning |
|---|---|---|
| gitleaks | always | A committed secret must be rotated. The sooner someone is forced to notice, the smaller the window. |
| `pip-audit` | yes | A vulnerable dependency *with an available fix* is a decision; make it explicitly with `--ignore-vuln`. |
| Checkov / Trivy config | yes (configurable) | Findings on Terraform are usually actionable in the repository that owns it. |
| Trivy image, fixed CVEs | yes | Actionable: rebuild on a patched base. |
| Trivy image, unfixed CVEs | no | Not actionable — the only remedy is waiting for upstream. Still reported to the Security tab. |
| bandit | no | False-positive rate on well-written Python is high enough that blocking would train people to skip it. Reported as SARIF. |
| Container smoke test | yes | An image that does not start is not a candidate for publication. |
| Non-root UID assertion | yes | Catches a Dockerfile change that drops `USER`, which no static scan reliably reports. |

## Reporting

Security issues in this repository: open a private security advisory rather than a public
issue.
