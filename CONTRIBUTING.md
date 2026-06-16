# Contributing to AgentArmor

Thanks for your interest in contributing — students, early-career engineers, and
seasoned security folks are all welcome. Please **open an issue first** to
discuss anything non-trivial so we can align on approach before you invest time.

## Contributor License Agreement (required)

Before your first pull request can be merged, you must sign the
[Contributor License Agreement](CLA.md).

In short: **you assign the copyright in your contribution to the project
maintainer** so AgentArmor can be maintained and, where the maintainer chooses,
licensed commercially in the future. In return you keep a perpetual,
royalty-free license to reuse your own contributed code in your own projects. A
contribution is a voluntary gift and **does not entitle you to payment, equity,
royalties, or a share of any monetization** — now or later. Please read the
[full CLA](CLA.md) before signing.

**How to sign:** open your pull request as normal. A bot will comment asking you
to sign. Add a comment to the PR containing exactly:

```
I have read the CLA Document and I hereby sign the CLA
```

You only sign once — future PRs are recognized automatically.

> If you're contributing as part of your job or using an employer's resources,
> make sure you have permission to contribute and to grant these rights (see
> Section 8 of the CLA).

## Local development

```bash
git clone https://github.com/vikrantwaghmode/agentarmor-oss && cd agentarmor-oss
cd proxy
go build ./...               # full flavor (default)
go build -tags lite ./...    # lite flavor (no compliance/WASM)
go test ./...                # run the suite
gofmt -l . && go vet ./...   # must be clean before a PR
```

## Good first contributions

- New `policy.yaml` scanner rules (prompt-injection, malicious-content, PII,
  secrets) — pure data, no Go needed.
- WASM filters in `./wasm-filters/` (any WASI language) — see
  `wasm-filters/README.md`.
- ATR rules — contribute upstream at
  [Agent-Threat-Rule/agent-threat-rules](https://github.com/Agent-Threat-Rule/agent-threat-rules).

## Pull requests

- Keep them focused and small.
- Include clean `go test` / `go vet` / `gofmt` output.
- Update the README and the `policy.yaml` example when you add a config-visible
  feature.
- Security-sensitive changes (auth, egress, the scan pipeline) should explain
  the threat model in the PR description.

Questions or commercial/partnership inquiries: vikrant.waghmode@gmail.com ·
[LinkedIn](https://www.linkedin.com/in/securityhandyman/)
