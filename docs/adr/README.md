# Architecture Decision Records

Numbered, append-only records of decisions that shape architecture, security posture
or tooling with lasting impact. Once **Accepted**, an ADR is immutable — changing course
means a new ADR that supersedes the old one.

## When to write one

A change that future-you (or a reviewer) would ask *"why is it like this?"* about:
component choices, protocols/contracts, security trade-offs, pipeline gates,
anything overriding a previous ADR or a core architecture decision (ADR-0001).

## Conventions

- Filename: `NNNN-kebab-title.md`, numbered sequentially from `0001`.
- Statuses: `Proposed` → `Accepted` | `Rejected`; later possibly `Superseded by ADR-NNNN` | `Deprecated`.
- Use [`template.md`](template.md). Keep it honest: real alternatives, real downsides.
- Decisions altering interview-approved choices (ADR-0001) require
  explicit user/owner sign-off before `Accepted`.

## Index

| ADR | Title | Status |
|---|---|---|
| [0001](0001-architektura.md) | Core architecture of netSoldier (interview decisions) | Accepted |
| [0002](0002-tls-fingerprinting.md) | Passive TLS/HTTP fingerprinting with JA3 + JA4+ | Accepted |
