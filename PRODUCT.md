# Product

## Register

product

## Users

The primary user is a security or platform engineer evaluating one
pre-instrumented AWS RAG application. They work at a technical workstation,
already control the suite, execution policy, AWS identities, synthetic
canaries, and evidence directory, and need to understand exactly what the
verifier attempted and what the evidence supports.

Their primary task is to load an authorized reciprocal retrieval scenario,
confirm readiness, execute the bounded two-direction run, interpret both
results, and inspect the integrity state of locally retained evidence.

## Product Purpose

Cloud AI Control Verifier executes narrow, deterministic security-control tests
and preserves normalized machine-readable evidence. The local security console
makes the complete reciprocal AWS retrieval workflow easier to operate without
moving AWS credentials, configuration, or evidence to a hosted service.

Success means an operator can review the exact authorized plan, identify a
readiness problem, run the existing engine, and distinguish verified,
incomplete, and invalid evidence without mistaking any result for a compliance
determination.

## Brand Personality

Calm, precise, forensic.

The product should feel disciplined under pressure. Its voice is direct and
technical without becoming terse or theatrical. Linear is a reference for
information density and state clarity, Stripe for careful technical
configuration, and 1Password for communicating sensitive boundaries without
alarmism.

## Anti-references

- AWS-console sprawl with many unrelated services, nested navigation, and
  competing panels.
- Generic card-grid dashboards and hero metrics that obscure the actual
  workflow.
- Generic AI-tool chrome such as purple gradients, neon accents, glassmorphism,
  and decorative model imagery.
- Compliance-certificate theater or copy that implies one passing run
  establishes compliance.
- Consumer onboarding that hides technical boundaries or turns exact
  authorization into a one-click promise.

## Design Principles

- **Follow the evidence path.** Organize every screen around configuration,
  readiness, execution, results, and evidence integrity.
- **Expose boundaries before action.** State what will run, which fixed
  operations are authorized, and what the result cannot establish.
- **Reveal sensitive configuration deliberately.** Mask identifiers by default,
  make reveal temporary and explicit, and never reveal environment values or
  credentials.
- **Make uncertainty legible.** Missing, stale, partial, malformed, or ambiguous
  evidence must remain visibly distinct from a pass.
- **Keep the engine authoritative.** The console presents validated engine
  state and normalized results. It does not invent assertions, reinterpret
  statuses, or make compliance claims.

## Accessibility & Inclusion

The console targets WCAG 2.2 AA. Every workflow must be keyboard-complete, use
semantic landmarks and native controls, preserve a visible focus indicator,
and expose status through text and iconography rather than color alone. Text
and controls must retain required contrast in both themes and at 200 percent
zoom. Motion must honor reduced-motion preferences, and layouts must remain
usable from a 320-pixel viewport through large desktop displays.
