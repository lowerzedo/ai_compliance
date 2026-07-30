______________________________________________________________________

## name: CAI Verify Security Console description: A quiet forensic workstation for bounded cloud AI control evidence. colors: forensic-teal: "oklch(0.47 0.09 194)" forensic-teal-hover: "oklch(0.40 0.09 194)" forensic-teal-soft: "oklch(0.94 0.025 194)" light-canvas: "oklch(0.985 0.003 210)" light-surface: "oklch(1 0 0)" light-surface-muted: "oklch(0.96 0.006 210)" light-ink: "oklch(0.22 0.01 220)" light-ink-muted: "oklch(0.46 0.01 220)" light-border: "oklch(0.85 0.008 210)" dark-canvas: "oklch(0.14 0.008 220)" dark-surface: "oklch(0.18 0.009 220)" dark-surface-muted: "oklch(0.23 0.01 220)" dark-ink: "oklch(0.94 0.005 195)" dark-ink-muted: "oklch(0.72 0.01 200)" dark-border: "oklch(0.34 0.012 210)" danger-crimson: "oklch(0.50 0.18 25)" danger-soft: "oklch(0.95 0.025 25)" warning-ochre: "oklch(0.53 0.11 80)" warning-soft: "oklch(0.95 0.025 80)" typography: display: fontFamily: 'ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif' fontSize: "1.75rem" fontWeight: 650 lineHeight: 1.2 letterSpacing: "-0.02em" headline: fontFamily: 'ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif' fontSize: "1.375rem" fontWeight: 650 lineHeight: 1.3 letterSpacing: "-0.015em" title: fontFamily: 'ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif' fontSize: "1rem" fontWeight: 650 lineHeight: 1.4 body: fontFamily: 'ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif' fontSize: "0.9375rem" fontWeight: 400 lineHeight: 1.5 label: fontFamily: 'ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif' fontSize: "0.8125rem" fontWeight: 600 lineHeight: 1.35 letterSpacing: "0.01em" mono: fontFamily: 'ui-monospace, "SFMono-Regular", Menlo, Consolas, monospace' fontSize: "0.8125rem" fontWeight: 500 lineHeight: 1.45 rounded: sm: "6px" md: "10px" lg: "12px" pill: "999px" spacing: xs: "4px" sm: "8px" md: "12px" lg: "16px" xl: "24px" 2xl: "32px" components: button-primary: backgroundColor: "{colors.forensic-teal}" textColor: "{colors.light-surface}" typography: "{typography.label}" rounded: "{rounded.sm}" padding: "10px 14px" height: "40px" button-primary-hover: backgroundColor: "{colors.forensic-teal-hover}" textColor: "{colors.light-surface}" button-secondary: backgroundColor: "{colors.light-surface}" textColor: "{colors.light-ink}" typography: "{typography.label}" rounded: "{rounded.sm}" padding: "10px 14px" height: "40px" field: backgroundColor: "{colors.light-surface}" textColor: "{colors.light-ink}" typography: "{typography.body}" rounded: "{rounded.sm}" padding: "10px 12px" height: "40px" status-pass: backgroundColor: "{colors.forensic-teal-soft}" textColor: "{colors.forensic-teal-hover}" typography: "{typography.label}" rounded: "{rounded.pill}" padding: "4px 8px" status-critical: backgroundColor: "{colors.danger-soft}" textColor: "{colors.danger-crimson}" typography: "{typography.label}" rounded: "{rounded.pill}" padding: "4px 8px"

# Design System: CAI Verify Security Console

## Overview

**Creative North Star: "Quiet Forensic Workstation"**

The console is designed for a security engineer reviewing bounded evidence at a
technical workstation, often for an extended period and sometimes under
incident-response pressure. It should feel calm, exact, and durable in mixed
office light. Density is disciplined rather than sparse: important
relationships stay visible, while decoration stays out of the operator's path.

The workflow is linear and honest. Configuration leads to readiness, readiness
to explicit confirmation, execution to two-direction results, and results to
verified evidence. Responsive layouts preserve that order from 320 pixels
through large desktops. The system follows the user's light or dark preference
by default and allows an in-memory theme change without saving browser state.

This system explicitly rejects AWS-console sprawl, generic card-grid
dashboards, generic AI-tool chrome, compliance-certificate theater, and
consumer onboarding that hides technical boundaries.

**Key Characteristics:**

- Compact, structured, and evidence-led.
- Familiar controls with no invented interaction vocabulary.
- Restrained color, with status carried by text and icons as well as hue.
- Responsive state transitions with no decorative choreography.
- Explicit limitations and integrity state adjacent to every result.

## Colors

The palette uses near-neutral surfaces and one deep teal product accent.
Crimson and ochre are semantic signals, never decoration.

### Primary

- **Forensic Teal** (`forensic-teal`): Primary actions, current workflow state,
  selected navigation, links, and positive completion. It occupies no more
  than 10 percent of a screen.
- **Forensic Teal Hover** (`forensic-teal-hover`): Active and hover treatment
  for teal controls, plus readable teal text on pale teal surfaces.
- **Forensic Teal Soft** (`forensic-teal-soft`): Restrained backgrounds for
  selected rows and successful status labels.

### Neutral

- **Light Canvas and Surfaces** (`light-canvas`, `light-surface`,
  `light-surface-muted`): Three flat layers for the application shell,
  primary work area, and grouped secondary content.
- **Light Ink and Dividers** (`light-ink`, `light-ink-muted`, `light-border`):
  High-contrast primary text, secondary text, and structural separators.
- **Dark Canvas and Surfaces** (`dark-canvas`, `dark-surface`,
  `dark-surface-muted`): The corresponding dark-theme layers, tinted only
  enough to preserve the teal family.
- **Dark Ink and Dividers** (`dark-ink`, `dark-ink-muted`, `dark-border`):
  Legible dark-theme text and quiet structural boundaries.

### Semantic

- **Danger Crimson** (`danger-crimson`, `danger-soft`): Reserved for failed,
  invalid, or error states and destructive warnings. Never use it for
  decoration or ordinary emphasis.
- **Warning Ochre** (`warning-ochre`, `warning-soft`): Reserved for incomplete,
  unfinalized, stale, or inconclusive states.

### Named Rules

**The Ten Percent Rule.** Forensic Teal occupies no more than 10 percent of a
screen. Its scarcity identifies action and state.

**The Status Pairing Rule.** Every status combines an icon and explicit text.
Color is never the only carrier of meaning.

## Typography

**Display Font:** Native system sans

**Body Font:** Native system sans

**Label/Mono Font:** Native system monospace

**Character:** One familiar sans family keeps the product quiet and legible.
Monospace is reserved for bounded identifiers, timestamps, paths, and technical
values where character distinction matters.

### Hierarchy

- **Display** (650, 1.75rem, 1.2): One screen title, never a marketing hero.
- **Headline** (650, 1.375rem, 1.3): Major workflow and evidence sections.
- **Title** (650, 1rem, 1.4): Row groups, dialogs, and result direction labels.
- **Body** (400, 0.9375rem, 1.5): Instructions, findings, and limitations,
  capped at 72 characters per line for prose.
- **Label** (600, 0.8125rem, 1 percent tracking): Controls, field names, and
  status labels in sentence case.
- **Mono** (500, 0.8125rem, 1.45): Bounded technical values only.

### Named Rules

**The Evidence Is Readable Rule.** Never reduce a technical value below
0.8125rem or use color contrast as a substitute for typographic hierarchy.

**The Sentence Case Rule.** Buttons, labels, navigation, and status text use
sentence case. All-caps copy is forbidden.

## Elevation

The console is flat by default. Depth comes from tonal layering and structural
dividers, not stacks of floating cards. A low structural shadow
(`0 2px 6px rgb(8 23 26 / 0.12)`) is permitted only for temporary popovers. A
modal may use the overlay shadow
(`0 4px 8px rgb(8 23 26 / 0.18)`) without a decorative border.

### Named Rules

**The Flat By Default Rule.** Work surfaces remain flat at rest. Shadows exist
only to explain a temporary layer above the current task.

**The One Boundary Rule.** A component may use a divider, tonal contrast, or a
shadow to establish its boundary, never all three.

## Components

Components are refined and restrained. Every interactive component has
default, hover, focus-visible, active, disabled, loading, and error behavior
where that state is meaningful.

### Buttons

- **Shape:** Gently squared corners (`6px`) with a consistent `40px` height.
- **Primary:** Forensic Teal with light text and `10px 14px` padding. Use one
  primary action per decision area.
- **Hover / Focus:** Hover darkens to Forensic Teal Hover over `160ms` using
  `cubic-bezier(0.16, 1, 0.3, 1)`. Focus uses a visible `2px` outline with a
  `2px` offset. Active state translates at most `1px`.
- **Secondary / Ghost:** Secondary buttons use a flat surface and structural
  border. Ghost actions appear only in compact navigation or row utilities.

### Chips

- **Style:** Pale semantic fill, readable semantic text, an icon, and a
  `999px` radius. Chips report state and never behave as unlabeled controls.
- **State:** `PASS`, `FAIL`, `ERROR`, `INCONCLUSIVE`, `SKIPPED`, verified,
  unfinalized, and invalid always appear as explicit words.

### Cards / Containers

- **Corner Style:** Quietly rounded (`10px` for groups, `12px` for dialogs).
- **Background:** One surface token appropriate to the active theme.
- **Shadow Strategy:** Flat at rest, following the Flat By Default Rule.
- **Border:** A single structural divider when tonal layering is insufficient.
- **Internal Padding:** `16px` on compact work areas and `24px` on major
  sections.

### Inputs / Fields

- **Style:** Native file controls and text fields use a `1px` structural border,
  flat surface, `6px` radius, and at least `40px` height.
- **Focus:** A visible `2px` Forensic Teal outline with `2px` offset. Browser
  focus is never removed without this replacement.
- **Error / Disabled:** Error text sits next to the field and is announced
  programmatically. Disabled state remains readable and never communicates
  readiness.

### Navigation

The desktop workflow uses a compact left rail and a persistent top context
line. Current location uses Forensic Teal plus text weight, not a filled
decorative block. At `940px` and below, the rail becomes an ordered horizontal
workflow summary and content remains in document order. No navigation item
depends on hover to expose its name.

### Evidence State Row

This signature row aligns integrity icon, status, run label, collection time,
and the next safe action without turning each value into a card. Verified
paths appear only after manifest validation. Invalid or unfinalized rows expose
their stable classification and no artifact content.

State changes use `160ms` for direct control feedback and `200ms` for panel
transitions, both with `cubic-bezier(0.16, 1, 0.3, 1)`. Reduced-motion mode
removes translation and completes nonessential transitions immediately.

## Do's and Don'ts

### Do:

- **Do** keep configuration, readiness, execution, results, and evidence in one
  visible workflow order.
- **Do** use Forensic Teal only for primary action, current selection, links,
  and positive state.
- **Do** pair every status color with a distinct icon and explicit text.
- **Do** preserve at least the WCAG 2.2 AA `24px` target minimum; primary
  workflow controls use a `40px` minimum height and compact row utilities remain
  visibly separated.
- **Do** retain keyboard order, visible focus, semantic landmarks, and
  meaningful headings from 320 pixels through 200 percent zoom.
- **Do** reveal sensitive configuration only after an explicit action, then
  conceal it after 30 seconds, navigation, tab loss, configuration replacement,
  or operator request.

### Don't:

- **Don't** recreate AWS-console sprawl with many unrelated services, nested
  navigation, and competing panels.
- **Don't** use generic card-grid dashboards and hero metrics that obscure the
  actual workflow.
- **Don't** use generic AI-tool chrome such as purple gradients, neon accents,
  glassmorphism, and decorative model imagery.
- **Don't** use compliance-certificate theater or copy that implies one passing
  run establishes compliance.
- **Don't** use consumer onboarding that hides technical boundaries or turns
  exact authorization into a one-click promise.
- **Don't** add decorative motion, page-load choreography, gradient text,
  colored side-stripe borders, or wide ghost-card shadows.
- **Don't** expose sensitive values through tooltips, truncated text, copy
  controls, browser storage, or visual debug output.

## Implementation Scan

The implemented React console was scanned after completion against
`ui/src/App.tsx`, `ui/src/components.tsx`, and `ui/src/styles.css`. The scan
reported no gradient text, decorative side stripes, glassmorphism, oversized
rounding, repeating stripe backgrounds, or other prohibited interface
patterns.

The shipped responsive contract uses breakpoints at `940px`, `700px`, and
`440px`, with a hard `320px` minimum layout. Light, dark, and system themes use
only local CSS tokens. Motion is limited to direct control feedback and bounded
progress indicators; the reduced-motion query collapses all animation and
transition durations. File controls retain a visible focus ring through their
styled labels, and statuses pair fixed text with iconography.
