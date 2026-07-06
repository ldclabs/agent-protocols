---
version: alpha
name: Agent Protocols — Celadon & Seal
description: Design system for the Agent Protocols docs and site. Celadon stoneware surfaces, pine-ink text, and one cinnabar seal reserved for moments of cryptographic assurance. Flat, archival, provider-neutral.
colors:
  # celadon surfaces — the glazed desk
  canvas: "#EFF1EA" # page background (celadon stone)
  surface: "#FFFFFF" # cards, panels
  paper: "#FDFEFB" # secondary cards, warm white
  glaze: "#E6EAE0" # insets, code blocks, table headers
  # pine ink — the specification text
  ink: "#101D17" # primary text & structure (green-black)
  ink-hover: "#24332B"
  ink-soft: "#39473D" # long-form body
  stone: "#5B6B5E" # secondary text
  sage: "#8AA08E" # decorative graphics & diagram fills only, never text
  # cinnabar seal — verification & interaction
  seal: "#C13527" # links, verification accents; text-capable on all light surfaces
  seal-deep: "#A32A1F" # hover, pressed, small text on seal-soft
  seal-soft: "#F5E0D8" # seal tint background
  seal-line: "#E7C4B6"
  # admonition & status hues
  moss: "#2F6B4F" # success / verified
  moss-soft: "#DFEADF"
  moss-line: "#BFD6C4"
  amber: "#8A671C" # caution icons & borders
  amber-ink: "#6E5316" # caution text on amber-soft
  amber-soft: "#F0E6C8"
  amber-line: "#DFD0A4"
  rust: "#8E3B2F" # danger / breaking changes
  rust-soft: "#F0DED6"
  rust-line: "#DEC3B8"
  steel: "#46648A" # notes / informational
  steel-soft: "#E1E8F0"
  steel-line: "#C3D0E0"
  # hairlines & selection
  line-hair: "#101D1712" # ink 7%
  line-soft: "#101D171F" # ink 12%
  line-strong: "#101D1738" # ink 22%
  selection: "#DCE5D8"
typography:
  display:
    fontFamily: IBM Plex Sans
    fontSize: 34px
    fontWeight: 500
    lineHeight: 1.2
    letterSpacing: "-0.01em"
  headline-lg:
    fontFamily: IBM Plex Sans
    fontSize: 28px
    fontWeight: 500
    lineHeight: 1.25
    letterSpacing: "-0.01em"
  headline-md:
    fontFamily: IBM Plex Sans
    fontSize: 22px
    fontWeight: 500
    lineHeight: 1.3
  headline-sm:
    fontFamily: IBM Plex Sans
    fontSize: 18px
    fontWeight: 500
    lineHeight: 1.35
  body-lg:
    fontFamily: IBM Plex Sans
    fontSize: 17px
    fontWeight: 400
    lineHeight: 1.7
  body-md:
    fontFamily: IBM Plex Sans
    fontSize: 16px
    fontWeight: 400
    lineHeight: 1.65
  body-sm:
    fontFamily: IBM Plex Sans
    fontSize: 14px
    fontWeight: 400
    lineHeight: 1.6
  spec-body:
    fontFamily: IBM Plex Serif
    fontSize: 17px
    fontWeight: 400
    lineHeight: 1.75
  label-md:
    fontFamily: IBM Plex Sans
    fontSize: 12px
    fontWeight: 500
    lineHeight: 1.2
    letterSpacing: "0.06em"
  label-sm:
    fontFamily: IBM Plex Sans
    fontSize: 11px
    fontWeight: 500
    lineHeight: 1.1
    letterSpacing: "0.08em"
  code-block:
    fontFamily: IBM Plex Mono
    fontSize: 14px
    fontWeight: 400
    lineHeight: 1.6
  code-inline:
    fontFamily: IBM Plex Mono
    fontSize: 14px
    fontWeight: 400
    lineHeight: 1
  keyword:
    fontFamily: IBM Plex Mono
    fontSize: 13px
    fontWeight: 500
    lineHeight: 1
    letterSpacing: "0.02em"
  data-sm:
    fontFamily: IBM Plex Mono
    fontSize: 12px
    fontWeight: 400
    lineHeight: 1.4
spacing:
  base: 4px
  xs: 4px
  sm: 8px
  md: 16px
  lg: 24px
  xl: 32px
  2xl: 48px
  3xl: 64px
  gutter: 24px
  content: 800px
  sidebar: 260px
  container: 1200px
rounded:
  sm: 4px
  md: 6px
  lg: 8px
  xl: 12px
  full: 9999px
components:
  link:
    textColor: "{colors.seal}"
  link-hover:
    textColor: "{colors.seal-deep}"
  button-primary:
    backgroundColor: "{colors.ink}"
    textColor: "{colors.canvas}"
    typography: "{typography.body-sm}"
    rounded: "{rounded.lg}"
    height: 40px
    padding: 16px
  button-primary-hover:
    backgroundColor: "{colors.ink-hover}"
  button-quiet:
    backgroundColor: transparent
    textColor: "{colors.ink}"
    borderColor: "{colors.line-strong}"
    typography: "{typography.body-sm}"
    rounded: "{rounded.lg}"
    height: 40px
    padding: 16px
  code-inline:
    backgroundColor: "{colors.glaze}"
    textColor: "{colors.ink}"
    typography: "{typography.code-inline}"
    rounded: "{rounded.sm}"
    padding: 3px
  code-block:
    backgroundColor: "{colors.glaze}"
    textColor: "{colors.ink}"
    borderColor: "{colors.line-soft}"
    typography: "{typography.code-block}"
    rounded: "{rounded.lg}"
    padding: 16px
  seal-stable:
    backgroundColor: "{colors.seal}"
    textColor: "#FFFFFF"
    typography: "{typography.label-md}"
    rounded: "{rounded.sm}"
    padding: 6px
  seal-candidate:
    backgroundColor: "{colors.amber-soft}"
    textColor: "{colors.amber-ink}"
    borderColor: "{colors.amber-line}"
    typography: "{typography.label-md}"
    rounded: "{rounded.sm}"
    padding: 6px
  seal-draft:
    backgroundColor: transparent
    textColor: "{colors.stone}"
    borderColor: "{colors.line-strong}"
    typography: "{typography.label-md}"
    rounded: "{rounded.sm}"
    padding: 6px
  seal-deprecated:
    backgroundColor: "{colors.glaze}"
    textColor: "{colors.stone}"
    typography: "{typography.label-md}"
    rounded: "{rounded.sm}"
    padding: 6px
  admonition-note:
    backgroundColor: "{colors.steel-soft}"
    textColor: "{colors.steel}"
    borderColor: "{colors.steel-line}"
    rounded: "{rounded.lg}"
    padding: 16px
  admonition-warning:
    backgroundColor: "{colors.amber-soft}"
    textColor: "{colors.amber-ink}"
    borderColor: "{colors.amber-line}"
    rounded: "{rounded.lg}"
    padding: 16px
  admonition-danger:
    backgroundColor: "{colors.rust-soft}"
    textColor: "{colors.rust}"
    borderColor: "{colors.rust-line}"
    rounded: "{rounded.lg}"
    padding: 16px
  table-header:
    backgroundColor: "{colors.glaze}"
    textColor: "{colors.ink}"
    typography: "{typography.label-md}"
  tooltip:
    backgroundColor: "{colors.ink}"
    textColor: "{colors.canvas}"
    typography: "{typography.body-sm}"
    rounded: "{rounded.md}"
    padding: 8px
---

# Agent Protocols Design System

> **A protocol is a document. A signature is a seal.**
> The visual language is the scholar's desk (文房): celadon-glazed stoneware for surfaces (青瓷), pine ink for the normative text (墨), and one cinnabar seal (朱印) that appears only where something is signed, verified, or declared stable.

This file governs the documentation site ([docs/index.html](docs/index.html)), spec pages, diagrams, and any future web presence of this repository. Format follows the DESIGN.md spec (YAML front matter = normative tokens; prose = rationale).

## Overview

Agent Protocols is an open, provider-neutral specification repository: four draft protocols for interoperable autonomous agents, maintained bilingually (English canonical, Simplified Chinese in parity). The design must read as a **standards desk, not a startup dashboard** — calm, archival, verifiable, slightly austere. If IETF RFCs had been brushed onto celadon instead of typed on white, they would look like this.

The palette follows the family discipline shared with alink's "Ink Night & Porcelain" system (ldclabs sibling project): **cold surfaces, one warm accent**. Here the temperature is green-stone rather than blue-porcelain, and the single warm accent is not a human dot but a **cinnabar seal** — the mark a document receives when a signature verifies. Everything on the page is cold and mineral except the moments of cryptographic assurance.

Provider neutrality is a design requirement: these protocols are meant to be implemented by many services. The protocol surfaces must never borrow alink's Ember `#F0552E` or its ink-night marketing look — a spec page that looks owned by one provider undermines the spec.

The system is flat: no gradients, no shadows, no glow. Interfaces are documents with seals, not pages with chrome.

## Colors

Palette = celadon (surfaces) + pine ink (text) + cinnabar (the seal) + four muted admonition hues.

- **Celadon family**: `canvas` is the glazed stone page; cards sit on `surface`/`paper`; `glaze` is the recessed tone for code blocks, insets, and table headers. Hierarchy comes from these adjacent tones plus ink hairlines (`line-hair/soft/strong`), never from shadows.
- **Pine ink family**: `ink` is a green-black (hue-matched to the celadon undertone, deliberately distinct from alink's blue-black). `ink-soft` for long-form body, `stone` for secondary text, `sage` for decorative graphics and diagram fills **only** — at ≈2.5:1 it is never a text color.
- **Cinnabar seal**: `seal` is the only warm color in the system. Measured contrast is ≥4.5:1 on every light surface (canvas 4.85, glaze 4.52, paper 5.45, white 5.52), so unlike a typical accent it is **text-capable**: links and inline verification accents may use it freely. What is rationed is the *filled* seal — a solid cinnabar block (the Stable stamp, a "verify" action) appears **at most once per view**, like a real seal pressed once on a page.
- **Admonition hues**: note = `steel`, caution = `amber` (text uses the darkened `amber-ink`), danger/breaking = `rust`, success/verified = `moss`. Each pairs a `-soft` tint with a `-line` border — stamped, not glowing. `rust` (brown-red, borders and admonitions) is kept visually apart from `seal` (vermilion, interaction and status).

**Contrast duties (WCAG AA, measured)**: body and secondary text pass everywhere — `stone` ≥4.6:1 on all surfaces including `glaze`; `ink-soft` ≥8:1. On dark `ink` blocks (footer, tooltip) use `canvas` as the text color (15.2:1) and `sage` for muted lines (6.2:1); `seal` on ink is 3.15:1 — graphic use only, never text on dark.

## Typography

The repository already standardizes on the **IBM Plex** superfamily; the design system keeps it and assigns roles:

- **IBM Plex Sans** — UI, navigation, headings, README-level prose. CJK pairing: Noto Sans SC.
- **IBM Plex Serif** (`spec-body`) — optional long-form register for normative spec prose, giving spec pages an RFC-like document gravity. CJK pairing: Noto Serif SC. Use it for spec body text or not at all on a page — never mix serif and sans body in one document.
- **IBM Plex Mono** — wire formats, code, field names, `did:agent:` identifiers, hashes, timestamps, and **RFC 2119 keywords**: `MUST`, `SHOULD`, `MAY` are set inline in mono 500 (`keyword` token), which makes normative force visually scannable.

Weights are **400 and 500 only** — the current font loading of 600/700 is to be dropped. Hierarchy comes from size, color, and spacing, not boldness. Uppercase micro-labels (`label-*`) always carry 0.06em+ tracking.

## Layout

- **Grid**: 4px base scale; common rhythm 8/16/24/32/48/64.
- **Docs frame**: sidebar 260px + content column max 800px (≈72ch for 16px body), total container 1200px centered; 16–24px page margins on mobile.
- **Spec pages**: generous section spacing (48–64px), anchor-linked headings, sticky table of contents in the sidebar. Diagrams and code blocks share the content column width.
- **Bilingual parity**: layout must tolerate EN/zh-CN text-length differences; labels and stamps size to content, never to fixed widths.

## Elevation & Depth

**No shadows, no blur, no glow.** The current site's glow/pulse keyframes (`ap-pulse`, `ap-chainglow`) are retired. Depth is tonal:

1. `canvas` page → 2. `surface`/`paper` cards → 3. `glaze` recessed blocks → 4. `ink` reversed blocks (footer, tooltip).

Borders step `line-hair` → `line-soft` → `line-strong` with interaction strength. Motion is reserved for meaning: one stamp-press animation on a verification demo is acceptable; decorative floating and pulsing are not.

## Shapes

- Monoline geometry with round caps in all diagrams — when ASCII diagrams from the specs are rendered as SVG, keep single-weight ink strokes, `sage` fills for passive nodes, and `seal` only on the verification/signature node.
- **Stamps are rectangles, not pills**: status seals use `rounded.sm` (4px) near-square corners, echoing a real seal impression (and deliberately distinct from alink's pill chips). Cards use `rounded.xl` (12px), code blocks `rounded.lg` (8px), buttons `rounded.lg`.
- Do not mix sharp (0px) and rounded corners in one view.

## Components

- **Links**: `seal` text, underline with 2px offset; hover deepens to `seal-deep`. Visited stays `seal` — a spec is re-read, not conquered.
- **Buttons**: rare on a docs site. Primary = `ink` fill with `canvas` text; quiet = hairline outline. No seal-filled buttons except a single verification action per view (the one allowed filled seal).
- **Status seals** (protocol maturity, replacing ad-hoc badges): `Draft` = outline stamp in `stone`; `Candidate` = amber stamp; `Stable` = **filled cinnabar stamp** — the one filled seal a page earns; `Deprecated` = glaze stamp with strikethrough label. Version strings inside stamps are mono (`data-sm`).
- **Code**: inline code on `glaze` with `sm` corners; block code on `glaze` with hairline border, `lg` corners, mono 14px. Syntax highlighting stays within the palette: `ink` default, `stone` comments, `moss` strings, `steel` keywords, `seal` reserved for diff-removals/errors.
- **Admonitions**: full hairline border + tint + title in the hue's text variant (`steel` / `amber-ink` / `rust`), body text in `ink-soft`. Title takes an uppercase `label-md` kicker (NOTE / WARNING / BREAKING).
- **Tables**: spec tables use `glaze` header row with `label-md` ink text, `line-hair` row separators, field names in mono, no zebra striping.
- **Tooltips**: `ink` block, `canvas` text, `md` corners.

## Do's and Don'ts

- Do reserve the **filled** seal for verification moments and Stable status — at most one per view; seal-colored text (links, accents) is unrestricted.
- Don't use gradients, shadows, or glow; retire the existing pulse/glow animations.
- Do use only weights 400 and 500; drop the 600/700 font loads.
- Don't set text in `sage` (2.5:1) — secondary text is `stone`, muted-on-dark is `sage` only for graphics.
- Do set identifiers, wire fields, and RFC 2119 keywords in IBM Plex Mono; keywords at weight 500.
- Don't borrow alink brand elements — no Ember `#F0552E`, no ink-night surfaces; the spec stays provider-neutral.
- Do keep diagrams monoline: ink strokes, sage passive fills, seal only on the signature/verification node.
- Do maintain EN/zh-CN parity in any labeled component; never hardcode label widths.
- Don't use pill-shaped status chips — stamps are 4px-corner rectangles here.

## Migration Notes

Deltas from the current `docs/index.html` implementation, in priority order:

1. Background `#f4f1e9` → `canvas #EFF1EA`; text `#1c1a14` → `ink #101D17`; selection → `#DCE5D8`.
2. Retire `ap-pulse` / `ap-chainglow` glow keyframes and all `box-shadow` usage; replace emphasis with `line-strong` borders or `glaze` fills.
3. Replace the multi-hue accent set (oklch blue/green, favicon's blue/orange/magenta dots) with the seal system; protocol cards differentiate by stamp status, not by hue.
4. Font loading: drop 600/700 weights; add IBM Plex Serif only if `spec-body` is adopted.
5. Favicon: retint to celadon tile, ink strokes, single `seal` dot at the apex node.
