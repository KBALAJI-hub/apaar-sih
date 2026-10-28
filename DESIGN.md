---
name: ApaarAnvaya
description: A restrained dark workspace for academic records, compliance, and credential verification.
colors:
  midnight: "#0b111b"
  raised: "#101923"
  panel: "#121b28"
  panel-soft: "#1a2838"
  panel-hover: "#213247"
  border: "rgba(169, 189, 213, 0.13)"
  border-bright: "rgba(169, 189, 213, 0.23)"
  text-primary: "#edf2f7"
  text-secondary: "#c0cad6"
  text-muted: "#96a4b5"
  signal-blue: "#6997c8"
  signal-teal: "#68ad9f"
  signal-amber: "#c5a165"
  signal-red: "#c97982"
typography:
  display:
    fontFamily: "IBM Plex Sans, sans-serif"
    fontSize: "clamp(40px, 4.5vw, 56px)"
    fontWeight: 750
    lineHeight: 1.08
    letterSpacing: "-0.04em"
  title:
    fontFamily: "IBM Plex Sans, sans-serif"
    fontSize: "clamp(26px, 3vw, 34px)"
    fontWeight: 750
    lineHeight: 1.25
    letterSpacing: "-0.035em"
  body:
    fontFamily: "IBM Plex Sans, ui-sans-serif, system-ui, sans-serif"
    fontSize: "16px"
    fontWeight: 400
    lineHeight: 1.6
  label:
    fontFamily: "IBM Plex Sans, ui-sans-serif, system-ui, sans-serif"
    fontSize: "12px"
    fontWeight: 700
    letterSpacing: "0.02em"
  data:
    fontFamily: "IBM Plex Mono, Consolas, monospace"
    fontSize: "12px"
    fontWeight: 400
rounded:
  sm: "8px"
  md: "10px"
  lg: "15px"
  xl: "18px"
  pill: "999px"
spacing:
  xs: "8px"
  sm: "12px"
  md: "16px"
  lg: "24px"
  xl: "32px"
components:
  button-primary:
    backgroundColor: "#315f92"
    textColor: "#f7fbff"
    typography: "{typography.label}"
    rounded: "{rounded.md}"
    padding: "0 16px"
    height: "44px"
  button-secondary:
    backgroundColor: "rgba(255,255,255,0.025)"
    textColor: "#c4d3e6"
    typography: "{typography.label}"
    rounded: "{rounded.md}"
    padding: "0 16px"
    height: "43px"
  input-default:
    backgroundColor: "#0a1018"
    textColor: "{colors.text-primary}"
    typography: "{typography.body}"
    rounded: "9px"
    padding: "0 12px"
    height: "43px"
  surface-card:
    backgroundColor: "{colors.panel}"
    textColor: "{colors.text-primary}"
    rounded: "{rounded.lg}"
    padding: "20px 21px"
  nav-item:
    backgroundColor: "rgba(105,151,200,0.16)"
    textColor: "#dceaff"
    typography: "{typography.body}"
    rounded: "{rounded.md}"
    padding: "0 12px"
    height: "43px"
  status-chip:
    backgroundColor: "rgba(105,151,200,0.11)"
    textColor: "#a4c6e8"
    typography: "{typography.label}"
    rounded: "{rounded.pill}"
    padding: "4px 9px"
---

# Design System: ApaarAnvaya

## Overview

**Creative North Star: "The Verifiable Workspace"**

ApaarAnvaya's web UI is a dark, information-dense workspace for reviewing academic records and their trust signals. Deep blue-gray surfaces carry the working content; restrained blue and teal accents identify navigation, actions, and integrity cues, while amber and red distinguish attention states. The visual voice is precise and operational rather than ornamental.

The shared authenticated shell anchors desktop screens with a persistent role-based sidebar and a sticky workspace header. Panels, tables, filters, and compact labels keep dashboards and review workflows scannable. The public home and sign-in surfaces use the same dark foundation with a more open split composition, but remain part of the same interface family.

**Key Characteristics:**
- Dark, layered blue-gray surfaces with soft borders.
- IBM Plex Sans for headings and interface copy, with IBM Plex Mono for hashes and identifiers.
- Blue and teal actions with amber/red status signaling.
- Compact, role-oriented navigation and data presentation.

## Colors

The palette pairs near-black navy surfaces and cool pale text with a restrained blue action color, desaturated teal integrity cues, and muted amber/red status colors.

### Primary
- **Signal Blue** (`{colors.signal-blue}`): Primary links, selected navigation, actions, and verification emphasis. Use its lighter text tint for links and a deeper blue surface for filled actions.

### Secondary
- **Signal Teal** (`{colors.signal-teal}`): Integrity and protected-workspace cues, with occasional success-state use.

### Tertiary
- **Signal Amber** (`{colors.signal-amber}`): Demo/live indicators and warning or near-limit states.
- **Signal Red** (`{colors.signal-red}`): High-severity flags and over-limit/error states.

### Neutral
- **Midnight** (`{colors.midnight}`) and **Raised** (`{colors.raised}`): Page background and slightly lifted shell surfaces.
- **Panel** (`{colors.panel}`), **Panel Soft** (`{colors.panel-soft}`), and **Panel Hover** (`{colors.panel-hover}`): Cards, controls, and interactive surface steps.
- **Border** (`{colors.border}`) and **Bright Border** (`{colors.border-bright}`): Quiet panel divisions and stronger control outlines.
- **Primary Text** (`{colors.text-primary}`), **Secondary Text** (`{colors.text-secondary}`), and **Muted Text** (`{colors.text-muted}`): Main reading, supporting data, and secondary labels.

**The Signal-Color Rule.** Keep blue for actions and selection, teal for integrity and success, and reserve muted amber and red for warning and error states. Use text labels and chart context alongside color.

## Typography

**Display Font:** IBM Plex Sans (with a sans-serif fallback)
**Body Font:** IBM Plex Sans (with ui-sans-serif and system-ui fallbacks)
**Label/Mono Font:** IBM Plex Sans for labels; IBM Plex Mono for hashes and compact record identifiers.

**Character:** IBM Plex Sans brings a humanist, technical voice suited to public infrastructure: distinctive in headings, calm in operational copy, and legible in dense data. IBM Plex Mono is reserved for hashes and measured identifiers.

### Hierarchy
- **Display** (750, responsive 40–56px, 1.08 line-height): Public landing headline.
- **Headline** (700–750, responsive 26–34px, 1.25 line-height): Page headings and primary screen titles.
- **Title** (600–800, commonly 16–22px): Card headings and secondary dashboard group titles.
- **Body** (400, 16px, 1.6 line-height): Default interface copy and record descriptions; dense supporting descriptions may use 14px.
- **Label** (600–700, 12–13px): Metric names, table headings, workspace context, and compact metadata.
- **Data** (400, 12px): Hashes and technical identifiers, with a Consolas/monospace fallback.

The shared small-text utility floor is 13px, with 12px reserved for purpose-built labels and technical values. Avoid shrinking essential instructions or record status text below this scale.

**The Role-Separation Rule.** Use IBM Plex Sans for both hierarchy and interface reading; reserve IBM Plex Mono for values that are genuinely technical.

## Layout

Authenticated desktop screens use a two-column shell: a 252px sticky sidebar beside a flexible content column. At 1050px the sidebar narrows to 220px; at 760px the shell becomes a single column and navigation becomes a horizontally scrollable row. The compact 480px treatment reduces page gutters and hides the demo indicator in the workspace header.

The main content is centered with a 1600px maximum width and responsive horizontal/vertical padding (`clamp(22px, 4vw, 58px)` across the shell; main content uses `clamp(24px, 4vw, 52px)` vertically). Repeated spacing clusters around 8, 12, 16, 24, and 32px. Dashboards use responsive card grids; record tables preserve a wide minimum width and scroll horizontally rather than compressing columns past legibility.

The public landing page leads with a wider copy-and-action column beside a supporting network illustration, then presents its three role paths as open, top-ruled columns rather than nested cards. At 851px the hero tightens to a balanced split and the role paths reflow into compact rows; at 600px the hero and role paths stack, and below 480px the decorative illustration is shortened and its labels are hidden to keep the primary action close to the first viewport.

**The Shell-First Rule.** Keep authenticated workflows inside the shared sidebar/header frame; at narrow widths, move navigation above content and allow it to scroll horizontally.

## Elevation & Depth

Depth comes primarily from stepped dark surfaces and fine cool borders, with a restrained panel shadow for separation. The shared panel shadow is `0 10px 28px rgba(0, 0, 0, 0.17)`; stronger sign-in-card shadowing is a local treatment, not the default for every surface. The source disables the decorative ambient aura and several earlier animations in its final stylesheet section, so the system should read as calm and static at rest.

### Shadow Vocabulary
- **Panel separation** (`0 10px 28px rgba(0, 0, 0, 0.17)`): Shared cards, metric surfaces, and review panels.
- **Authentication focus** (`0 28px 80px rgba(0,0,0,.35)`): Sign-in card only, paired with a subtle inset highlight.

**The Tonal-Layer Rule.** Use panel tone and a quiet border to establish grouping first; keep shadows soft and avoid using elevation as the only separator.

## Shapes

Most controls use gently rounded corners, while information panels have a broader radius and status chips use a full pill. Common radii range from 8–18px; the primary shared surface panel is 15px, compact metric cards settle at 12px, and status chips use a 999px radius. Borders are thin and low-contrast, becoming slightly brighter on inputs or interactive states. Data tables remain rectangular within the rounded outer container.

## Components

### Buttons
- **Character:** Compact, confident, and action-oriented.
- **Primary:** Blue fill, near-white label, 43–44px height, and 16px horizontal padding; the sign-in action uses a subtle blue shadow.
- **Secondary:** Translucent dark fill with a brightened cool border and pale blue text.
- **Hover / Focus:** Actions brighten or shift slightly; keyboard focus uses a visible 2px teal outline with a 3px offset.

### Chips
- **Style:** Compact pill with a thin semantic border, tinted dark fill, and strongly readable label.
- **State:** High severity uses muted red, medium uses amber, and low uses blue; status meaning must remain visible in text as well as color.

### Cards / Containers
- **Corner Style:** Broad but restrained rounding (typically 12–15px; authentication card 18px).
- **Background:** Solid or lightly graduated deep blue-gray panels, depending on the surface.
- **Shadow Strategy:** Shared soft panel shadow; rely on tonal contrast and fine borders for most grouping.
- **Border:** Subtle cool translucent line.
- **Internal Padding:** Common panel padding is responsive 20–32px; compact metrics use about 20px.

### Inputs / Fields
- **Style:** Dark inset field, cool border, 9px rounding, and compact 43px height.
- **Focus:** Blue border shift and a soft blue focus glow; keyboard focus also receives the shared teal outline.
- **Error / Disabled:** Error messaging uses a restrained red-tinted panel; disabled buttons use a not-allowed cursor.

### Navigation
- Desktop navigation is stacked in the persistent sidebar with 43px minimum link height, 10px corners, muted labels, and blue-tinted current-page fill.
- Hover adds a quiet surface and border change. On mobile, navigation moves above the workspace and becomes horizontally scrollable; the sidebar's supporting account and security blocks are hidden.

### Data Tables
Table headings are compact uppercase labels with tracked lettering; rows use quiet separators and a subtle hover surface. Keep identifiers monospace where they are identity or machine values, and preserve horizontal scrolling for wide student records.

### Audit Events
Audit entries use a compact timeline with a connecting rule, round event node, rounded panel, and distinct monospace hash values. Integrity state is communicated through a text result panel as well as color.

## Do's and Don'ts

### Do:
- **Do** use the dark blue-gray panel sequence as the foundation for authenticated and public surfaces.
- **Do** reserve semantic color accents for actions, integrity cues, and severity states.
- **Do** preserve visible keyboard focus and the reduced-motion treatment present in the stylesheet.
- **Do** keep data tables horizontally scrollable when their columns cannot fit safely.

### Don't:
- **Don't** use bright warning colors as neutral decoration; keep amber and red tied to status meaning.
- **Don't** flatten layered panels into one undifferentiated background; borders and tonal steps carry hierarchy.
- **Don't** assign a shadow to every element; the shared shadow belongs to panel-like surfaces.
