# AKFES interaction design foundations

AKFES uses research as a constraint, not as decoration. Classic HCI findings
describe tendencies under particular experimental conditions; they are not
universal formulas. Product decisions must still be checked with real users,
assistive technology, different languages, and actual devices.

## 1. Fast, reliable targets

Fitts showed that aimed movement time varies with target distance and size.
Parhi, Karlson, and Bederson later found that one-handed thumb use benefited
from targets around 9.2–9.6 mm in their mobile-device tasks.

Applied in AKFES:

- frequent chat-header actions sit together at the nearest stable edge;
- mobile interactive targets are at least 44 CSS px high;
- send, attach, back, and conversation rows receive the largest touch areas;
- icon glyphs can remain visually light while their hit areas stay generous.

Sources: [Fitts (1954)](https://www2.psychology.uiowa.edu/faculty/mordkoff/infoproc/pdfs/Fitts%201954.pdf),
[Parhi, Karlson & Bederson (2006)](https://doi.org/10.1145/1152215.1152260).

## 2. Bounded choice and progressive disclosure

Hyman found that discriminatory response time increased with the information
carried by the set of possible stimuli. AKFES does not interpret this as a
fixed maximum number of buttons. Instead, it avoids presenting unrelated
actions as equal choices.

Applied in AKFES:

- the header exposes only call, search, and conversation settings;
- account and security actions are grouped under named menu sections;
- secret-message and Arduino controls remain behind an explicit security
  options disclosure;
- advanced trust detail is opened from one compact status strip.

Source: [Hyman (1953)](https://www2.psychology.uiowa.edu/faculty/mordkoff/InfoProc/pdfs/Hyman%201953.pdf).

## 3. Calm awareness instead of forced interruption

Iqbal and Horvitz found that lightweight notification information can support
awareness without requiring an immediate context switch. Their task-recovery
research also found substantial recovery costs after interruptions and points
to preserving visible task context.

Applied in AKFES:

- incoming messages update unread counts and conversation previews without
  stealing keyboard focus or opening the conversation;
- operating-system notifications are emitted only while the document is hidden;
- status toasts use a polite live region and are dismissible;
- per-conversation drafts and the last open conversation are restored for the
  current browser session; secret plaintext is never included in that context;
- typing and presence are peripheral cues rather than modal prompts.

Sources: [Iqbal & Horvitz, Notifications and Awareness (2010)](https://www.erichorvitz.com/shamsi_iqbal-eric_horvitz_cscw_2010.pdf),
[Iqbal & Horvitz, Disruption and Recovery (2007)](https://www.microsoft.com/en-us/research/wp-content/uploads/2016/11/CHI_2007_Iqbal_Horvitz-1.pdf).

## 4. Clarity over visual density

Baughan and colleagues found that higher visual complexity harmed search
efficiency and information recall in their website experiments. AKFES therefore
uses one dominant work area, a quiet rail, limited simultaneous banners, and
consistent action locations instead of ornamental panels.

Applied in AKFES:

- messages and the composer share a centered readable width;
- trust state is one line until expanded;
- the mobile header hides the lower-priority video shortcut while preserving it
  on wider displays;
- color conveys state but never replaces text or accessible labels.

Source: [Baughan et al. (CHI 2020)](https://doi.org/10.1145/3313831.3376849).

## 5. Accessibility is a baseline

WCAG 2.2 specifies a 24×24 CSS px minimum target with exceptions and recommends
larger targets for important actions. AKFES aims for the enhanced 44 px target
on mobile, provides a visible two-pixel keyboard focus perimeter, respects
reduced-motion preferences, and strengthens borders when increased contrast is
requested.

Sources: [WCAG 2.2 target size](https://www.w3.org/WAI/WCAG22/Understanding/target-size-minimum),
[focus appearance](https://www.w3.org/WAI/WCAG22/Understanding/focus-appearance),
[animation from interactions](https://www.w3.org/WAI/WCAG22/Understanding/animation-from-interactions).
