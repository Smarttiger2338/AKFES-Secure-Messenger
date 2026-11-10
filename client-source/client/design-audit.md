# Messenger UI audit

Reference: `design-audit/01-before.png`

## High-impact problems found

- The composer controls were allowed to wrap into separate rows. This made the send button render vertically and pushed the Arduino action away from the message field.
- Persistent security status, file state, secret-message controls, notices, and the composer competed for the same vertical space.
- Every account and conversation action was shown at once, creating large button clusters and weak visual hierarchy.
- Raw Web Crypto exceptions were exposed in the interface. The file path also passed an undefined `additionalData` member to AES-GCM instead of omitting it.
- The mobile header did not reserve enough width for its back control, so its label could wrap.

## Implemented direction

- Adopted a compact Telegram-like two-pane structure: stable navigation rail, fixed conversation header, flexible message history, and fixed composer.
- Moved account and conversation actions into contextual menus.
- Kept trust state visible but compact, with details available on demand.
- Grouped secret-message state and PIN unlock into one toolbar immediately above the composer.
- Used a single horizontal composer with an attachment control, flexible message field, and stable send action.
- Added a one-pane mobile layout with an explicit back control and safe composer sizing.
- Replaced raw encryption errors with short, actionable Korean messages.

## Validation references

- Desktop: `design-audit/02-after-desktop.png`
- Mobile breakpoint: `design-audit/03-after-mobile.png`
