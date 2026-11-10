# Design QA

Reference: `design-audit/01-before.png`
Implementation: `design-audit/02-after-desktop.png`, `design-audit/03-after-mobile.png`
Viewport: desktop 1280×720; mobile responsive checks at 390×844 in the in-app browser and 500×844 for the saved capture

## Revision history

### Pass 1

- Restructured the sidebar header, conversation header, security strip, message history, and composer.
- Fixed the vertical send-button regression and made the history the only flexible-height region.
- Added contextual menus and compact secret-message controls.
- Result: mobile back label wrapped at 390 px.

### Pass 2

- Added a non-wrapping minimum width for the mobile back control.
- Verified the message field accepts text, the secret toggle changes the primary action to `비밀 전송`, and the action becomes enabled.
- Opened both contextual menus and confirmed they overlay without shifting the chat or composer.
- Checked the browser console: no warnings or errors.
- Production build completed successfully.

### Pass 3 — presence and receipts

- Added an ephemeral, conversation-scoped typing indicator with automatic expiry and disconnect cleanup.
- Added a durable per-conversation read watermark and a compact `전송됨`/`읽음` state on the latest outgoing message.
- Prevented background tabs and undecryptable incoming messages from producing a false read receipt.
- Verified desktop and 390 px mobile layouts in the in-app browser; browser console contained no warnings or errors.
- Captures: `design-audit/04-presence-desktop.png`, `design-audit/05-presence-mobile.png`.
- Client production build passed. The complete server suite, including the new two-user WebSocket presence/read-receipt test, passed: 8 tests passed.

## Severity review

- P0 blockers: none
- P1 major layout or interaction defects: none
- P2 visible polish defects affecting normal use: none observed in the checked states

final result: passed
