## 2026-07-20 - Replaced custom div toggles with semantic switch buttons
**Learning:** Custom toggle switches in the frontend (`.sq-toggle`) were previously implemented using `<div>` elements. This breaks keyboard focusability and accessibility since div elements aren't inherently interactive.
**Action:** Always use `<button type="button">` elements with `role="switch"` and `aria-checked` attributes for custom toggle switches to ensure correct semantics, keyboard navigation, and screen reader support.
