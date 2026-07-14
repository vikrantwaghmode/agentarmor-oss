## 2024-07-14 - Custom toggles require semantic button attributes
**Learning:** Custom toggle switches built with `<div>` elements are not keyboard focusable or announced correctly by screen readers.
**Action:** Always use `<button type="button">` with `role="switch"` and `aria-checked` for custom toggles to ensure they are accessible. Added a `:focus-visible` style to ensure the focus state is clearly visible.
