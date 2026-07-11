## 2026-07-11 - Added ARIA labels to icon-only buttons
**Learning:** The proxy dashboard heavily uses icon-only buttons (like ✕ for closing or removing items, and 🔔 for notifications). Without ARIA labels, these buttons are inaccessible to screen readers, preventing users from understanding their function.
**Action:** Always ensure that any button containing only an icon or symbol has an `aria-label` describing its action.
