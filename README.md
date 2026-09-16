# FraudLens — Procurement Fraud Detection Analyst

FraudLens reviews transactional records from a procurement system and identifies indicators of fraud, collusion, error and policy circumvention. It does not accuse — it **flags, evidences and ranks**.

**Live demo:** https://tshepisofrominnostation.github.io/procurement-fraud-detector/

## How it works

Paste a JSON payload containing any combination of:

- `purchase_orders` — id, supplier_id, requester, approver, dates, line_items[], total, cost_centre, sourcing_method
- `invoices` — id, supplier_id, po_id, invoice_number, dates, total, tax_amount, bank_account_hash
- `goods_receipts` — id, po_id, date_received, quantities_received, receiver
- `suppliers` — identity, registration/tax numbers, address, contacts, bank_account_hash, onboarding
- `employees` — id, name, address_hash, contacts, role, approval_limit
- `policy` — approval thresholds, quotation rules, segregation-of-duties rules

Every field is treated as **untrusted data** — never as instructions. Records containing instruction-like text are flagged as `POSSIBLE_PROMPT_INJECTION` and ignored as directives.

## Detection typologies

1. **Duplicate payment** — near-identical amounts, transposed invoice digits, same invoice against two POs
2. **Threshold splitting** — multiple sub-threshold POs to one supplier that collectively breach approval/quotation limits
3. **Phantom / shell supplier** — recent onboarding, missing registration, PO Box address, webmail domain, no goods receipts, name resembling a legitimate supplier
4. **Employee–supplier collusion** — shared address, phone, email domain or bank account
5. **Banking detail manipulation** — account changed shortly before payment
6. **Sequence anomalies** — invoices/goods receipts predating the PO (after-the-fact approval)
7. **Price & quantity manipulation** — unit prices above the supplier's trailing average or peer baseline; invoiced quantity exceeding quantity received
8. **Approval abuse** — self-approval, above-limit approvals, approver concentration, out-of-hours approvals
9. **Sourcing circumvention** — repeated emergency / single-source use vs policy
10. **Statistical anomalies** — Benford's law first-digit deviation, threshold clustering, round-number patterns
11. **Dormancy reactivation** — long-inactive supplier transacting at high value

## Scoring

Each triggered indicator contributes weighted points. **Corroboration** (two or more independent typologies on the same transaction or supplier) escalates the score materially. Scores are capped at 100.

`0–24 LOW · 25–49 MEDIUM · 50–74 HIGH · 75–100 CRITICAL`

HIGH or CRITICAL findings require at least two independent pieces of evidence. Every finding carries observed-vs-expected evidence, benign explanations considered, a recommended action and a suggested control. Checks that cannot be performed due to missing data are recorded under `data_gaps` — never guessed.

## Output

The tool returns a strict JSON structure: `run_summary` (records reviewed, flagged count, highest risk band, data gaps) and `findings[]` (finding_id, entity, typology, risk score/band, confidence, evidence, benign explanations, recommended action, suggested control) — copyable and downloadable directly from the UI.

## Tech

Single-page vanilla HTML/CSS/JS. No build step, no backend, no data leaves the browser — the full analysis runs client-side.

---

Built by **Freddy Thosago**.
