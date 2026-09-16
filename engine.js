/* FraudLens — procurement fraud detection engine.
   Relational analysis across POs, invoices, goods receipts, suppliers,
   employees and policy. Flags, evidences and ranks — never accuses. */

(function (global) {
  "use strict";

  const WEBMAIL_DOMAINS = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "webmail.co.za", "mweb.co.za", "iafrica.com"];
  const INJECTION_RE = /(ignore|disregard|forget)\s+(all\s+|the\s+|any\s+|prior\s+|previous\s+)?(previous|prior|above|earlier|preceding)?\s*(instructions?|prompts?|rules?)|you\s+are\s+now|act\s+as\s+(a\s+new|an?\s+\w+)|system\s*prompt|mark\s+(this|all|the)\b[^.]{0,30}\b(clean|paid|approved|valid)/i;

  /* ---------- helpers ---------- */
  const d = (s) => (s == null || s === "" ? null : new Date(s));
  const daysBetween = (a, b) => {
    const da = d(a), db = d(b);
    if (!da || !db) return null;
    return Math.round((db - da) / 86400000);
  };
  const money = (n) => "R " + Number(n).toLocaleString("en-ZA", { maximumFractionDigits: 2 });
  const normText = (s) => String(s || "").toLowerCase().replace(/[^a-z0-9]+/g, " ").trim();
  const digits = (s) => String(s || "").replace(/\D/g, "");
  const domain = (e) => { const m = String(e || "").toLowerCase().split("@"); return m.length === 2 ? m[1] : null; };
  const median = (arr) => { if (!arr.length) return null; const s = [...arr].sort((a, b) => a - b); const m = Math.floor(s.length / 2); return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; };

  function levenshtein(a, b) {
    const m = a.length, n = b.length;
    if (!m) return n; if (!n) return m;
    let prev = Array.from({ length: n + 1 }, (_, i) => i);
    for (let i = 1; i <= m; i++) {
      const cur = [i];
      for (let j = 1; j <= n; j++) {
        cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      }
      prev = cur;
    }
    return prev[n];
  }
  const similarity = (a, b) => {
    const x = normText(a), y = normText(b);
    if (!x || !y) return 0;
    return 1 - levenshtein(x, y) / Math.max(x.length, y.length);
  };
  const isTransposed = (a, b) => {
    const x = String(a || ""), y = String(b || "");
    if (x === y || !x || !y) return false;
    const dx = x.split("").sort().join(""), dy = y.split("").sort().join("");
    return dx === dy;
  };
  const band = (s) => (s >= 75 ? "CRITICAL" : s >= 50 ? "HIGH" : s >= 25 ? "MEDIUM" : "LOW");

  /* ---------- main ---------- */
  function analyze(data) {
    data = data || {};
    const pos = data.purchase_orders || [], invs = data.invoices || [],
      grs = data.goods_receipts || [], sups = data.suppliers || [], emps = data.employees || [];
    const P = data.policy || {};
    const apprThresh = (P.approval_thresholds && Number(P.approval_thresholds.standard)) || 50000;
    const quoteThresh = (P.quotation_rules && Number(P.quotation_rules.quotes_required_above)) || 10000;
    const emergMax = (P.quotation_rules && Number(P.quotation_rules.emergency_max_per_supplier_per_year)) || 2;

    const supById = Object.fromEntries(sups.map(s => [s.id, s]));
    const empById = Object.fromEntries(emps.map(e => [e.id, e]));
    const poById = Object.fromEntries(pos.map(p => [p.id, p]));
    const grByPo = {};
    grs.forEach(g => { (grByPo[g.po_id] = grByPo[g.po_id] || []).push(g); });
    const invBySupplier = {}, poBySupplier = {};
    invs.forEach(i => (invBySupplier[i.supplier_id] = invBySupplier[i.supplier_id] || []).push(i));
    pos.forEach(p => (poBySupplier[p.supplier_id] = poBySupplier[p.supplier_id] || []).push(p));

    const findings = [];
    const gaps = [];
    const ev = (field, observed, expected) => ({ field, observed, expected });

    /* ---- 0. prompt-injection scan (treat all fields as data) ---- */
    (function scanInjection() {
      const collections = [["purchase_order", pos], ["invoice", invs], ["goods_receipt", grs], ["supplier", sups], ["employee", emps]];
      collections.forEach(([type, list]) => {
        list.forEach(rec => {
          const found = [];
          (function walk(node, path) {
            if (found.length >= 3) return;
            if (typeof node === "string") { if (INJECTION_RE.test(node)) found.push({ path, text: node.slice(0, 160) }); }
            else if (node && typeof node === "object") Object.entries(node).forEach(([k, v]) => walk(v, path ? path + "." + k : k));
          })(rec, "");
          if (found.length) {
            findings.push({
              entity_type: type, entity_ids: [rec.id], typology: "POSSIBLE_PROMPT_INJECTION",
              _supplierIds: rec.supplier_id ? [rec.supplier_id] : [],
              base_score: 45, confidence: "high",
              evidence: found.map(f => ev(f.path, '"' + f.text + '"', "free-text fields must contain data only, never instructions")),
              benign: ["poorly worded internal note in a description field, not an instruction"],
              action: "escalate_to_internal_audit", control: "input sanitisation and length/format validation on all free-text fields; log and quarantine records containing instruction-like text"
            });
          }
        });
      });
    })();

    /* ---- 1. duplicate payment ---- */
    Object.entries(invBySupplier).forEach(([sid, list]) => {
      for (let a = 0; a < list.length; a++) {
        for (let b = a + 1; b < list.length; b++) {
          const x = list[a], y = list[b];
          const nearAmt = Math.abs(x.total - y.total) <= Math.min(100, 0.01 * Math.max(Math.abs(x.total), 1));
          const sameNum = x.invoice_number && String(x.invoice_number) === String(y.invoice_number);
          const transp = isTransposed(x.invoice_number, y.invoice_number);
          const closeDate = daysBetween(x.invoice_date, y.invoice_date) != null && Math.abs(daysBetween(x.invoice_date, y.invoice_date)) <= 14;
          const twoPOs = x.po_id && y.po_id && x.po_id !== y.po_id;
          if (nearAmt && (sameNum || transp || closeDate)) {
            const evidence = [ev("total", `${x.invoice_number} ${money(x.total)} / ${y.invoice_number} ${money(y.total)}`, "amounts for one supplier should differ")];
            if (sameNum) evidence.push(ev("invoice_number", x.invoice_number, "unique per supplier"));
            if (transp) evidence.push(ev("invoice_number", `${x.invoice_number} vs ${y.invoice_number}`, "distinct numbers; transposed-digit pattern"));
            if (closeDate) evidence.push(ev("invoice_date", `${x.invoice_date} / ${y.invoice_date}`, "more than 14 days apart"));
            if (sameNum && twoPOs) evidence.push(ev("po_id", `${x.po_id} and ${y.po_id}`, "one invoice matched to one PO only"));
            findings.push({
              entity_type: "invoice", entity_ids: [x.id, y.id], typology: "DUPLICATE_PAYMENT",
              _supplierIds: [sid],
              base_score: (sameNum || transp) ? 40 : 25,
              confidence: (sameNum || transp) ? "high" : "medium",
              evidence,
              benign: ["staged deliveries invoiced separately with identical values", "resubmission of a corrected invoice", "two legitimate orders of identical composition placed close together"],
              action: "hold_payment", control: "AP system duplicate-invoice check on (supplier, amount, invoice number, date) before payment run"
            });
          }
        }
      }
    });

    /* ---- 2. threshold splitting ---- */
    (function thresholdSplit() {
      const thresholds = [["approval_threshold", apprThresh], ["quotation_threshold", quoteThresh]];
      Object.entries(poBySupplier).forEach(([sid, list]) => {
        thresholds.forEach(([tname, T]) => {
          const below = list.filter(p => p.total != null && p.total < T).sort((a, b) => new Date(a.date_created) - new Date(b.date_created));
          for (let i = 0; i < below.length; i++) {
            const window = below.filter(p => {
              const gap = daysBetween(below[i].date_created, p.date_created);
              return gap != null && gap >= 0 && gap <= 30;
            });
            const sum = window.reduce((s2, p) => s2 + p.total, 0);
            if (window.length >= 2 && sum >= T) {
              const ids = window.map(p => p.id);
              findings.push({
                entity_type: "purchase_order", entity_ids: ids, typology: "THRESHOLD_SPLITTING",
                _supplierIds: [sid], _threshold: tname,
                base_score: 25, confidence: "medium",
                evidence: [
                  ev("po_totals", ids.map(id => `${id} ${money(poById[id].total)}`).join(", "), `each individually below the ${tname} of ${money(T)}`),
                  ev("combined_total", money(sum), `exceeds the ${tname} of ${money(T)} within a 30-day window`),
                  ev("window", `${daysBetween(window[0].date_created, window[window.length - 1].date_created)} days`, "short interval consistent with splitting one requirement")
                ],
                benign: ["legitimately phased deliveries under a framework agreement", "separate cost-centre requests for genuinely different needs"],
                action: "request_supporting_documents", control: "rolling 30-day cumulative spend check per supplier against approval and quotation thresholds"
              });
              break; // one finding per supplier per threshold
            }
          }
        });
      });
    })();

    /* ---- 3. phantom / shell supplier ---- */
    (function phantom() {
      const poIdsWithGR = new Set(grs.map(g => g.po_id));
      sups.forEach(s => {
        const spos = poBySupplier[s.id] || [];
        if (!spos.length) return;
        const evidence = [];
        const onbDays = daysBetween(s.date_onboarded, "2026-09-16");
        if (onbDays != null && onbDays < 90) evidence.push(ev("date_onboarded", `${s.date_onboarded} (${onbDays} days before first flagged activity window)`, "established supplier with trading history"));
        if (!s.registration_number) evidence.push(ev("registration_number", "missing", "company registration number on file"));
        if (!s.tax_number) evidence.push(ev("tax_number", "missing", "valid tax reference on file"));
        if (/p\.?\s*o\.?\s*box/i.test(s.address || "")) evidence.push(ev("address", s.address, "physical business address"));
        const dom = domain(s.contact_email);
        if (dom && WEBMAIL_DOMAINS.includes(dom)) evidence.push(ev("contact_email", s.contact_email, "corporate email domain"));
        const noGR = spos.filter(p => !poIdsWithGR.has(p.id));
        if (noGR.length === spos.length) evidence.push(ev("goods_receipts", `no goods receipts for any of ${spos.length} PO(s)`, "receipted delivery evidence for paid orders"));
        sups.forEach(o => {
          if (o.id === s.id) return;
          const sim = Math.max(similarity(s.legal_name, o.legal_name), similarity(s.trading_name, o.trading_name));
          if (sim >= 0.85) {
            const later = daysBetween(o.date_onboarded, s.date_onboarded);
            if (later != null && later > 0) evidence.push(ev("legal_name", `"${s.legal_name}" vs "${o.legal_name}" (${Math.round(sim * 100)}% similar)`, "distinct supplier identities"));
          }
        });
        if (evidence.length >= 2) {
          findings.push({
            entity_type: "supplier", entity_ids: [s.id], typology: "PHANTOM_SUPPLIER",
            _supplierIds: [s.id],
            base_score: Math.min(55, 18 + 7 * evidence.length),
            confidence: evidence.length >= 4 ? "high" : "medium",
            evidence,
            benign: ["genuinely new vendor mid-onboarding with documents still being verified", "newly registered subsidiary of an existing supplier"],
            action: evidence.length >= 4 ? "escalate_to_internal_audit" : "request_supporting_documents",
            control: "vendor onboarding due diligence: CIPC registration verification, physical address check, bank verification callback before first payment"
          });
        }
      });
    })();

    /* ---- 4. employee-supplier collusion ---- */
    (function collusion() {
      sups.forEach(s => {
        const evidence = [];
        emps.forEach(e => {
          const shared = [];
          if (s.contact_phone && e.phone && digits(s.contact_phone) && digits(s.contact_phone) === digits(e.phone)) shared.push("phone number");
          if (normText(s.address) && normText(s.address) === normText(e.address_hash)) shared.push("address");
          const sd = domain(s.contact_email), ed = domain(e.email);
          if (sd && ed && sd === ed && !WEBMAIL_DOMAINS.includes(sd) && sd !== "dept.gov.za") shared.push("email domain");
          if (s.bank_account_hash && e.bank_account_hash && s.bank_account_hash === e.bank_account_hash) shared.push("bank account");
          if (shared.length) {
            shared.forEach(item => {
              const f = item === "phone number" ? "contact_phone" : item === "address" ? "address" : item === "email domain" ? "contact_email" : "bank_account_hash";
              evidence.push(ev(f, `supplier ${s.id} and employee ${e.id} share ${item} (${f === "contact_phone" ? s.contact_phone : f === "address" ? s.address : f === "contact_email" ? s.contact_email : s.bank_account_hash})`, "no shared contact or banking identifiers between staff and vendors"));
            });
          }
        });
        if (evidence.length) {
          findings.push({
            entity_type: "employee_supplier_link", entity_ids: [s.id], typology: "COLLUSION",
            _supplierIds: [s.id],
            base_score: 45, confidence: "high",
            evidence,
            benign: ["coincidental match on a common address or number", "family member legitimately running a registered business — declarable, not conclusive"],
            action: "escalate_to_internal_audit", control: "periodic vendor-master vs HR-master matching on phone, address, email domain and bank hash; mandatory declarations of interest"
          });
        }
      });
      if (emps.length && !emps.some(e => e.bank_account_hash)) gaps.push("Employee records do not include bank_account_hash; employee-supplier bank account sharing could not be checked.");
      if (emps.some(e => normText(e.address_hash) === e.address_hash && e.address_hash && e.address_hash.length > 8)) gaps.push("Employee address_hash values appear to be raw text rather than independent hashes; address matches rely on exact-string comparison.");
    })();

    /* ---- 5. banking detail manipulation ---- */
    (function bankChange() {
      sups.forEach(s => {
        if (!s.last_bank_change_date) return;
        const after = (invBySupplier[s.id] || []).filter(i => {
          const dd = daysBetween(s.last_bank_change_date, i.received_date || i.invoice_date);
          return dd != null && dd >= 0 && dd <= 30;
        });
        if (after.length && s.last_bank_change_date !== s.date_onboarded) {
          findings.push({
            entity_type: "supplier", entity_ids: [s.id, ...after.map(i => i.id)], typology: "BANK_DETAIL_CHANGE",
            _supplierIds: [s.id],
            base_score: 30, confidence: "medium",
            evidence: [
              ev("last_bank_change_date", s.last_bank_change_date, "stable banking details, or changes verified by callback to a known contact"),
              ev("invoice(s) received within 30 days of change", after.map(i => `${i.id} (${i.received_date})`).join(", "), "verification completed before any payment is released")
            ],
            benign: ["legitimate bank migration after a supplier changed banks", "routine account maintenance done through the verified portal"],
            action: "verify_bank_details_by_callback", control: "mandatory dual-channel verification callback for any bank detail change, with a payment hold period"
          });
        }
      });
      gaps.push("Payment execution dates are not provided; bank-change timing was assessed against invoice received_date as a proxy.");
    })();

    /* ---- 6. sequence anomalies ---- */
    (function sequence() {
      invs.forEach(i => {
        const po = i.po_id ? poById[i.po_id] : null;
        if (po && i.invoice_date && po.date_created && new Date(i.invoice_date) < new Date(po.date_created)) {
          findings.push({
            entity_type: "invoice", entity_ids: [i.id, po.id], typology: "SEQUENCE_ANOMALY",
            _supplierIds: [i.supplier_id],
            base_score: 15, confidence: "medium",
            evidence: [
              ev("invoice_date", `${i.id} dated ${i.invoice_date}`, "invoice dated on or after PO creation"),
              ev("po_date_created", `${po.id} created ${po.date_created}`, "procurement precedes invoicing")
            ],
            benign: ["date-entry error on the invoice", "PO created retrospectively to regularise a genuine urgent purchase (process weakness, not fraud)"],
            action: "request_supporting_documents", control: "block payment of invoices dated before the referenced PO; log retrospective approvals for review"
          });
        }
      });
      grs.forEach(g => {
        const po = g.po_id ? poById[g.po_id] : null;
        if (po && g.date_received && po.date_created && new Date(g.date_received) < new Date(po.date_created)) {
          findings.push({
            entity_type: "goods_receipt", entity_ids: [g.id, po.id], typology: "SEQUENCE_ANOMALY",
            _supplierIds: [po.supplier_id],
            base_score: 15, confidence: "medium",
            evidence: [
              ev("date_received", `${g.id} received ${g.date_received}`, "receipt dated on or after PO creation"),
              ev("po_date_created", `${po.id} created ${po.date_created}`, "orders precede delivery")
            ],
            benign: ["data-entry error on the receipt date"],
            action: "request_supporting_documents", control: "system-enforced date ordering between PO, dispatch and receipt"
          });
        }
      });
    })();

    /* ---- 7. price & quantity manipulation ---- */
    (function priceQty() {
      const hist = {}; // (supplier, sku) -> [{date, price}]
      const peer = {}; // sku -> [{supplier, price}]
      const buildRow = (p, line) => {
        const key = p.supplier_id + "|" + line.sku;
        (hist[key] = hist[key] || []).push({ date: p.date_created, price: line.unit_price, po: p.id });
        (peer[line.sku] = peer[line.sku] || []).push({ supplier: p.supplier_id, price: line.unit_price });
      };
      pos.forEach(p => (p.line_items || []).forEach(l => l.sku && l.unit_price != null && buildRow(p, l)));

      pos.forEach(p => {
        (p.line_items || []).forEach(line => {
          if (!line.sku || line.unit_price == null) return;
          const own = (hist[p.supplier_id + "|" + line.sku] || []).filter(h => h.date < p.date_created);
          const trailing = own.length ? own.reduce((s, h) => s + h.price, 0) / own.length : null;
          const peers = (peer[line.sku] || []).filter(h => h.supplier !== p.supplier_id);
          const peerAvg = peers.length ? peers.reduce((s, h) => s + h.price, 0) / peers.length : null;
          const evidence = [];
          if (trailing != null && line.unit_price >= trailing * 1.2 && line.unit_price - trailing >= 50) evidence.push(ev("unit_price", `${line.sku} at ${money(line.unit_price)} on ${p.id}`, `supplier's own trailing average ${money(trailing)}`));
          if (peerAvg != null && line.unit_price >= peerAvg * 1.25 && line.unit_price - peerAvg >= 50) evidence.push(ev("unit_price", `${line.sku} at ${money(line.unit_price)} on ${p.id}`, `peer-supplier average ${money(peerAvg)}`));
          if (evidence.length) {
            findings.push({
              entity_type: "purchase_order", entity_ids: [p.id], typology: "PRICE_MANIPULATION",
              _supplierIds: [p.supplier_id],
              base_score: 25, confidence: "medium",
              evidence,
              benign: ["genuine price escalation (paper/input cost increases)", "premium grade or different specification under the same SKU"],
              action: "request_supporting_documents", control: "unit-price variance check against supplier history and peer catalogue prices at PO capture"
            });
          }
        });

        // quantity received vs ordered/invoiced
        const receipts = grByPo[p.id] || [];
        if (receipts.length) {
          const rcv = {};
          receipts.forEach(g => (g.quantities_received || []).forEach(q => { rcv[q.sku] = (rcv[q.sku] || 0) + Number(q.quantity || 0); }));
          const short = (p.line_items || []).filter(l => l.sku && rcv[l.sku] != null && rcv[l.sku] < 0.9 * Number(l.quantity || 0));
          if (short.length) {
            findings.push({
              entity_type: "purchase_order", entity_ids: [p.id, ...receipts.map(g => g.id)], typology: "PRICE_MANIPULATION",
              _supplierIds: [p.supplier_id],
              base_score: 25, confidence: "medium",
              evidence: short.map(l => ev("quantity", `${l.sku}: ordered/invoiced ${l.quantity} on ${p.id}, received ${rcv[l.sku]}`, "received quantity matches invoiced quantity before payment")),
              benign: ["partial delivery with balance still in transit", "goods receipt captured incorrectly (quantity under-keyed)"],
              action: "hold_payment", control: "3-way match (PO, goods receipt, invoice) with quantity tolerance before payment release"
            });
          }
        }
      });
      gaps.push("Invoices do not include line-item quantities; quantity checks were performed against purchase order quantities as a proxy.");
    })();

    /* ---- 8. approval abuse ---- */
    (function approval() {
      pos.forEach(p => {
        const evidence = [];
        let score = 0;
        const appr = p.approver ? empById[p.approver] : null;
        if (p.approver && p.requester && p.approver === p.requester) {
          evidence.push(ev("approver = requester", `${p.approver} raised and approved ${p.id}`, "segregation of duties: approver must differ from requester"));
          score += 20;
        }
        if (appr && appr.approval_limit != null && p.total > appr.approval_limit) {
          evidence.push(ev("total vs approval_limit", `${p.id} ${money(p.total)} approved by ${p.approver} (limit ${money(appr.approval_limit)})`, "approval only within the approver's delegated limit"));
          score += 30;
        }
        const dt = d(p.date_approved);
        if (dt && /\d{2}:\d{2}/.test(String(p.date_approved))) {
          const day = dt.getDay(), hr = dt.getHours();
          if (day === 0 || day === 6 || hr < 7 || hr > 19) {
            evidence.push(ev("date_approved", `${p.id} approved ${p.date_approved} (${day === 0 ? "Sunday" : day === 6 ? "Saturday" : "outside 07:00-19:00"})`, "approvals during business hours"));
            score += 10;
          }
        }
        if (evidence.length) {
          findings.push({
            entity_type: "purchase_order", entity_ids: [p.id], typology: "APPROVAL_ABUSE",
            _supplierIds: [p.supplier_id],
            base_score: Math.min(45, score),
            confidence: p.approver === p.requester || (appr && p.total > appr.approval_limit) ? "high" : "low",
            evidence,
            benign: ["approver working weekend shift legitimately", "delegated limit recently increased and not yet reflected in the master data"],
            action: score >= 40 ? "escalate_to_internal_audit" : "monitor",
            control: "workflow-enforced segregation of duties and hard limit checks; exception report for out-of-hours approvals"
          });
        }
      });
      // repeated approver for one supplier
      const counts = {};
      pos.forEach(p => { const k = p.supplier_id + "|" + p.approver; counts[k] = counts[k] || []; counts[k].push(p.id); });
      Object.entries(counts).forEach(([k, ids]) => {
        const [sid, aid] = k.split("|");
        if (ids.length >= 3) {
          findings.push({
            entity_type: "purchase_order", entity_ids: ids, typology: "APPROVAL_ABUSE",
            _supplierIds: [sid],
            base_score: 15, confidence: "low",
            evidence: [ev("approver concentration", `approver ${aid} approved ${ids.length} POs for supplier ${sid} (${ids.join(", ")})`, "approval rotation across approvers for a single supplier")],
            benign: ["the approver is the category owner for this supplier", "small supplier base for a niche category"],
            action: "monitor", control: "rotate approvers per supplier and report on concentration of approvals"
          });
        }
      });
      if (emps.some(e => e.approval_limit == null)) gaps.push("Some employee records lack approval_limit; above-limit approval checks were skipped for those approvers.");
    })();

    /* ---- 9. sourcing circumvention ---- */
    (function sourcing() {
      Object.entries(poBySupplier).forEach(([sid, list]) => {
        const emerg = list.filter(p => String(p.sourcing_method || "").toLowerCase().includes("emergency"));
        const single = list.filter(p => String(p.sourcing_method || "").toLowerCase() === "single_source");
        const evidence = [];
        if (emerg.length > emergMax) evidence.push(ev("sourcing_method", `emergency used ${emerg.length} times in 12 months (${emerg.map(p => p.id).join(", ")})`, `policy maximum ${emergMax} emergency purchases per supplier per year`));
        if (single.length >= 3) evidence.push(ev("sourcing_method", `single_source used ${single.length} times (${single.map(p => p.id).join(", ")})`, "competitive quotations for recurring spend above the quotation threshold"));
        if (evidence.length) {
          findings.push({
            entity_type: "purchase_order", entity_ids: list.map(p => p.id), typology: "SOURCING_CIRCUMVENTION",
            _supplierIds: [sid],
            base_score: emerg.length > emergMax ? 25 : 20, confidence: "medium",
            evidence,
            benign: ["genuine recurring breakdowns requiring emergency response", "sole OEM-approved supplier for specialised parts"],
            action: emerg.length > emergMax ? "escalate_to_internal_audit" : "monitor",
            control: "emergency procurement register with mandatory post-hoc justification and quarterly competitive re-tender"
          });
        }
      });
    })();

    /* ---- 10. statistical anomalies ---- */
    (function statistical() {
      const BENFORD = [30.1, 17.6, 12.5, 9.7, 7.9, 6.7, 5.8, 5.1, 4.6];
      Object.entries(invBySupplier).forEach(([sid, list]) => {
        const evidence = [];
        const firstDigits = list.map(i => String(Math.abs(i.total)).replace(/[^1-9]/g, "")[0]).filter(Boolean).map(Number);
        if (firstDigits.length >= 6) {
          const counts = Array(9).fill(0);
          firstDigits.forEach(x => counts[x - 1]++);
          const dev = counts.map((c, i) => Math.abs(c / firstDigits.length * 100 - BENFORD[i]));
          const mad = dev.reduce((s, x) => s + x, 0) / 9;
          const maxDev = Math.max(...dev);
          if (mad > 8 || maxDev > 20) {
            const worst = dev.indexOf(maxDev) + 1;
            evidence.push(ev("first-digit distribution (Benford)", `digit ${worst} leads ${(counts[worst - 1] / firstDigits.length * 100).toFixed(0)}% of ${firstDigits.length} invoices (expected ${BENFORD[worst - 1]}%)`, "first-digit profile close to Benford's law"));
          }
        }
        const clusterBelow = list.filter(i => {
          const t = i.total / quoteThresh;
          const a = i.total / apprThresh;
          return (a >= 0.9 && a < 1) || (t >= 0.9 && t < 1);
        });
        if (clusterBelow.length >= 3) evidence.push(ev("amount clustering", `${clusterBelow.length} invoices in the 90-99% band of a threshold (${clusterBelow.map(i => money(i.total)).join(", ")})`, "amounts spread naturally across values"));
        const round = list.filter(i => i.total % 1000 === 0);
        if (list.length >= 4 && round.length >= 3 && round.length / list.length >= 0.4) evidence.push(ev("round-number totals", `${round.length} of ${list.length} invoice totals are exact multiples of R1,000`, "fewer round numbers in a natural invoice set"));
        if (evidence.length) {
          findings.push({
            entity_type: "supplier", entity_ids: [sid], typology: "STATISTICAL_ANOMALY",
            _supplierIds: [sid],
            base_score: Math.min(30, 12 + 6 * evidence.length), confidence: "low",
            evidence,
            benign: ["fixed-price service packages billed at round contract amounts", "genuine price points just under a quotation threshold (list pricing)"],
            action: "monitor", control: "periodic Benford and threshold-clustering analytics over supplier invoice populations"
          });
        }
      });
    })();

    /* ---- 11. dormancy reactivation ---- */
    (function dormancy() {
      Object.entries(invBySupplier).forEach(([sid, list]) => {
        const sorted = list.filter(i => i.invoice_date).sort((a, b) => new Date(a.invoice_date) - new Date(b.invoice_date));
        for (let i = 1; i < sorted.length; i++) {
          const gap = daysBetween(sorted[i - 1].invoice_date, sorted[i].invoice_date);
          if (gap > 180) {
            const prior = sorted.slice(0, i).map(x => x.total);
            const med = median(prior);
            if (med != null && sorted[i].total > 2 * med) {
              findings.push({
                entity_type: "invoice", entity_ids: [sorted[i].id], typology: "DORMANCY_REACTIVATION",
                _supplierIds: [sid],
                base_score: 20, confidence: "medium",
                evidence: [
                  ev("invoice gap", `${gap} days of inactivity for supplier ${sid} before ${sorted[i].id}`, "regular trading pattern or dormant status maintained"),
                  ev("reactivation value", `${sorted[i].id} at ${money(sorted[i].total)} vs prior median ${money(med)}`, "transaction value in line with historical activity")
                ],
                benign: ["new annual contract won after a dormant period", "genuine seasonal or project-based supplier usage"],
                action: "request_supporting_documents", control: "revalidation of dormant suppliers (details, KYC, bank verification) before high-value reactivation"
              });
            }
          }
        }
      });
    })();

    /* ---- data gaps: master data quality ---- */
    const noReg = sups.filter(s => !s.registration_number || !s.tax_number).map(s => s.id);
    if (noReg.length) gaps.push(`Suppliers ${noReg.join(", ")}: registration_number and/or tax_number missing.`);
    const poNoGR = pos.filter(p => !(grByPo[p.id] || []).length).map(p => p.id);
    if (poNoGR.length) gaps.push(`No goods_receipts provided for ${poNoGR.length} purchase order(s) (${poNoGR.slice(0, 8).join(", ")}${poNoGR.length > 8 ? ", …" : ""}); under-delivery could not be assessed for those POs.`);
    gaps.push("Approver working-hours checks are limited where date_approved lacks a time component.");

    /* ---- corroboration & scoring ---- */
    const supTypo = {};
    findings.forEach(f => (f._supplierIds || []).forEach(sid => { (supTypo[sid] = supTypo[sid] || new Set()).add(f.typology); }));

    const out = findings.map((f, ix) => {
      let score = f.base_score;
      let distinct = new Set();
      (f._supplierIds || []).forEach(sid => (supTypo[sid] || new Set()).forEach(t => distinct.add(t)));
      if (distinct.size >= 2) score = Math.round(score * (1 + 0.25 * (distinct.size - 1)));
      score = Math.min(100, Math.round(score));
      let b = band(score);
      if ((b === "HIGH" || b === "CRITICAL") && f.evidence.length < 2 && distinct.size < 3) { score = 45; b = "MEDIUM"; }
      return {
        finding_id: "F-" + String(ix + 1).padStart(3, "0"),
        entity_type: f.entity_type,
        entity_ids: f.entity_ids,
        typology: f.typology,
        risk_score: score,
        risk_band: b,
        confidence: f.confidence,
        evidence: f.evidence,
        benign_explanations: f.benign,
        recommended_action: f.action,
        suggested_control: f.control
      };
    });
    out.sort((a, b) => b.risk_score - a.risk_score);
    out.forEach((f, i) => (f.finding_id = "F-" + String(i + 1).padStart(3, "0")));

    const bands = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
    return {
      run_summary: {
        records_reviewed: pos.length + invs.length + grs.length + sups.length + emps.length,
        flagged_count: out.length,
        highest_risk_band: out.length ? out[0].risk_band : "LOW",
        data_gaps: gaps
      },
      findings: out
    };
  }

  global.FraudLens = { analyze };
})(window);
