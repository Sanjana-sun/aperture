/* Aperture — text PII detection.
 *
 * Deliberately conservative. Every detector here is a pattern match, which means
 * it finds things that *look like* identifiers, not things that *are* identifiers.
 * The UI must say so: this reduces accidental disclosure, it does not certify that
 * a caption is safe. Overclaiming is the standard failure of this product category.
 */

const DETECTORS = [
  {
    id: 'email', label: 'Email address', severity: 'high',
    re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
  },
  {
    id: 'phone', label: 'Phone number', severity: 'high',
    // NANP and common international shapes; requires separators to cut false hits
    re: /(?:\+?\d{1,3}[\s.-]?)?\(?\b\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}\b/g,
  },
  {
    id: 'coords', label: 'Geographic coordinates', severity: 'high',
    re: /\b-?(?:[0-8]?\d(?:\.\d{3,})|90(?:\.0+)?)\s*,\s*-?(?:1[0-7]\d|[0-9]?\d)(?:\.\d{3,})\b/g,
  },
  {
    id: 'card', label: 'Payment-card-like number', severity: 'high',
    re: /\b(?:\d[ -]?){13,19}\b/g,
    // Luhn check, so we don't flag every long digit run
    validate: (m) => {
      const d = m.replace(/\D/g, '');
      if (d.length < 13 || d.length > 19) return false;
      let sum = 0, alt = false;
      for (let i = d.length - 1; i >= 0; i--) {
        let n = +d[i];
        if (alt) { n *= 2; if (n > 9) n -= 9; }
        sum += n; alt = !alt;
      }
      return sum % 10 === 0;
    },
  },
  {
    id: 'ssn', label: 'US SSN-like number', severity: 'high',
    re: /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g,
  },
  {
    id: 'ip', label: 'IP address', severity: 'medium',
    re: /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g,
  },
  {
    id: 'handle', label: 'Social handle', severity: 'low',
    re: /(?:^|\s)@[A-Za-z0-9_]{3,30}\b/g,
  },
  {
    id: 'dob', label: 'Date of birth phrasing', severity: 'medium',
    re: /\b(?:born|DOB|date of birth|b\.)\s*:?\s*\d{1,4}[/\-.]\d{1,2}[/\-.]\d{2,4}\b/gi,
  },
  {
    id: 'address', label: 'Street address', severity: 'medium',
    re: /\b\d{1,5}\s+(?:[A-Z][a-z]+\s){1,3}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl)\b\.?/g,
  },
  {
    id: 'postcode', label: 'Postcode', severity: 'low',
    re: /\b(?:\d{5}(?:-\d{4})?|[A-Z]{1,2}\d[A-Z\d]?\s?\d[A-Z]{2})\b/g,
  },
];

/** Scan text. Returns findings with offsets so the UI can highlight in place. */
export function scanText(text) {
  const findings = [];
  for (const d of DETECTORS) {
    d.re.lastIndex = 0;
    let m;
    while ((m = d.re.exec(text)) !== null) {
      // A zero-width match would leave lastIndex where it is and spin forever.
      // This has to come before any `continue`, or the guard below it is dead.
      if (m[0].length === 0) { d.re.lastIndex++; continue; }
      // Some patterns (card, handle) legitimately capture surrounding separators.
      // Trim them and adjust the offsets, or redaction eats the word boundary.
      const raw = m[0];
      const lead = raw.length - raw.replace(/^[\s]+/, '').length;
      const trail = raw.length - raw.replace(/[\s\-]+$/, '').length;
      const value = raw.slice(lead, raw.length - trail);
      if (!value) continue;
      if (d.validate && !d.validate(value)) continue;
      findings.push({
        id: d.id, label: d.label, severity: d.severity,
        value,
        start: m.index + lead,
        end: m.index + raw.length - trail,
      });
    }
  }
  // Overlapping matches: keep the higher-severity one.
  //
  // The comparison has to lead with severity. Sorting by position first meant an
  // earlier low-severity match claimed the span and suppressed a high-severity
  // match that started one character later, so a postcode could hide an SSN.
  // Ties go to the longer, more specific match.
  const rank = { high: 3, medium: 2, low: 1 };
  findings.sort((a, b) =>
    rank[b.severity] - rank[a.severity] ||
    (b.end - b.start) - (a.end - a.start) ||
    a.start - b.start);
  const kept = [];
  for (const f of findings) {
    if (kept.some(k => f.start < k.end && f.end > k.start)) continue;
    kept.push(f);
  }
  return kept.sort((a, b) => a.start - b.start);
}

/** Replace findings with a placeholder, preserving the rest of the text. */
export function redactText(text, findings) {
  let out = '', cursor = 0;
  for (const f of [...findings].sort((a, b) => a.start - b.start)) {
    // scanText returns non-overlapping findings, but this is exported and callers
    // may not. Without this guard a overlapping pair rewinds the cursor and the
    // text between them is dropped from the output entirely.
    if (f.start < cursor) continue;
    out += text.slice(cursor, f.start) + `[${f.label.toUpperCase()} REMOVED]`;
    cursor = f.end;
  }
  return out + text.slice(cursor);
}

export const DETECTOR_COUNT = DETECTORS.length;
