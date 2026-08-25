# Aperture

**A client-side layer between you and social platforms.**
[Live demo →](https://sanjana-sun.github.io/aperture/)

It shows you what your files reveal before you upload them, audits what a platform
already holds about you, and drafts the legal requests to get it deleted.

**Everything runs in the browser.** No server, no upload, no analytics, no network
request of any kind. Open the network tab and watch it stay empty. **Zero
dependencies** — every capability below is built on web standards.

---

## What it does

### Pillar 1 — Control what leaves

- **JPEG metadata analysis.** Parses the JPEG segment structure and walks EXIF /
  TIFF IFDs directly. Surfaces camera make and model, body serial number, software,
  timestamps, lens identifiers, and GPS.
- **GPS resolution.** Converts EXIF rationals to signed decimal degrees and links
  the coordinates to a map, because that is the finding people react to.
- **Metadata stripping by segment removal.** Removes APP0–APP15 and COM markers and
  copies the scan data verbatim, so **the compressed image is byte-identical**.
  This is deliberately not a canvas re-encode, which would alter every pixel and
  degrade the image.
- **Text PII detection.** Ten detectors over captions and screenshots: email,
  phone, coordinates, payment cards (**Luhn-validated**, so long digit runs are not
  false-flagged), US SSN, IP, handles, dates of birth, street addresses, postcodes.
  Overlapping matches resolve by severity. In-place highlighting and redaction.

### Pillar 2 — See what they already hold

- **ZIP reader with no library.** Parses the central directory, handles ZIP64, and
  decompresses through the platform's own `DecompressionStream('deflate-raw')`.
- **Categorises a data export** into nine sensitivity-ranked categories with sizes,
  file counts, and an explanation of why each matters.
- **Drafts data-rights requests**, populated from what is actually in your archive:
  - **GDPR Article 15** — access, with the full Art. 15(1)(a)–(h) supplementary
    information, and a specific demand for inferred and derived data that exports
    routinely omit.
  - **GDPR Article 17** — erasure, with consent withdrawal under 6(1)(a), objection
    under 21(1) and 21(2), Article 19 downstream notification, and a demand that
    any 17(3) exemption be identified specifically rather than asserted generally.
  - **CCPA / CPRA** — right to know, delete, opt out of sale or sharing, limit
    sensitive personal information, and correct.

### Pillar 3 — Private messages

**Deliberately not built.** Real end-to-end encrypted messaging belongs on a
reviewed implementation — `libsignal` (X3DH + Double Ratchet) or MLS (RFC 9420) —
not on a ratchet written in a hurry. Hand-rolled protocols fail silently, in ways
only formal analysis catches.

The same reasoning rules out the approach people suggest first, encrypting
everything before upload. It fails structurally: platforms must render content,
they re-encode images and destroy anything embedded, and key distribution kills
adoption before the cryptography matters. **Keybase and Scramble! both died on
exactly this.** Aperture works on what survives that constraint.

---

## What it does not claim

- **Pattern matching is not certification.** The text scanner finds things that
  *look like* identifiers. It misses things and it over-flags. It reduces
  accidental disclosure; it does not make a caption safe.
- **Metadata removal is not anonymity.** The image content still shows where you
  were, and the platform still sees your account, IP and upload time.
- **Deletion requests are not deletion.** This drafts letters. Whether a company
  complies is outside what software controls.
- **It never automates anything on a platform.** No posting, no scraping, no
  logging in for you. That is a deliberate constraint, chosen to stay clear of
  terms-of-service and Computer Fraud and Abuse Act exposure. **You click send.**

---

## Run it

```bash
git clone https://github.com/Sanjana-sun/aperture
cd aperture/docs && python3 -m http.server 8742
```

Then open `http://localhost:8742`. Append `#demo` to preload the bundled fixtures.

Tests (Node, no runner):
```bash
node test/run.mjs     # EXIF parse, GPS resolution, strip, byte-identity of scan data
node test/pii.mjs     # detectors, Luhn rejection, redaction offsets
node test/audit.mjs   # ZIP parse, DecompressionStream, categorisation, letters
```

---

Sanjana Sri Injamuri · MS Computer Science, Northeastern University
injamuri.s@northeastern.edu

Prototype. Two of three pillars implemented. Not legal advice.
