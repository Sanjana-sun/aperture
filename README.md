# Aperture

[![tests](https://github.com/Sanjana-sun/aperture/actions/workflows/test.yml/badge.svg)](https://github.com/Sanjana-sun/aperture/actions/workflows/test.yml)

**A client-side layer between you and social platforms.**
[Live demo](https://sanjana-sun.github.io/aperture/)

It shows you what your files reveal before you upload them, opens the export a
platform gave you and reads what is actually inside it, and drafts the legal
requests to get that data deleted.

**Everything runs in the browser.** No server, no upload, no analytics, and no
request that carries your data anywhere. Open your browser's network tab, drop a
photo in, and watch it stay still. (The page fetches its own stylesheet and modules
like any web page, and the `#demo` links load two bundled sample files. Nothing you
choose is ever sent.) **Zero dependencies:** every capability below is built on web
standards, including the binary parsers.

---

## What it does

### Pillar 1: control what leaves

- **Metadata analysis for JPEG, PNG and WebP.** Walks JPEG marker segments and
  TIFF/EXIF IFDs, PNG `tEXt` / `zTXt` / `iTXt` / `eXIf` / `iCCP` chunks, and WebP
  RIFF `EXIF` / `XMP` / `ICCP` chunks. Surfaces camera make and model, body serial
  number, software, timestamps, lens identifiers, ICC profiles and GPS.
- **GPS resolution.** Converts EXIF rationals to signed decimal degrees, renders
  the angle as degrees/minutes/seconds, and links the coordinates to a map, because
  that is the finding people react to.
- **Stripping by segment removal, not re-encoding.** Drops the metadata segments
  and copies the image data verbatim, so **the compressed image is byte-identical**
  and a test asserts it. A canvas re-encode would alter every pixel and visibly
  degrade the image. Removing a WebP chunk also clears the matching VP8X feature
  bit, so the file does not advertise metadata it no longer carries.
- **Text PII detection.** Ten detectors over captions and screenshots: email,
  phone, coordinates, payment cards (**Luhn-validated**, so long digit runs are not
  false-flagged), US SSN, IP, handles, dates of birth, street addresses, postcodes.
  Overlapping matches resolve by severity, so a low-confidence postcode cannot mask
  an SSN that overlaps it. In-place highlighting and redaction.

### Pillar 2: see what they already hold

- **ZIP reader with no library.** Parses the central directory, reads the ZIP64
  extended-information extra field so archives and entries over 4 GiB work, decodes
  CP437 filenames when the UTF-8 flag is absent, reports encrypted entries instead
  of inflating them into garbage, and decompresses through the platform's own
  `DecompressionStream('deflate-raw')`.
- **Shallow audit.** Categorises the export into nine sensitivity-ranked categories
  with sizes, file counts, date range, and an explanation of why each matters.
- **Deep scan.** Opens the JSON rather than just listing filenames, and pulls out
  what people do not know is in there:
  - every **third-party advertiser** that uploaded a customer list you matched
  - the **interest and topic categories** inferred about you
  - **login IP history** with frequency
  - the **location trace**, rendered as a scatter plot with a bounding box in km.
    The plot is a dependency-free SVG, so there are no map tiles and therefore no
    network call.

  Inferred attributes get their own section deliberately. They are personal data
  under GDPR Art. 4(1) and CCPA s.1798.140(v)(1)(K), they are the most commercially
  valuable category, and exports routinely bury or omit them.
- **Drafts data-rights requests**, populated from what is actually in your archive:
  - **GDPR Article 15:** access, with the full Art. 15(1)(a) to (h) supplementary
    information and a specific demand for the inferred and derived data above.
  - **GDPR Article 17:** erasure, with consent withdrawal under 6(1)(a), objection
    under 21(1) and 21(2), Article 19 downstream notification, and a demand that
    any 17(3) exemption be identified specifically rather than asserted generally.
  - **CCPA / CPRA:** right to know, delete, opt out of sale or sharing, limit
    sensitive personal information, and correct.
  - **GDPR Article 77:** complaint to a supervisory authority, for when the
    controller ignores the request. This is the step that gives the others teeth.
  - **Deadline tracking.** Computes the Art. 12(3) one-month and CCPA 45-day
    response dates from the day you send.

### Pillar 3: private messages

**Deliberately not built.** Real end-to-end encrypted messaging belongs on a
reviewed implementation, `libsignal` (X3DH plus Double Ratchet) or MLS (RFC 9420),
not on a ratchet written in a hurry. Hand-rolled protocols fail silently, in ways
only formal analysis catches.

The same reasoning rules out the approach people suggest first, encrypting
everything before upload. It fails structurally: platforms must render content,
they re-encode images and destroy anything embedded, and key distribution kills
adoption before the cryptography matters. **Keybase and Scramble! both died on
exactly this.** Aperture works on what survives that constraint.

---

## How it is tested

`node test/all.mjs` runs everything. There is no test runner and nothing to
install.

Alongside the ordinary unit tests there is an **adversarial suite** that exists to
attack the parsers rather than confirm them. It is where most of the real bugs came
from. It covers truncated and non-ZIP input, corrupt PNG chunk lengths, ZIP64
saturated size fields, encrypted entries, CP437 filenames, VP8X feature bits, WebP
EXIF chunks that already carry the `Exif\0\0` magic, severity inversion in
overlapping PII matches, overlapping input to the redactor, and a 150,000-point
location history, which is roughly the size at which `Math.min(...points)` exceeds
the argument limit and throws.

Its fixtures are built in memory by `test/helpers.mjs`, which writes ZIP, PNG and
WebP by hand. That is deliberate: awkward cases like a ZIP64 extra field or a
CP437 filename can then be produced exactly and explained in code. The assertions
are behavioural, and each one has been checked by mutating the code it guards to
confirm it actually fails.

Two properties are worth calling out, because both were bugs first:

- **Coordinates are read per object, never across objects.** An earlier version
  tracked a pending latitude while walking JSON leaves in document order, which
  paired a latitude with whatever longitude came next, including one from an
  unrelated record. That invented locations the user had never been to. For a tool
  whose whole claim is that it reports only what is in the file, fabricating
  evidence is the one unacceptable failure.
- **Fixtures are generated, not hand-carved.** `test/make-fixtures.py` is
  deterministic and checked in, so the binary in the repo is explainable. This
  matters: `test/meta.webp` was once malformed in a way that made the WebP test
  pass while only ever exercising the parser's rejection path.

GitHub Pages serves `docs/` only, so the modules are copied there rather than
imported from `../src`. That copy is the one thing here that can drift with nothing
failing, so `./sync.sh` performs it and `test/sync.mjs` fails if it was not run.

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

### Known limits

- **HEIC is not supported.** It is what iPhones shoot by default, so this is a real
  gap rather than a rounding error. Reading and stripping HEIC metadata does not
  require decoding HEVC, since it lives in ISOBMFF boxes, so it is tractable. It is
  simply not done yet.
- **Whole files are read into memory.** Archives are loaded with
  `file.arrayBuffer()`, which is fine for a social export and not fine for a
  multi-gigabyte Google Takeout. Reading the central directory through
  `File.slice()` and slicing per entry is the fix.
- **The deep scan reads JSON only.** Exports that ship HTML are listed and
  categorised, but not opened.
- **It has been tested against synthetic exports.** The fixtures model the shape of
  a real one. They are not a substitute for running it on yours.

---

## Run it

```bash
git clone https://github.com/Sanjana-sun/aperture
cd aperture/docs && python3 -m http.server 8742
```

Then open `http://localhost:8742`. Append `#demo` to preload the image fixtures, or
`#demo2` to preload the export archive.

```bash
node test/all.mjs            # everything, including the drift check
./sync.sh                    # copy src/ and fixtures into docs/
python3 test/make-fixtures.py  # regenerate the synthetic export
```

Individual suites: `run` (EXIF parse, GPS, strip, byte-identity), `pii`
(detectors, Luhn rejection, redaction offsets), `audit` (ZIP, categorisation,
letters), `formats` (JPEG, PNG, WebP round-trip), `deep` (archive scan),
`adversarial` and `adv2` (malformed and hostile input), `sync` (docs/ drift).
Fixture builders live in `test/helpers.mjs`.

---

Sanjana Sri Injamuri · MS Computer Science, Northeastern University
injamuri.s@northeastern.edu

Prototype. Two of three pillars implemented. Not legal advice.
