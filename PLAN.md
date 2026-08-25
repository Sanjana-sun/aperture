# Build plan — 38 hours to the Bietti call

## What we build, and what we deliberately don't

**Build Pillar 1 (outbound gateway) and Pillar 2 (exposure audit + data rights).**
Both run **entirely in the browser**. No server, no upload, no build step. That is
not a shortcut — it *is* the product thesis, demonstrated. She can watch it work
over Zoom screenshare and verify nothing leaves the device by opening the network
tab.

**Do NOT build Pillar 3 (E2EE messaging) tonight.** Your own design principle says
do not roll custom crypto; use libsignal or MLS. Shipping hand-rolled crypto in a
night would contradict the one design rule you already got right. Say that in the
meeting — it is a stronger answer than a half-built ratchet.

## Scope

**Pillar 1 — outbound gateway**
- Parse JPEG APP1/EXIF, show the user exactly what metadata is present
- Surface GPS coordinates explicitly, with a map link, because that is the one that
  makes people flinch
- Strip metadata by removing the APP1 segment, preserving image bytes exactly
  (better than canvas re-encode, which degrades the image)
- PII detection over caption text: emails, phones, coordinates, card-like numbers,
  government-ID-like patterns, handles

**Pillar 2 — exposure audit + data rights**
- Read a platform DSAR export `.zip` locally using `DecompressionStream`
- No library, no upload; the archive never leaves the machine
- Categorise contents, size them, flag high-sensitivity categories
- Generate GDPR Art. 15 / Art. 17 and CCPA/CPRA request letters, pre-filled

## Constraints

- **Zero dependencies.** Everything from web standards. A dependency-free build is
  also an auditability argument, which matters to her.
- **Nothing leaves the device.** No fetch, no analytics, no fonts from a CDN.
- Must work offline. Open the HTML file and it runs.

## What this buys in the meeting

- It stops being a design and becomes a thing she can watch run.
- The network tab is the proof of the zero-knowledge claim.
- Pillar 2 is the legally interesting one, and it is *pure exercise of statutory
  rights* — no platform system is touched.
