# Feature round 2

## Chosen, in priority order

**1. Deep archive scan (Pillar 2).** Right now we categorise filenames. We never
open the files. Decompress the JSON inside the export, run the PII detectors over
it, and extract structured facts. This turns "location history, 69 KB" into "1,200
location points spanning 50 days, here they are on a map."

**2. Inference and advertiser extraction.** Both letters demand *inferred data*,
which exports routinely omit and which is the most commercially valuable category.
Showing the actual list — "340 advertisers hold a customer list with you in it" —
makes that demand concrete rather than boilerplate.

**3. Location plot.** The most re-identifying category in any export. Rendering the
points is the single most visceral thing this tool can do.

**4. PNG and WebP metadata.** Currently JPEG only, which is a real gap: PNG carries
tEXt/iTXt/zTXt and eXIf chunks, WebP carries EXIF and XMP in RIFF chunks.

**5. Supervisory-authority complaint letter.** GDPR Art. 77. Completes the legal
pathway: if the controller ignores the Art. 15/17 request, this is what you send
next, and it is the step that gives the request teeth.

**6. Deadline tracking.** Art. 12(3) is one month; CCPA s.1798.130 is 45 days.
Compute and show the date the response is due.

## Deliberately still not doing

- **OCR on screenshots.** In-browser OCR without a dependency is not realistic, and
  a bad OCR pass would produce confident wrong answers about what is in an image.
- **Face and plate blur.** The design calls for automatic detection. `FaceDetector`
  is Chrome-only and unreliable; shipping it would mean claiming detection that
  silently fails on the faces that matter. Manual redaction is honest, but it is a
  drawing tool, not a privacy feature, so it waits.
- **Pillar 3.** Same reason as before: libsignal or MLS, not a hand-rolled ratchet.
