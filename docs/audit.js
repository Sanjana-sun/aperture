/* Aperture — DSAR export audit and data-rights request generation.
 *
 * Categorises the contents of a platform data export and drafts GDPR / CCPA
 * requests. This pillar never touches the platform's systems: it reads a file the
 * platform already gave the user, and produces letters the user sends themselves.
 */

// Category rules, matched against the path inside the archive. Ordered: first match wins.
const CATEGORIES = [
  { id: 'location',  label: 'Location history',        severity: 'high',
    match: /(^|\/)(location|places|gps|timeline)/i,
    why: 'Precise movement history is the most re-identifying category in a typical export.' },
  { id: 'messages',  label: 'Private messages',        severity: 'high',
    match: /(^|\/)(messages|inbox|chats|dm)/i,
    why: 'Message content includes other people who never consented to this export.' },
  { id: 'contacts',  label: 'Contacts and connections', severity: 'high',
    match: /(^|\/)(connections|contacts|friends|followers|address_book)/i,
    why: 'Your social graph identifies you even when your own records are removed.' },
  { id: 'ads',       label: 'Advertising and inferences', severity: 'high',
    match: /(^|\/)(ads?|advertis|interests|topics|preferences)/i,
    why: 'Inferred attributes are derived data. They are often the least visible and most commercially valuable.' },
  { id: 'security',  label: 'Logins, IPs and sessions', severity: 'medium',
    match: /(^|\/)(security|login|sessions?|access|ip_)/i,
    why: 'IP and session history reveals home, work and travel patterns.' },
  { id: 'devices',   label: 'Device identifiers',      severity: 'medium',
    match: /(^|\/)(device|hardware|browser)/i,
    why: 'Device identifiers link activity across apps and accounts.' },
  { id: 'profile',   label: 'Profile and identity',    severity: 'medium',
    match: /(^|\/)(personal|profile|account|identity|about)/i,
    why: 'Directly identifying fields: name, email, phone, date of birth.' },
  { id: 'media',     label: 'Photos and video',        severity: 'medium',
    match: /\.(jpe?g|png|heic|gif|mp4|mov|webp)$/i,
    why: 'Media may carry its own embedded metadata, separately from this export.' },
  { id: 'content',   label: 'Posts and activity',      severity: 'low',
    match: /(^|\/)(posts?|comments?|likes?|reactions?|activity|stories)/i,
    why: 'Content you authored, plus engagement records you may not have known were kept.' },
];

const OTHER = { id: 'other', label: 'Uncategorised', severity: 'low',
  why: 'Not matched by any rule. Worth opening manually.' };

function categorise(path) {
  for (const c of CATEGORIES) if (c.match.test(path)) return c;
  return OTHER;
}

export function fmtBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MB`;
  return `${(n / 1024 ** 3).toFixed(2)} GB`;
}

/** Group entries into categories with sizes and counts. */
export function auditEntries(entries) {
  const files = entries.filter(e => !e.isDir);
  const groups = new Map();
  for (const e of files) {
    const c = categorise(e.name);
    if (!groups.has(c.id)) groups.set(c.id, { ...c, files: [], bytes: 0 });
    const g = groups.get(c.id);
    g.files.push(e);
    g.bytes += e.uncompressed;
  }
  const rank = { high: 3, medium: 2, low: 1 };
  const list = [...groups.values()].sort(
    (a, b) => rank[b.severity] - rank[a.severity] || b.bytes - a.bytes);

  const dates = files.map(f => f.modified).filter(Boolean).sort((a, b) => a - b);
  return {
    groups: list,
    totalFiles: files.length,
    totalBytes: files.reduce((n, f) => n + f.uncompressed, 0),
    highCount: list.filter(g => g.severity === 'high').length,
    earliest: dates[0] || null,
    latest: dates[dates.length - 1] || null,
  };
}

// ---------------------------------------------------------------- letters

const today = () => new Date().toISOString().slice(0, 10);

export function gdprAccess({ name, email, platform, audit }) {
  const cats = audit.groups.map(g => `  - ${g.label}`).join('\n');
  return `Date: ${today()}
To: Data Protection Officer, ${platform}
From: ${name} <${email}>
Subject: Request for access under Article 15 GDPR

Dear Data Protection Officer,

I am making a request under Article 15 of the General Data Protection Regulation
for access to the personal data you hold about me, and for the supplementary
information Article 15(1) requires.

Please provide:

1. Confirmation as to whether you are processing personal data concerning me.
2. A copy of that personal data (Article 15(3)).
3. The purposes of the processing (Article 15(1)(a)).
4. The categories of personal data concerned (Article 15(1)(b)).
5. The recipients or categories of recipient to whom the data have been or will
   be disclosed, in particular recipients in third countries (Article 15(1)(c)).
6. The envisaged retention period, or the criteria used to determine it
   (Article 15(1)(d)).
7. The source of the data where it was not collected from me (Article 15(1)(g)).
8. The existence of automated decision-making, including profiling, and
   meaningful information about the logic involved and the significance and
   envisaged consequences of such processing (Article 15(1)(h)).

I have reviewed a data export previously provided to me, which contained the
following categories:

${cats}

That export contained ${audit.totalFiles} files totalling ${fmtBytes(audit.totalBytes)}.
Please confirm whether it represents the complete set of personal data you hold
about me. In particular, please confirm whether it includes **inferred or derived
data**, such as advertising interest categories and predicted attributes, which
constitute personal data under Article 4(1) and which exports frequently omit.

Please respond within one month of receipt, as required by Article 12(3).

Yours faithfully,
${name}
${email}`;
}

export function gdprErasure({ name, email, platform, audit }) {
  const high = audit.groups.filter(g => g.severity === 'high')
    .map(g => `  - ${g.label}`).join('\n') || '  - (none identified)';
  return `Date: ${today()}
To: Data Protection Officer, ${platform}
From: ${name} <${email}>
Subject: Request for erasure under Article 17 GDPR

Dear Data Protection Officer,

I am making a request under Article 17 of the General Data Protection Regulation
for the erasure of personal data concerning me.

I request erasure in particular of the following categories, which I have
identified in a data export you provided:

${high}

Where you rely on consent as the lawful basis (Article 6(1)(a)), I withdraw that
consent, and erasure is required under Article 17(1)(b).

Where you rely on legitimate interests (Article 6(1)(f)), I object to the
processing under Article 21(1), and erasure is required under Article 17(1)(c).
Where the processing is for direct marketing purposes, I object under
Article 21(2), for which there is no balancing test.

Please also confirm, under Article 19, that you have communicated this erasure to
each recipient to whom the data were disclosed, or explain why this proves
impossible or involves disproportionate effort.

If you consider that an exemption under Article 17(3) applies to any category,
please identify the category and the specific exemption relied upon, rather than
declining the request in general terms.

Please respond within one month of receipt, as required by Article 12(3).

Yours faithfully,
${name}
${email}`;
}

export function ccpaRequest({ name, email, platform, audit }) {
  return `Date: ${today()}
To: Privacy Team, ${platform}
From: ${name} <${email}>
Subject: Consumer requests under the CCPA/CPRA

To whom it may concern,

I am a California resident exercising rights under the California Consumer
Privacy Act as amended by the California Privacy Rights Act.

1. RIGHT TO KNOW (Civ. Code s. 1798.110 and 1798.115). Please disclose:
   a. the specific pieces of personal information you have collected about me;
   b. the categories of personal information collected;
   c. the categories of sources;
   d. the business or commercial purpose for collecting, selling or sharing it;
   e. the categories of third parties to whom it was disclosed, sold or shared.

2. RIGHT TO DELETE (s. 1798.105). Please delete the personal information you
   have collected from me, and direct your service providers, contractors and
   third parties to do the same.

3. RIGHT TO OPT OUT (s. 1798.120 and 1798.121). Please cease any sale or sharing
   of my personal information, and limit the use and disclosure of any sensitive
   personal information to what is necessary to provide the services requested.

4. RIGHT TO CORRECT (s. 1798.106). Please correct any inaccurate personal
   information you maintain about me.

A data export you previously provided contained ${audit.totalFiles} files totalling
${fmtBytes(audit.totalBytes)}. Please confirm whether that export constitutes the complete
set of personal information you hold, including inferred characteristics, which
are personal information under s. 1798.140(v)(1)(K).

Please respond within 45 days as required by s. 1798.130(a)(2).

Sincerely,
${name}
${email}`;
}


/** GDPR Art. 12(3): one month. CCPA s.1798.130(a)(2): 45 days. */
export function deadlines(from = new Date()) {
  const gdpr = new Date(from); gdpr.setMonth(gdpr.getMonth() + 1);
  const ccpa = new Date(from); ccpa.setDate(ccpa.getDate() + 45);
  return {
    gdpr: gdpr.toISOString().slice(0, 10),
    ccpa: ccpa.toISOString().slice(0, 10),
  };
}

/**
 * Escalation to a supervisory authority under Art. 77. This is the step that
 * gives an Art. 15 or 17 request teeth: without a credible route to a regulator,
 * a controller can simply not reply.
 */
export function dpaComplaint({ name, email, platform, audit, sentOn }) {
  const d = sentOn || '[DATE YOU SENT THE ORIGINAL REQUEST]';
  const due = sentOn ? deadlines(new Date(sentOn)).gdpr : '[ONE MONTH AFTER THAT DATE]';
  return `Date: ${today()}
To: [YOUR SUPERVISORY AUTHORITY]
From: ${name} <${email}>
Subject: Complaint under Article 77 GDPR concerning ${platform}

Dear Sir or Madam,

I am lodging a complaint under Article 77(1) of the General Data Protection
Regulation. I consider that the processing of personal data relating to me by
${platform} infringes the Regulation.

BACKGROUND

On ${d} I submitted a request to ${platform} under [Article 15 / Article 17].
Under Article 12(3), the controller was required to provide information on action
taken without undue delay and in any event within one month of receipt, that is by
${due}.

[Select the applicable ground:]
  - No response was received within the period required by Article 12(3).
  - A response was received but was incomplete, in that it omitted the following:
    [list]
  - The request was refused without the controller identifying the specific
    exemption relied upon.

GROUNDS OF COMPLAINT

1. Failure to comply with Article 12(3) as to time limits.
2. Failure to provide the supplementary information required by Article 15(1)(a)
   to (h), in particular the recipients under 15(1)(c) and the existence of
   automated decision-making under 15(1)(h).
3. Failure to provide inferred and derived personal data. Data inferred about a
   data subject is personal data within Article 4(1). A data export that omits
   advertising interest categories and predicted attributes is not a complete
   response to an Article 15 request.

EVIDENCE

I have retained the data export provided to me by the controller, comprising
${audit.totalFiles} files totalling ${fmtBytes(audit.totalBytes)}, together with my original request
and any response received. I can supply these on request.

RELIEF SOUGHT

I ask that the supervisory authority investigate under Article 57(1)(f) and
exercise its corrective powers under Article 58(2) as it sees fit.

Yours faithfully,
${name}
${email}`;
}

export const LETTERS = [
  { id: 'gdpr15', label: 'GDPR Art. 15: access',  build: gdprAccess },
  { id: 'gdpr17', label: 'GDPR Art. 17: erasure', build: gdprErasure },
  { id: 'ccpa',   label: 'CCPA / CPRA requests',   build: ccpaRequest },
  { id: 'dpa',    label: 'Art. 77: complaint to a regulator', build: dpaComplaint },
];
