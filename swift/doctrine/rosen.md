# Rosén Doctrine: The Report as a Story

A vulnerability report is not a form to be filled in. It is the only artifact that survives contact between the researcher and the program, and it does all the work that the researcher cannot do in person: it persuades a triage engineer that this finding is real, that it matters, and that fixing it is worth the engineering time. A report that reads like a database dump — endpoint, payload, response code, CVSS score — fails at this job even when the underlying finding is critical. The Rosén doctrine is built on one observation: the best reports in bug bounty are stories, not lists. They have a beginning (how the researcher found the surface), a middle (the chain of reasoning from interesting to exploitable), and an end (the impact on the business and its users).

## Story Arc Over Structure

Every report has an implicit arc. Discovery: how the researcher arrived at this surface, what drew their attention, what the first signal was that something was wrong. Hypothesis: what the researcher believed was possible before they proved it — this is what separates a researcher from a fuzzer. Escalation: the chain of reasoning from "this parameter is reflected" to "this parameter controls an OAuth redirect with a loose matching regex that allows subdomain prefix bypass." Impact: what an attacker can actually do with this, in business terms that a non-technical reader can follow. Resolution: what the fix looks like in concrete, actionable terms. The arc matters because it mirrors the reader's decision process. A triage engineer reading a good report moves from curiosity to conviction to action without having to reconstruct the researcher's reasoning independently.

## Discovery Section

The discovery section earns the reader's trust by demonstrating that the researcher did real work. It does not need to be long, but it must be specific. "I noticed that the OAuth authorization endpoint accepts a redirect_uri parameter that is validated client-side but not server-side" is a discovery. "I found a vulnerability in the OAuth flow" is not. The discovery section should answer: what surface were you looking at, what drew your attention, and what was the first observation that made you think there was something worth investigating? Showing the reasoning — "the SPF record for example.com includes sendgrid.net, which suggested a third-party email flow; investigating that flow revealed..." — demonstrates a depth of recon that builds credibility with the program.

## Hypothesis Section

The hypothesis section is often omitted and always missed when it is. It states what the researcher believed was possible before they had proof, and it invites the reader to follow the reasoning rather than simply observe the conclusion. A hypothesis section does two things: it shows that the researcher has a mental model of the vulnerability class (not just a lucky payload), and it makes the reproduction steps that follow legible — the reader understands what each step is testing for. The hypothesis should be falsifiable and specific: "I hypothesized that the state parameter in the OAuth flow was validated only for format, not for binding to the initiating session, which would allow a state parameter from one session to be replayed in another."

## Escalation Narrative

The escalation section is where the researcher shows their chain. Bug bounty triage is full of reports that start with a promising observation and end with "this is critical" without any intermediate steps. The Rosén approach is to make every link in the chain explicit: observation → inference → test → confirmation → next inference → next test. The reader should be able to stop at any point and understand where they are in the chain and why the next step follows from the previous one. This matters practically because it makes the report defensible — if the program disputes the severity, the researcher can point to specific links in the chain rather than arguing from the conclusion.

## Impact Section

Business impact comes first, always. Technical impact — "this allows reading of arbitrary files from the server filesystem" — is necessary but not sufficient. Business impact answers the question that a program manager or CISO actually cares about: what can an attacker do to this company and its customers? Quantify wherever possible: "any authenticated user can read the personal data of any other user," "an attacker who controls a single merchant account can exfiltrate payment data for all merchants in the same region," "this allows account takeover for any user whose email address is known." CVSS scores are not impact — they are a shorthand that programs use internally. A report that leads with "CVSS 9.3 Critical" and follows with a technical description of the bug has not communicated impact; it has deferred it.

## Reproduction Steps

Reproduction steps should be executable by a tired triage engineer in under ten minutes, with no prior context. The target length is three to five steps. Each step is a single action with an expected result. The exact HTTP request and response should be included — not a screenshot of Burp Suite, but the actual request text that can be replayed. Steps that require special tooling should specify the exact command. Steps that depend on prior state (an account at a specific privilege level, a specific feature flag enabled) should state that dependency explicitly at the top of the reproduction section, not buried in step three.

## Fix Section

The fix section should be specific enough that a developer can implement it without further research. "Implement proper validation" is not a fix. "Validate that the redirect_uri parameter exactly matches one of the pre-registered redirect URIs for the client_id in the authorization request, using exact string comparison rather than prefix matching" is a fix. Where the fix involves a configuration change rather than a code change, name the specific configuration option. Where the fix has a known implementation pattern in the target framework, reference it. The researcher who provides a concrete, minimal fix is doing the program a service that compounds goodwill across future reports.

## Triage Empathy

The best reports are written with the triage engineer's experience explicitly in mind. Triage is high-volume, time-pressured work. The engineer reading the report may have no prior context on this feature, may be reviewing twenty other reports the same day, and may be doing this work outside their primary engineering role. A report written with this reader in mind is shorter where possible, more precise where necessary, and structured so that the most important information — impact and reproduction — is findable without reading the entire document linearly.

## The Rosén Test

Before submitting, read the first paragraph of the report. If a non-technical product manager cannot understand what the impact is from that first paragraph alone, rewrite the impact section until they can. The report does not need to be simple — the technical details belong in the body — but the impact must be legible to a non-technical reader from the opening. This is the test that separates reports that get triaged quickly from reports that sit in a queue while the engineer tries to understand why they should care.

---

*A great report is not evidence of a bug — it's evidence of understanding.*
