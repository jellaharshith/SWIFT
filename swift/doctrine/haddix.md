# Haddix Methodology: Recon as a Mindset

The single most common mistake in offensive security — and especially in bug bounty — is probing before mapping. An operator who fires off a scanner against the first subdomain they find has already lost. They have traded depth for speed in a market where depth is the only scarce resource. The Haddix methodology begins with a principle that sounds obvious but is rarely practiced: expand the surface completely before you touch any of it. Every minute spent on enumeration before probing is an investment that compounds — the operator who maps more surface finds the edges that everyone else ignores, and the edges are where the high-severity bugs live.

## Subdomain Enumeration Layers

Passive enumeration runs first and costs nothing. Certificate Transparency logs (crt.sh, censys.io, certspotter) reveal every domain a certificate has been issued to, including development, staging, and internal-facing names that the organization never intended to be indexed. Shodan and Censys surface hosts by banner, certificate, and autonomous system — they find servers that DNS never points to. The chaos project aggregates passive subdomain data from multiple sources into a single queryable API. These passive sources are combined, deduplicated, and resolved before any active work begins.

Active enumeration runs second, after passive sources are exhausted. DNS brute-force with curated wordlists — SecLists combined with target-specific custom lists — finds names that passive sources missed because they were never in a certificate or a crawl. Permutation tools like altdns and gotator generate plausible mutations of known subdomains: `api.target.com` → `api-v2.target.com`, `dev-api.target.com`, `api-staging.target.com`. Reverse DNS sweeps over known IP ranges reveal hosts that resolve to no public DNS record at all. Zone transfer attempts are low-cost and occasionally still succeed against misconfigured nameservers.

## Asset Discovery Beyond DNS

The attack surface extends well past DNS. SPF records are infrastructure maps: every `include:` directive names a third-party sending service that has permission to send email on behalf of the domain, and third-party services mean third-party attack surface — shared tenancy assumptions, subdomain takeover vectors, OAuth integrations. ASN pivoting starts from a single registered IP block and expands to the full set of IP ranges the organization owns, including acquisitions that never got rebranded. Acquisition history is worth researching explicitly: a company acquired two years ago may still be running on its original infrastructure with its original security posture, fully in scope because the parent company owns it. GitHub organization search reveals repositories, CI configs, environment variable references, and internal tooling names that feed directly back into the subdomain and credential hunting pipelines.

## JavaScript Analysis Pipeline

Modern web applications leak their own attack surface through JavaScript. The first step is crawling: katana and gospider spider the application following JavaScript-rendered links, API calls, and dynamically loaded resources that a static link crawler misses. The output is a list of JS files and API endpoints that the application actually calls at runtime. The second step is endpoint extraction: LinkFinder and JSluice parse each JS file for URL patterns, API paths, and internal references — strings that look like `/internal/admin/`, `/api/v2/debug`, `/_ah/admin` that the developer included as a constant and never expected to be read. The third step is parameter extraction: every discovered endpoint is analyzed for query and body parameters, especially non-obvious ones. The fourth step is secret detection: regex patterns for AWS access keys, JWT tokens, internal API keys, Slack webhooks, and database connection strings are run against every JS file. JS files fetched from CDNs are not exempt — developers commit secrets to source and the CDN serves them faithfully.

## Content Discovery Layers

Directory and file discovery runs in layers, each layer feeding the next. Common.txt provides broad coverage quickly. Raft-large deepens it. Technology-specific wordlists — generated for the identified framework (Rails, Laravel, Spring, Django) — find paths that generic wordlists miss. The highest-signal wordlist is the one built from the JS analysis: every path fragment discovered in JS becomes a candidate for directory busting. This custom wordlist consistently surfaces endpoints that no published wordlist contains because they are specific to this application.

## Parameter Mining

Hidden parameters are among the highest-yield, lowest-competition targets in bug bounty. Arjun fuzzes endpoints for undocumented query and body parameters by sending large parameter sets and observing response differentiation — a parameter that changes the response exists, even if the application never documents it. Paramspider queries the Wayback Machine for all archived URLs for the target domain and extracts every parameter name ever observed, including parameters from deprecated flows. x8 specializes in HTTP header injection parameter discovery, finding cases where internal proxy or load-balancer headers influence application behavior.

## Wayback Diffing

Deprecated endpoints are a persistent source of vulnerabilities because applications remove UI references to old flows without removing the underlying server-side handler. Wayback Machine diffing compares the current sitemap and JS file contents against archived snapshots from six months, one year, and two years prior. Endpoints that appear in old snapshots but not in the current crawl are candidates for live probing — they may still be accessible, still functional, and no longer reviewed by the security team. Similarly, JS file diffs reveal API endpoints that were removed from the frontend but not from the backend, and configuration values that changed in ways that suggest a security fix that may have been incomplete.

## The Haddix Rule

The first vulnerability you find on a target is almost certainly already reported. The bug bounty programs that pay well are not slow to triage — they have been running for years, and the easy surface has been walked many times. The findings that pay are the ones that require multiple recon steps to discover: the subdomain found by permutation that passive sources missed, the endpoint extracted from a six-month-old archived JS file, the parameter found by Arjun that no other tool generates. The competition in bug bounty is not a race to probe — it is a race to enumerate. The operator who goes deeper in recon consistently finds what the operator who goes straight to probing will never see.

---

*Recon is not a phase — it's a mindset that never stops.*
