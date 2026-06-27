# Changelog

## v1.2.0-beta.0 — 2026-05-24

### New features

- **`--type cdn` filter** — CDN discovery now returns actual CDN providers (Cloudflare, Akamai, Fastly, CDN77, ACE CDN, CacheFly, Alibaba Cloud CDN). CDN filter is applied *before* scoring so CDN providers aren't crowded out of top-N by large IaaS providers (Microsoft Azure, Amazon, OVH). Diagnostic line shows `After RIPE: N → After CDN filter: M → After scoring: K`.
- **`--country` filter fixed** — country filtering now works correctly for global `-r` searches. PeeringDB's bulk API does not return a `country` field; country is now resolved via ip2asn after enrichment.
- **`--from` coverage pinning** — when `--from` is active, providers with high coverage from the IP list are pinned into the scored result set regardless of their peering count. Providers with many IPs but few IXP peerings (e.g. a cloud provider with 500+ IPs, 11 peerings) are no longer silently eliminated before `--sort coverage` can have any effect. Top-5 (or `--top / 4`) providers by coverage are guaranteed to appear.
- **`asn-exclusions.json`** — ASN exclusion lists (`nonHosting`, `knownCdns`) moved from hardcoded C# sets to a downloadable JSON file (`data/asn-exclusions.json`), updated automatically every 14 days. Falls back to built-in defaults on first run or if download fails. New excluded ASNs: eBay (62955), VeriSign Global Registry (26415), Square Enix (17685), Skyhigh Security (203724).
- **RIPE Stat disk cache** — prefix and neighbour data fetched from RIPE Stat is cached to `ripe_cache.json` (TTL: 24 hours). Repeat runs are significantly faster.
- **`--sort latency` fallback** — when ICMP is blocked and no latency was measured, `--sort latency` now falls back to `score` with a visible warning instead of silently returning misleading results.
- **`--sort coverage` warning** — using `--sort coverage` without `--from` now prints a warning and falls back to `score`.
- **`--preset` validation** — invalid preset names are caught at startup before any network requests.
- **`--country` validation** — invalid country codes (not 2-letter ISO 3166-1 alpha-2) are rejected at startup with a clear error message.
- **Ctrl+C handling** — `SIGINT` now cleanly cancels all in-flight requests and exits with code 130.
- **Proper exit codes** — all error paths now exit with code 1; success exits with code 0; cancellation exits with code 130.
- **Latency note** — a note is shown when all providers have no latency data (ICMP blocked).

### Fixes

- **`--type cdn` supplement bypass** — local hosting database supplement (used for default `-r`) was incorrectly applied for `--type cdn` and `--type transit` searches, injecting wrong provider types into results. Supplement is now skipped when `--type` is set.
- **Coverage display with 0 hits** — `--from` coverage line is now shown for all providers when an IP list is active, even if coverage count is zero.
- **`--from` supplement** — ASNs from the input list that are not found in the main PeeringDB results are now correctly supplemented in all code paths.
- **Mode flag position** — flags are now accepted before the mode (`subnetSearch --abuseipdb-key KEY -r`).

### Improvements

- RIPE Stat enrichment parallelism raised from 5 to 10 concurrent requests.
- PeeringDB IXP region search now handles non-2xx responses gracefully (returns empty instead of throwing).
- `TracerouteAnalyzer` uses `ConcurrentDictionary` for PTR lookups; removed dead code loop.
- `HttpFileDownloader` partial-file tracking uses `ConcurrentDictionary`; `HttpResponseMessage` is now properly disposed.
- `AbuseIpDbClient` throttle semaphore moved from `static` to instance scope.
- `LocalFileStorage` validates file names against path traversal before any read or write.
- `FileMetadataStore` catches only `IOException`/`UnauthorizedAccessException` instead of bare `catch {}`.
- `PingService` parse calls use `InvariantCulture` for locale-safe number parsing; ping subprocess is killed on cancellation.
- PeeringDB "Hosting" info_type removed from bulk fetch (PeeringDB has no networks with this type, eliminating a wasted request).
- Known corporate non-CDN/non-hosting networks (Yahoo, Riot Games, Salesforce, Dropbox) added to permanent exclusion list.

---

## v1.1.0 — earlier

See git log.
