using SubnetSearch.Core.Models.Classification;
using SubnetSearch.Network.Recommend;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SubnetSearch.Network;

public class RipeStatClient
{
    private const string Base = "https://stat.ripe.net/data";
    private readonly HttpClient      _http;
    private readonly RipeStatCache?  _cache;

    public RipeStatClient(HttpClient http, RipeStatCache? cache = null)
    {
        _http  = http;
        _cache = cache;
    }

    private record PrefixCacheData(
        [property: JsonPropertyName("v4")] string[] Ipv4,
        [property: JsonPropertyName("v6")] string[] Ipv6);

    private record NeighbourCacheData(
        [property: JsonPropertyName("u")] int Upstream,
        [property: JsonPropertyName("d")] int Downstream);

    // ── ASN info ─────────────────────────────────────────────────────────────

    public async Task<AsnOverview?> GetAsnOverviewAsync(uint asn, CancellationToken ct = default)
    {
        try
        {
            var r = await _http.GetFromJsonAsync<AsnOverviewResponse>(
                $"{Base}/as-overview/data.json?resource=AS{asn}", ct);
            return r?.Status == "ok" ? r.Data : null;
        }
        catch { return null; }
    }

    // ── Country ASN registry ─────────────────────────────────────────────────

    // Returns all routed ASNs registered in the given ISO country code (e.g. "FI", "NL").
    // Used by the country-ASN supplement pipeline to find providers outside PeeringDB's top-N.
    public async Task<IReadOnlyList<uint>> GetCountryAsnsAsync(
        string countryCode, CancellationToken ct = default)
    {
        try
        {
            using var reqCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            reqCts.CancelAfter(TimeSpan.FromSeconds(30));

            var r = await _http.GetFromJsonAsync<CountryAsnsResponse>(
                $"{Base}/country-asns/data.json?resource={Uri.EscapeDataString(countryCode)}&lod=1",
                reqCts.Token);

            if (r?.Status != "ok" || r.Data?.Countries == null || r.Data.Countries.Length == 0)
                return [];

            // Match by resource code — RIPE Stat may return entries in arbitrary order.
            var entry = r.Data.Countries.FirstOrDefault(
                c => string.Equals(c.Resource, countryCode, StringComparison.OrdinalIgnoreCase));
            return entry?.Routed ?? [];
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch { return []; }
    }

    // ── Announced prefixes ────────────────────────────────────────────────────

    public async Task<IReadOnlyList<string>> GetPrefixesAsync(uint asn, CancellationToken ct = default)
    {
        try
        {
            var r = await _http.GetFromJsonAsync<AnnouncedPrefixesResponse>(
                $"{Base}/announced-prefixes/data.json?resource=AS{asn}", ct);
            if (r?.Status != "ok" || r.Data?.Prefixes == null) return [];
            return r.Data.Prefixes
                .Select(p => p.Prefix)
                .Where(p => !string.IsNullOrWhiteSpace(p) && !p.Contains(':'))  // только IPv4
                .Select(p => p!)
                .OrderBy(CidrToSortKey)
                .ToList();
        }
        catch { return []; }
    }

    // Returns both IPv4 and IPv6 prefixes in one request — avoids duplicate RIPE Stat calls.
    public async Task<(IReadOnlyList<string> IPv4, IReadOnlyList<string> IPv6)> GetAllPrefixesAsync(
        uint asn, CancellationToken ct = default)
    {
        string cacheKey = $"pfx_{asn}";
        if (_cache != null && _cache.TryGet(cacheKey, out var cached))
        {
            var d = JsonSerializer.Deserialize<PrefixCacheData>(cached!);
            if (d != null) return (d.Ipv4, d.Ipv6);
        }

        try
        {
            var r = await _http.GetFromJsonAsync<AnnouncedPrefixesResponse>(
                $"{Base}/announced-prefixes/data.json?resource=AS{asn}", ct);
            if (r?.Status != "ok" || r.Data?.Prefixes == null) return ([], []);
            var all = r.Data.Prefixes
                .Select(p => p.Prefix)
                .Where(p => !string.IsNullOrWhiteSpace(p))
                .Select(p => p!)
                .ToList();
            var ipv4 = all.Where(p => !p.Contains(':')).OrderBy(CidrToSortKey).ToList();
            var ipv6 = all.Where(p =>  p.Contains(':')).OrderBy(p => p).ToList();

            _cache?.Set(cacheKey,
                JsonSerializer.Serialize(new PrefixCacheData([.. ipv4], [.. ipv6])));

            return (ipv4, ipv6);
        }
        catch { return ([], []); }
    }

    // Returns (UpstreamCount, DownstreamCount) — proxy for connectivity quality.
    public async Task<(int Upstream, int Downstream)> GetNeighbourCountsAsync(
        uint asn, CancellationToken ct = default)
    {
        string cacheKey = $"nbr_{asn}";
        if (_cache != null && _cache.TryGet(cacheKey, out var cached))
        {
            var d = JsonSerializer.Deserialize<NeighbourCacheData>(cached!);
            if (d != null) return (d.Upstream, d.Downstream);
        }

        try
        {
            var r = await _http.GetFromJsonAsync<NeighboursResponse>(
                $"{Base}/asn-neighbours/data.json?resource=AS{asn}", ct);
            if (r?.Status != "ok" || r.Data?.Neighbours == null) return (0, 0);
            int up   = r.Data.Neighbours.Count(n => n.Type == "left");
            int down = r.Data.Neighbours.Count(n => n.Type == "right");

            _cache?.Set(cacheKey,
                JsonSerializer.Serialize(new NeighbourCacheData(up, down)));

            return (up, down);
        }
        catch { return (0, 0); }
    }

    // ── Upstream neighbours (type = "left") ───────────────────────────────────

    public async Task<IReadOnlyList<uint>> GetUpstreamAsnsAsync(uint asn, CancellationToken ct = default)
    {
        try
        {
            var r = await _http.GetFromJsonAsync<NeighboursResponse>(
                $"{Base}/asn-neighbours/data.json?resource=AS{asn}", ct);
            if (r?.Status != "ok" || r.Data?.Neighbours == null) return [];
            return r.Data.Neighbours
                .Where(n => n.Type == "left")
                .OrderByDescending(n => n.Power)
                .Select(n => n.Asn)
                .Take(10)
                .ToList();
        }
        catch { return []; }
    }

    // ── Bulk holder lookup for upstream ASNs ──────────────────────────────────

    public async Task<IReadOnlyList<ProviderUpstream>> GetUpstreamsAsync(
        IEnumerable<uint> asns, CancellationToken ct = default)
    {
        var results = new System.Collections.Concurrent.ConcurrentBag<ProviderUpstream>();
        await Parallel.ForEachAsync(asns,
            new ParallelOptions { MaxDegreeOfParallelism = 5, CancellationToken = ct },
            async (asn, innerCt) =>
            {
                var info = await GetAsnOverviewAsync(asn, innerCt);
                results.Add(new ProviderUpstream(asn, null, info?.Holder, null));
            });
        return [.. results];
    }

    // ── Search by name ────────────────────────────────────────────────────────

    public async Task<IReadOnlyList<SearchResult>> SearchAsync(string query, CancellationToken ct = default)
    {
        try
        {
            var url = $"{Base}/searchcomplete/data.json?resource={Uri.EscapeDataString(query)}&limit=8";
            var r   = await _http.GetFromJsonAsync<SearchCompleteResponse>(url, ct);
            if (r?.Status != "ok" || r.Data?.Categories == null) return [];

            return r.Data.Categories
                .Where(c => c.Category == "ASNs")
                .SelectMany(c => c.Suggestions ?? [])
                .Where(s => !string.IsNullOrWhiteSpace(s.Value))
                .Select(s =>
                {
                    // label = "AS213520", value = "AS213520", description = "SENKO-AS ..."
                    string numStr = s.Value!.StartsWith("AS", StringComparison.OrdinalIgnoreCase)
                        ? s.Value[2..] : s.Value!;
                    return uint.TryParse(numStr, out uint a)
                        ? new SearchResult(a, s.Description)
                        : null;
                })
                .Where(x => x != null)
                .Select(x => x!)
                .ToList();
        }
        catch { return []; }
    }

    // ── Public types ──────────────────────────────────────────────────────────

    public record AsnOverview(
        [property: JsonPropertyName("holder")]    string? Holder,
        [property: JsonPropertyName("announced")] bool    Announced);

    public record SearchResult(uint Asn, string? Description);

    // ── RPKI validity ratio ───────────────────────────────────────────────────

    // Returns the ratio of RPKI-valid prefixes (0.0–1.0).
    // Samples up to maxSample prefixes to limit request count.
    public async Task<double?> GetRpkiValidityRatioAsync(
        IReadOnlyList<string> prefixes, int maxSample = 5, CancellationToken ct = default)
    {
        if (prefixes.Count == 0) return null;
        var sample  = prefixes.Take(maxSample).ToList();
        int valid   = 0;
        int checked_ = 0;
        foreach (var prefix in sample)
        {
            try
            {
                var r = await _http.GetFromJsonAsync<RpkiValidationResponse>(
                    $"{Base}/rpki-validation/data.json?resource={Uri.EscapeDataString(prefix)}", ct);
                if (r?.Status != "ok" || r.Data?.Status is null) continue;
                checked_++;
                if (r.Data.Status.Equals("valid", StringComparison.OrdinalIgnoreCase))
                    valid++;
            }
            catch { }
        }
        return checked_ > 0 ? (double)valid / checked_ : null;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    // Numeric sort key for CIDR strings — prevents lex order ("100.x" < "5.x") from
    // causing ProviderScorer to probe unresponsive network addresses as anchor IPs.
    private static uint CidrToSortKey(string cidr)
    {
        var slash = cidr.IndexOf('/');
        var ipStr = slash < 0 ? cidr : cidr[..slash];
        if (!System.Net.IPAddress.TryParse(ipStr, out var addr)) return 0;
        var b = addr.GetAddressBytes();
        return (uint)((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]);
    }

    // ── Private JSON models ───────────────────────────────────────────────────

    private record AsnOverviewResponse(
        [property: JsonPropertyName("status")] string?     Status,
        [property: JsonPropertyName("data")]   AsnOverview? Data);

    private record AnnouncedPrefixesResponse(
        [property: JsonPropertyName("status")] string?             Status,
        [property: JsonPropertyName("data")]   AnnouncedPrefixData? Data);

    private record AnnouncedPrefixData(
        [property: JsonPropertyName("prefixes")] PrefixEntry[]? Prefixes);

    private record PrefixEntry(
        [property: JsonPropertyName("prefix")] string? Prefix);

    private record NeighboursResponse(
        [property: JsonPropertyName("status")] string?         Status,
        [property: JsonPropertyName("data")]   NeighboursData? Data);

    private record NeighboursData(
        [property: JsonPropertyName("neighbours")] NeighbourEntry[]? Neighbours);

    private record NeighbourEntry(
        [property: JsonPropertyName("asn")]   uint   Asn,
        [property: JsonPropertyName("type")]  string? Type,
        [property: JsonPropertyName("power")] int    Power);

    private record SearchCompleteResponse(
        [property: JsonPropertyName("status")] string?             Status,
        [property: JsonPropertyName("data")]   SearchCompleteData? Data);

    private record SearchCompleteData(
        [property: JsonPropertyName("categories")] SearchCategory[]? Categories);

    private record SearchCategory(
        [property: JsonPropertyName("category")]    string?           Category,
        [property: JsonPropertyName("suggestions")] SearchSuggestion[]? Suggestions);

    private record SearchSuggestion(
        [property: JsonPropertyName("value")]       string? Value,
        [property: JsonPropertyName("description")] string? Description);

    private record RpkiValidationResponse(
        [property: JsonPropertyName("status")] string?             Status,
        [property: JsonPropertyName("data")]   RpkiValidationData? Data);

    private record RpkiValidationData(
        [property: JsonPropertyName("status")] string? Status);

    private record CountryAsnsResponse(
        [property: JsonPropertyName("status")] string?          Status,
        [property: JsonPropertyName("data")]   CountryAsnsData? Data);

    private record CountryAsnsData(
        [property: JsonPropertyName("countries")] CountryAsnsEntry[]? Countries);

    private record CountryAsnsEntry(
        [property: JsonPropertyName("resource")] string? Resource,
        [property: JsonPropertyName("routed")]   uint[]? Routed);
}
