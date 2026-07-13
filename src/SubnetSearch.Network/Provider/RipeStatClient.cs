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

    private record RpkiCacheData(
        [property: JsonPropertyName("r")] double? Ratio);

    // ── ASN info ─────────────────────────────────────────────────────────────

    public async Task<AsnOverview?> GetAsnOverviewAsync(uint asn, CancellationToken ct = default)
    {
        try
        {
            using var reqCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            reqCts.CancelAfter(TimeSpan.FromSeconds(2));
            var r = await _http.GetFromJsonAsync<AsnOverviewResponse>(
                $"{Base}/as-overview/data.json?resource=AS{asn}", reqCts.Token);
            return r?.Status == "ok" ? r.Data : null;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
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
            reqCts.CancelAfter(TimeSpan.FromSeconds(2));

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
        var (_, ipv4, _) = await GetAllPrefixesAsync(asn, ct);
        return ipv4;
    }

    // Returns both IPv4 and IPv6 prefixes in one request — avoids duplicate RIPE Stat calls.
    // Ok = false означает «источник упал» (HTTP-сбой / не-ok статус / битый ответ) —
    // вызывающий НЕ должен трактовать пустые списки при Ok = false как авторитетное
    // «префиксов нет» (WR-01: иначе транзиентный сбой ставит негативный маркер pfx0_).
    public async Task<(bool Ok, IReadOnlyList<string> IPv4, IReadOnlyList<string> IPv6)> GetAllPrefixesAsync(
        uint asn, CancellationToken ct = default)
    {
        string cacheKey = $"pfx_{asn}";
        if (TryGetCachedPrefixes(asn, out var cachedIpv4, out var cachedIpv6))
            return (true, cachedIpv4, cachedIpv6);

        try
        {
            using var reqCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            reqCts.CancelAfter(TimeSpan.FromSeconds(2));
            var r = await _http.GetFromJsonAsync<AnnouncedPrefixesResponse>(
                $"{Base}/announced-prefixes/data.json?resource=AS{asn}", reqCts.Token);
            if (r?.Status != "ok" || r.Data?.Prefixes == null) return (false, [], []);
            var all = r.Data.Prefixes
                .Select(p => p.Prefix)
                .Where(p => !string.IsNullOrWhiteSpace(p))
                .Select(p => p!)
                .ToList();
            var ipv4 = all.Where(p => !p.Contains(':')).OrderBy(CidrToSortKey).ToList();
            var ipv6 = all.Where(p =>  p.Contains(':')).OrderBy(p => p).ToList();

            _cache?.Set(cacheKey,
                JsonSerializer.Serialize(new PrefixCacheData([.. ipv4], [.. ipv6])));

            return (true, ipv4, ipv6);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch { return (false, [], []); }
    }

    public bool TryGetCachedPrefixes(
        uint asn,
        out IReadOnlyList<string> ipv4,
        out IReadOnlyList<string> ipv6)
    {
        ipv4 = [];
        ipv6 = [];
        if (_cache == null || !_cache.TryGet($"pfx_{asn}", out var cached))
            return false;
        try
        {
            var data = JsonSerializer.Deserialize<PrefixCacheData>(cached!);
            if (data == null) return false;
            ipv4 = data.Ipv4;
            ipv6 = data.Ipv6;
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    // Persists prefixes obtained from a fallback source (BGPView) under the same pfx_{asn}
    // key, so a fallback ASN is served from cache instead of re-running the throttled
    // fallback request on every run.
    public void CachePrefixes(uint asn, IReadOnlyList<string> ipv4, IReadOnlyList<string> ipv6)
        => _cache?.Set($"pfx_{asn}",
            JsonSerializer.Serialize(new PrefixCacheData([.. ipv4], [.. ipv6])));

    // pfx0_{asn}: negative marker — both RIPE Stat and the fallback source returned no IPv4.
    // Lets callers skip the throttled fallback for known-empty ASNs within the cache TTL.
    public bool IsKnownEmpty(uint asn)
        => _cache != null && _cache.TryGet($"pfx0_{asn}", out _);

    // ttl == null → TTL кэша по умолчанию (24ч, подтверждённая пустота);
    // короткий ttl — для неподтверждённой (источник сбоил), чтобы ASN не долбил
    // троттленный BGPView каждый прогон, но и не замораживался на сутки (WR-01).
    public void MarkEmpty(uint asn, TimeSpan? ttl = null)
    {
        if (ttl.HasValue) _cache?.Set($"pfx0_{asn}", "1", ttl.Value);
        else              _cache?.Set($"pfx0_{asn}", "1");
    }

    // Returns (UpstreamCount, DownstreamCount) — proxy for connectivity quality.
    public async Task<(int Upstream, int Downstream)> GetNeighbourCountsAsync(
        uint asn, CancellationToken ct = default)
    {
        string cacheKey = $"nbr_{asn}";
        if (TryGetCachedNeighbourCounts(asn, out var cachedCounts))
            return cachedCounts;

        try
        {
            using var reqCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            reqCts.CancelAfter(TimeSpan.FromSeconds(2));
            var r = await _http.GetFromJsonAsync<NeighboursResponse>(
                $"{Base}/asn-neighbours/data.json?resource=AS{asn}", reqCts.Token);
            if (r?.Status != "ok" || r.Data?.Neighbours == null) return (0, 0);
            int up   = r.Data.Neighbours.Count(n => n.Type == "left");
            int down = r.Data.Neighbours.Count(n => n.Type == "right");

            _cache?.Set(cacheKey,
                JsonSerializer.Serialize(new NeighbourCacheData(up, down)));

            return (up, down);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch { return (0, 0); }
    }

    public bool TryGetCachedNeighbourCounts(uint asn, out (int Upstream, int Downstream) counts)
    {
        counts = (0, 0);
        if (_cache == null || !_cache.TryGet($"nbr_{asn}", out var cached))
            return false;
        try
        {
            var data = JsonSerializer.Deserialize<NeighbourCacheData>(cached!);
            if (data == null) return false;
            counts = (data.Upstream, data.Downstream);
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    // ── Upstream neighbours (type = "left") ───────────────────────────────────

    public async Task<IReadOnlyList<uint>> GetUpstreamAsnsAsync(uint asn, CancellationToken ct = default)
    {
        try
        {
            using var reqCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            reqCts.CancelAfter(TimeSpan.FromSeconds(2));
            var r = await _http.GetFromJsonAsync<NeighboursResponse>(
                $"{Base}/asn-neighbours/data.json?resource=AS{asn}", reqCts.Token);
            if (r?.Status != "ok" || r.Data?.Neighbours == null) return [];
            return r.Data.Neighbours
                .Where(n => n.Type == "left")
                .OrderByDescending(n => n.Power)
                .Select(n => n.Asn)
                .Take(10)
                .ToList();
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
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
            using var reqCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            reqCts.CancelAfter(TimeSpan.FromSeconds(2));
            var url = $"{Base}/searchcomplete/data.json?resource={Uri.EscapeDataString(query)}&limit=8";
            var r   = await _http.GetFromJsonAsync<SearchCompleteResponse>(url, reqCts.Token);
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
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch { return []; }
    }

    // ── Public types ──────────────────────────────────────────────────────────

    public record AsnOverview(
        [property: JsonPropertyName("holder")]    string? Holder,
        [property: JsonPropertyName("announced")] bool    Announced);

    public record SearchResult(uint Asn, string? Description);

    // ── RPKI validity ratio ───────────────────────────────────────────────────

    internal static readonly TimeSpan RpkiAuthoritativeTtl = TimeSpan.FromDays(7);
    private const string RpkiKeyPrefix = "rpki_";

    // Existing installations use one stable RPKI entry per ASN.
    public async Task<double?> GetRpkiValidityRatioAsync(
        uint asn, IReadOnlyList<string> prefixes, int maxSample = 5, CancellationToken ct = default)
    {
        var sample = prefixes.Take(maxSample).ToList();
        if (TryGetCachedRpki(asn, sample, out var cachedRatio))
            return cachedRatio;

        string cacheKey = BuildRpkiCacheKey(asn, sample);
        int valid    = 0;
        int checked_ = 0;
        int failures = 0;
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
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch { failures++; }
        }
        double? ratio = checked_ > 0 ? (double)valid / checked_ : null;

        // Partial results expire quickly and complete failures are not cached.
        if (failures == 0)
            _cache?.Set(cacheKey, JsonSerializer.Serialize(new RpkiCacheData(ratio)), RpkiAuthoritativeTtl);
        else if (checked_ > 0)
            _cache?.Set(cacheKey, JsonSerializer.Serialize(new RpkiCacheData(ratio)), TimeSpan.FromHours(1));

        return ratio;
    }

    public bool TryGetCachedRpki(
        uint asn,
        IReadOnlyList<string> prefixes,
        out double? ratio)
    {
        ratio = null;
        string cacheKey = BuildRpkiCacheKey(asn, prefixes);
        if (_cache == null || !_cache.TryGet(cacheKey, out var cached))
            return false;
        try
        {
            var data = JsonSerializer.Deserialize<RpkiCacheData>(cached!);
            if (data == null) return false;
            ratio = data.Ratio;
            return true;
        }
        catch (JsonException) { return false; }
    }

    internal static string BuildRpkiCacheKey(uint asn, IEnumerable<string> prefixes)
        => $"{RpkiKeyPrefix}{asn}";

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
