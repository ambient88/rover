using SubnetSearch.Core.Interfaces.Classification;
using SubnetSearch.Core.Models.Classification;
using SubnetSearch.Network.Http;
using System.Net;

namespace SubnetSearch.Network;

public static class TracerouteAnalyzer
{
    private static readonly string[] CdnPtrKeywords =
    [
        "cloudflare", "akamai", "akadns", "fastly", "edgecast", "cloudfront",
        "limelight", "cdn", "cache", "edge.", "stackpath", "bunnycdn",
        "incapsula", "sucuri", "ddos-guard", "qrator"
    ];

    // Minimum trailing timeouts to consider as a "hidden route" signal.
    private const int HiddenRouteThreshold = 3;

    public static async Task<TracerouteAnalysis> AnalyzeAsync(
        IReadOnlyList<TracerouteHop> hops,
        IDnsResolver dns,
        CancellationToken ct = default)
    {
        if (hops.Count == 0)
            return new TracerouteAnalysis([], false, 0, null);

        // Resolve PTRs for all responding hops in parallel (best-effort, short timeout).
        var respondingHops = hops
            .Where(h => h.IpAddress != null && IPAddress.TryParse(h.IpAddress, out _))
            .DistinctBy(h => h.IpAddress)
            .ToList();

        using var ptrCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        ptrCts.CancelAfter(TimeSpan.FromSeconds(5));

        var ptrMap = new System.Collections.Concurrent.ConcurrentDictionary<string, string?>();
        try
        {
            await Parallel.ForEachAsync(respondingHops,
                new ParallelOptions { MaxDegreeOfParallelism = 8, CancellationToken = ptrCts.Token },
                async (hop, innerCt) =>
                {
                    try
                    {
                        var ptr = await dns.ReverseDnsAsync(IPAddress.Parse(hop.IpAddress!), innerCt);
                        ptrMap[hop.IpAddress!] = ptr;
                    }
                    catch (OperationCanceledException) { throw; }
                    catch { ptrMap[hop.IpAddress!] = null; }
                });
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { }

        var enriched = new List<TracerouteHopAnalysis>(hops.Count);
        foreach (var hop in hops)
        {
            if (hop.IpAddress == null)
            {
                enriched.Add(new TracerouteHopAnalysis(hop, null, HopKind.Timeout, null));
                continue;
            }

            ptrMap.TryGetValue(hop.IpAddress, out string? ptr);
            var (kind, hint) = ClassifyHop(hop.IpAddress, ptr);
            enriched.Add(new TracerouteHopAnalysis(hop, ptr, kind, hint));
        }

        // Count consecutive timeouts at the end of the route.
        int trailing = 0;
        for (int i = enriched.Count - 1; i >= 0; i--)
        {
            if (enriched[i].Kind == HopKind.Timeout) trailing++;
            else break;
        }

        // Hidden route: significant trailing timeouts AND last visible hop is a proxy/CDN.
        var lastVisible = enriched.LastOrDefault(h => h.Kind != HopKind.Timeout);
        bool likelyHidden = trailing >= HiddenRouteThreshold
                         && lastVisible?.Kind == HopKind.ProxyCdn;
        string? hiddenBehind = likelyHidden ? lastVisible?.ProxyHint : null;

        return new TracerouteAnalysis(enriched, likelyHidden, trailing, hiddenBehind);
    }

    private static (HopKind Kind, string? Hint) ClassifyHop(string ip, string? ptr)
    {
        // Cloudflare: exact IP range lookup.
        var cfProduct = CloudflareProductDetector.DetectFromIp(ip);
        if (cfProduct != null)
            return (HopKind.ProxyCdn, $"Cloudflare ({cfProduct})");

        // PTR-based CDN detection.
        if (ptr != null)
        {
            var lower = ptr.ToLowerInvariant();
            if (CdnPtrKeywords.Any(k => lower.Contains(k)))
                return (HopKind.ProxyCdn, ExtractHintFromPtr(lower));
        }

        return (HopKind.Normal, null);
    }

    private static string ExtractHintFromPtr(string lower)
    {
        if (lower.Contains("cloudflare"))                  return "Cloudflare";
        if (lower.Contains("akamai") || lower.Contains("akadns")) return "Akamai";
        if (lower.Contains("fastly"))                      return "Fastly";
        if (lower.Contains("cloudfront"))                  return "AWS CloudFront";
        if (lower.Contains("edgecast"))                    return "Edgecast";
        if (lower.Contains("incapsula"))                   return "Imperva Incapsula";
        if (lower.Contains("sucuri"))                      return "Sucuri";
        if (lower.Contains("ddos-guard"))                  return "DDoS-Guard";
        if (lower.Contains("qrator"))                      return "Qrator";
        return "CDN";
    }
}
