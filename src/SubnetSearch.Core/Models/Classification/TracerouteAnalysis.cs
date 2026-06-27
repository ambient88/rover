namespace SubnetSearch.Core.Models.Classification;

public enum HopKind { Normal, ProxyCdn, Timeout }

public record TracerouteHopAnalysis(
    TracerouteHop Hop,
    string?  Ptr,
    HopKind  Kind,
    string?  ProxyHint  // "Cloudflare CDN", "Akamai", "CDN", etc.
);

public record TracerouteAnalysis(
    IReadOnlyList<TracerouteHopAnalysis> Hops,
    bool    LikelyHiddenRoute,
    int     TrailingTimeouts,
    string? HiddenBehind  // name of the proxy/CDN hiding the route
);
