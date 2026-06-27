using SubnetSearch.Core.Models.Classification;
using System.Text.RegularExpressions;

namespace SubnetSearch.Classification;

// Все правила классификации сосредоточены здесь, чтобы их можно было менять
// без касания логики классификатора (OCP).
internal static class ClassificationRules
{
    // HostingType.Unknown signals that no pattern matched — callers move to the next layer.
    // Patterns are ordered from most specific to least specific.
    private const RegexOptions RxOpts = RegexOptions.IgnoreCase | RegexOptions.Compiled;

    private static readonly (Regex Pattern, HostingType Type)[] PtrPatterns =
    [
        // CDN — well-known provider domains
        (new Regex(@"\.cloudfront\.net\.?$",         RxOpts), HostingType.Cdn),
        (new Regex(@"\.akamaiedge\.net\.?$",         RxOpts), HostingType.Cdn),
        (new Regex(@"\.akadns\.net\.?$",             RxOpts), HostingType.Cdn),
        (new Regex(@"\.akamaized\.net\.?$",          RxOpts), HostingType.Cdn),
        (new Regex(@"\.fastly\.net\.?$",             RxOpts), HostingType.Cdn),
        (new Regex(@"\.fastlylb\.net\.?$",           RxOpts), HostingType.Cdn),
        (new Regex(@"\.cloudflare\.net\.?$",         RxOpts), HostingType.Cdn),
        (new Regex(@"\.edgecast\.net\.?$",           RxOpts), HostingType.Cdn),
        (new Regex(@"\.b-cdn\.net\.?$",              RxOpts), HostingType.Cdn),
        (new Regex(@"(?:^|\.|\-)cdn(?:\.|-)|\bcdn\b",RxOpts), HostingType.Cdn),

        // Cloud — well-known cloud platforms
        (new Regex(@"\.compute\.amazonaws\.com\.?$", RxOpts), HostingType.Cloud),
        (new Regex(@"\.ec2\.internal\.?$",           RxOpts), HostingType.Cloud),
        (new Regex(@"\.cloudapp\.azure\.com\.?$",    RxOpts), HostingType.Cloud),
        (new Regex(@"\.cloudapp\.net\.?$",           RxOpts), HostingType.Cloud),
        (new Regex(@"\.googleusercontent\.com\.?$",  RxOpts), HostingType.Cloud),
        (new Regex(@"\.cloud\.google\.com\.?$",      RxOpts), HostingType.Cloud),
        (new Regex(@"\.vultr\.com\.?$",              RxOpts), HostingType.Cloud),
        (new Regex(@"\.linodeusercontent\.com\.?$",  RxOpts), HostingType.Cloud),
        (new Regex(@"\.linode\.com\.?$",             RxOpts), HostingType.Cloud),
        (new Regex(@"\.digitaloceanspaces\.com\.?$", RxOpts), HostingType.Cloud),

        // VPS — delimiters required to avoid false positives like "vpstar", "advds"
        (new Regex(@"(?:^|[.-])vps(?:[.-]|\d)",      RxOpts), HostingType.Vps),
        (new Regex(@"(?:^|[.-])vds(?:[.-]|\d)",      RxOpts), HostingType.Vps),
        (new Regex(@"droplet\.",                      RxOpts), HostingType.Vps),
        (new Regex(@"\.vps\.ovh\.net\.?$",           RxOpts), HostingType.Vps),
        // Generic cloud instance patterns: instance337049.waicore.network, vm-42.provider.com
        // All anchored at ^ — avoids matching ISP infrastructure mid-hostname (vm-agg.isp.net).
        (new Regex(@"^instance\d+\.",                RxOpts), HostingType.Vps),
        (new Regex(@"^vm-?\d+[.-]",                 RxOpts), HostingType.Vps),
        // s<id>.<domain> — numbered server IDs used by small hosters (s263723.h2nexus.net).
        // Requires 3+ digits to avoid collisions with short generic names (s1., s12.).
        (new Regex(@"^s\d{3,}\.",                   RxOpts), HostingType.Vps),

        // Dedicated
        (new Regex(@"\.dedicated\.",                  RxOpts), HostingType.Dedicated),
        (new Regex(@"\.static\.ovh\.net\.?$",        RxOpts), HostingType.Dedicated),
        (new Regex(@"ip\d+\..*\.hetzner\.com\.?$",   RxOpts), HostingType.Dedicated),
        (new Regex(@"static\..*\.hetzner\.com\.?$",  RxOpts), HostingType.Dedicated),
        (new Regex(@"(?:^|[.-])server\d+[.-]",       RxOpts), HostingType.Dedicated),

        // Shared
        (new Regex(@"(?:^|[.-])shared[.-]",          RxOpts), HostingType.Shared),

        // Colocation
        (new Regex(@"(?:^|[.-])colo[.-]",            RxOpts), HostingType.Colocation),

        // DDoS Protection
        (new Regex(@"ddos-guard",                    RxOpts), HostingType.DdosProtection),
        (new Regex(@"qrator\.net\.?$",               RxOpts), HostingType.DdosProtection),
        (new Regex(@"stormwall",                     RxOpts), HostingType.DdosProtection),

        // Proxy / Exit node
        (new Regex(@"(?:^|[.-])tor-exit[.-]",        RxOpts), HostingType.Proxy),
        (new Regex(@"tor\.exit\.",                   RxOpts), HostingType.Proxy),
        (new Regex(@"(?:^|[.-])proxy[.-]",           RxOpts), HostingType.Proxy),
    ];
    public static readonly HashSet<string> NonHostingOrgs = new(StringComparer.OrdinalIgnoreCase)
    {
        "Google", "Google LLC", "GOOGLE",
        "Microsoft Corporation", "MICROSOFT",
        "Cloudflare, Inc.", "CLOUDFLARE",
        "Apple Inc.",
        "Facebook, Inc.",
    };

    // ASNs of well-known CDN providers — shown as Type=CDN even when IsHosting=false.
    public static readonly HashSet<uint> CdnAsns = [
        13335,  // Cloudflare, Inc.
        209242, // Cloudflare WARP
        20940,  // Akamai Technologies
        16625,  // Akamai Technologies, Inc.
        54113,  // Fastly
        22822,  // Limelight Networks / Edgio
        15169,  // Google (primarily CDN/search, not hosting)
        32934,  // Meta Platforms (CDN, not server hosting)
    ];

    public static readonly HashSet<string> KnownHostingOrgs = new(StringComparer.OrdinalIgnoreCase)
    {
        "AWS", "Amazon", "DigitalOcean", "Hetzner",
        "OVH", "Linode", "Alibaba Cloud", "Tencent Cloud",
        "Oracle Cloud", "IBM Cloud", "Rackspace",
        "TimeWeb", "Beget", "Reg.ru", "Vscale", "Selectel",
        "DDoS-Guard", "QRATOR",
        "YANDEXCLOUD", "Yandex.Cloud", "Yandex Cloud", "Yandex.Cloud LLC",
        "Cloud Services Kazakhstan"
    };

    public static readonly HashSet<string> HostingKeywords = new(StringComparer.OrdinalIgnoreCase)
    {
        "hosting", "cloud", "server", "datacenter", "vps", "dedicated", "cdn", "colo", "proxy"
    };

    // Order matters: more specific markers are checked first.
    private static readonly (string Keyword, HostingType Type)[] HostingTypeKeywords =
    [
        ("ddos",      HostingType.DdosProtection),
        ("proxy",     HostingType.Proxy),
        ("cdn",       HostingType.Cdn),
        ("cloud",     HostingType.Cloud),
        ("vps",       HostingType.Vps),
        ("vds",       HostingType.Vps),
        ("vultr",     HostingType.Vps),
        ("choopa",    HostingType.Vps),
        ("linode",    HostingType.Vps),
        ("digitalocean", HostingType.Vps),
        ("hetzner",   HostingType.Dedicated),
        ("dedicated", HostingType.Dedicated),
        ("shared",    HostingType.Shared),
        ("colo",      HostingType.Colocation),
    ];

    // Tier-1 and major backbone providers — their IPs are carrier infrastructure,
    // not rentable server space.
    public static readonly HashSet<uint> BackboneAsns = [
        174,    // Cogent
        701,    // Verizon Business / UUNET
        1239,   // Sprint
        1273,   // Vodafone
        1299,   // Arelion (Telia Carrier)
        2914,   // NTT America
        3257,   // GTT Communications
        3320,   // Deutsche Telekom
        3356,   // Lumen (Level 3)
        3549,   // Lumen (Global Crossing)
        5400,   // BT
        5511,   // Orange / France Telecom
        6453,   // TATA Communications
        6461,   // Zayo (AboveNet)
        6762,   // Telecom Italia Sparkle
        7018,   // AT&T
        12956,  // Telefonica
    ];

    // Router interface PTR patterns — indicate backbone infrastructure IPs, not rentable servers.
    private static readonly Regex[] RouterPtrPatterns =
    [
        new Regex(@"^ae\d+\.",           RxOpts),  // Aggregated Ethernet (GTT: ae2.cr6-cph1...)
        new Regex(@"^xe-\d+",           RxOpts),  // 10GE Juniper
        new Regex(@"^ge-\d+",           RxOpts),  // GigaEthernet Juniper
        new Regex(@"^et-\d+",           RxOpts),  // 100GE Juniper
        new Regex(@"^te\d+[/-]",        RxOpts),  // TenGigE Cisco
        new Regex(@"^hundredge",        RxOpts),  // 100GE Cisco
        new Regex(@"^bundle-ether",     RxOpts),  // Bundle-Ether Cisco
        new Regex(@"\bcr\d+-\w+\d+\.",  RxOpts),  // Core Router (GTT: cr6-cph1)
        new Regex(@"\bpe\d+-\w+\d+\.",  RxOpts),  // Provider Edge Router
        new Regex(@"\.ip4\.[a-z]+\.net\.?$", RxOpts), // GTT backbone: .ip4.gtt.net
        new Regex(@"\.backbone\.",      RxOpts),  // generic backbone label
    ];

    public static bool IsRouterPtr(string? ptr)
    {
        if (string.IsNullOrWhiteSpace(ptr)) return false;
        return RouterPtrPatterns.Any(p => p.IsMatch(ptr));
    }

    // PeeringDB info_type values that unambiguously indicate hosting.
    // NSP (Network Service Provider) = ISP/transit carriers (Rostelecom, AT&T, etc.) —
    // their residential customers are not server renters, so NSP is excluded here.
    // ISP, IXP, Educational, Non-Profit — not hosting.
    public static bool IsHostingPeeringDbType(string? infoType) =>
        infoType?.ToLowerInvariant() is "hosting" or "content";

    // Substring match: "Google Cloud", "Microsoft Azure", etc. are correctly excluded.
    public static bool IsNonHostingOrg(string? org)
    {
        if (string.IsNullOrWhiteSpace(org)) return false;
        return NonHostingOrgs.Any(n => org.Contains(n, StringComparison.OrdinalIgnoreCase));
    }

    public static HostingType? ResolveHostingType(string? org)
    {
        if (string.IsNullOrWhiteSpace(org))
            return null;

        var lower = org.ToLowerInvariant();
        foreach (var (keyword, type) in HostingTypeKeywords)
            if (lower.Contains(keyword))
                return type;

        return HostingType.Unknown;
    }

    // Returns null when no pattern matched — signals the pipeline to move to the next layer.
    public static HostingType? ResolveHostingTypeFromPtr(string? ptr)
    {
        if (string.IsNullOrWhiteSpace(ptr))
            return null;

        foreach (var (pattern, type) in PtrPatterns)
            if (pattern.IsMatch(ptr))
                return type;

        return null;
    }
}
