using System.Net;
using FluentAssertions;
using SubnetSearch.Classification;
using SubnetSearch.Core.Interfaces.Classification;
using SubnetSearch.Core.Interfaces.Whois;
using SubnetSearch.Core.Models.Classification;
using SubnetSearch.Core.Utilities;

namespace SubnetSearch.Tests;

public class HostingClassifierTests
{
    private sealed class StubRange : IHostingIpRangeProvider
    {
        private readonly HostingIpRange? _r;
        public StubRange(HostingIpRange? r) => _r = r;
        public HostingIpRange? Find(uint ip) => _r;
    }

    private sealed class StubWebsite : IWebsiteResolver
    {
        public string? Website { get; set; }
        public PeeringDbNetworkInfo? Info { get; set; }
        public string? GetWebsite(uint? asn, string? org, string? whois = null) => whois ?? Website;
        public Task<PeeringDbNetworkInfo?> GetNetworkInfoFromPeeringDbAsync(uint asn, CancellationToken ct = default)
            => Task.FromResult(Info);
        public Task<IReadOnlyList<string>?> GetIxLocationsAsync(uint asn, CancellationToken ct = default)
            => Task.FromResult<IReadOnlyList<string>?>(null);
    }

    private sealed class StubWhois : IWhoisResolver
    {
        private readonly WhoisResult? _r;
        public StubWhois(WhoisResult? r) => _r = r;
        public Task<WhoisResult?> ResolveAsync(string ip, CancellationToken ct = default) => Task.FromResult(_r);
    }

    private sealed class StubHostingType : IHostingTypeResolver
    {
        public Task<HostingType> ResolveAsync(string ip, uint? asn, string? org, CancellationToken ct = default)
            => Task.FromResult(HostingType.Vps);
    }

    private sealed class StubDns : IDnsResolver
    {
        private readonly string? _ptr;
        public StubDns(string? ptr) => _ptr = ptr;
        public Task<IReadOnlyList<IPAddress>> ResolveAllIpAsync(string d, CancellationToken ct = default)
            => Task.FromResult((IReadOnlyList<IPAddress>)Array.Empty<IPAddress>());
        public Task<string?> ReverseDnsAsync(IPAddress ip, CancellationToken ct = default) => Task.FromResult(_ptr);
    }

    private sealed class StubGeo : IGeolocator
    {
        private readonly GeoLocation? _g;
        public StubGeo(GeoLocation? g) => _g = g;
        public GeoLocation? Locate(string ip) => _g;
        public Task<GeoLocation?> LocateAsync(string ip, CancellationToken ct = default) => Task.FromResult(_g);
        public void Dispose() { }
    }

    private sealed class StubReputation : IIpReputationChecker
    {
        private readonly int? _score;
        public StubReputation(int? score) => _score = score;
        public int? Check(uint ip) => _score;
    }

    private static Ip2AsnRecord Rec(string start, string end, uint asn, string desc) => new()
    {
        StartIp = IpConverter.IpToUint(start), EndIp = IpConverter.IpToUint(end),
        Asn = asn, Country = "DE", Description = desc,
    };

    private static HostingClassifier Build(
        HostingIpRange? range = null,
        Ip2AsnRecord[]? records = null,
        HashSet<uint>? hostingAsns = null,
        IWhoisResolver? whois = null,
        StubWebsite? website = null,
        string? ptr = null,
        GeoLocation? geo = null,
        int? reputation = null)
        => new(
            new StubRange(range),
            new IpRangeIndex(records ?? Array.Empty<Ip2AsnRecord>()),
            hostingAsns ?? new HashSet<uint>(),
            new HashSet<uint>(),
            website ?? new StubWebsite(),
            whois,
            forceWhois: false,
            new StubHostingType(),
            new StubDns(ptr),
            geo != null ? new StubGeo(geo) : null,
            reputation.HasValue ? new StubReputation(reputation) : null);

    [Fact]
    public async Task Classify_HostingRangeHit_IsHosting()
    {
        var range = new HostingIpRange
        {
            StartIp = IpConverter.IpToUint("5.6.7.0"), EndIp = IpConverter.IpToUint("5.6.7.255"),
            ProviderName = "RangeHost", Website = "https://rangehost.example",
        };
        var sut = Build(range: range);

        var r = await sut.ClassifyAsync("5.6.7.8");

        r.IsHosting.Should().BeTrue();
        r.Source.Should().Be("HostingRangeDB");
        r.Organization.Should().Be("RangeHost");
        r.Website.Should().Be("https://rangehost.example");
    }

    [Fact]
    public async Task Classify_Ip2AsnHit_AsnInHostingSet_IsHosting()
    {
        var sut = Build(
            records: new[] { Rec("5.6.7.0", "5.6.7.255", 64500, "Blue Widget Co") },
            hostingAsns: new HashSet<uint> { 64500 });

        var r = await sut.ClassifyAsync("5.6.7.8");

        r.IsHosting.Should().BeTrue();
        r.Source.Should().Be("IP2ASN");
        r.Organization.Should().Be("Blue Widget Co");
        r.Asn.Should().Be(64500u);
    }

    [Fact]
    public async Task Classify_Ip2AsnHit_NotHosting_StaysNonHosting()
    {
        var sut = Build(
            records: new[] { Rec("5.6.7.0", "5.6.7.255", 64501, "Zeta Manufacturing GmbH") },
            hostingAsns: new HashSet<uint>());

        var r = await sut.ClassifyAsync("5.6.7.8");

        r.IsHosting.Should().BeFalse();
        r.Source.Should().Be("IP2ASN");
    }

    // F12: a curated CDN ASN (Akamai 20940) must win over the generic as.json "hosting" category.
    // Akamai's org string is not in NonHostingOrgs, so only the ASN-based CDN override applies.
    [Fact]
    public async Task Classify_CuratedCdnAsn_OverridesHostingCategory()
    {
        var sut = Build(
            records: new[] { Rec("23.1.2.0", "23.1.2.255", 20940, "Akamai Technologies") },
            hostingAsns: new HashSet<uint> { 20940 }); // as.json marks it hosting — must be overridden

        var r = await sut.ClassifyAsync("23.1.2.5");

        r.IsHosting.Should().BeFalse("a curated CDN is not rentable hosting");
        r.HostingType.Should().Be(HostingType.Cdn, "it is tagged as CDN instead");
    }

    [Fact]
    public async Task Classify_NoRangeNoIp2Asn_WhoisFallback()
    {
        var whois = new StubWhois(new WhoisResult(
            "SomeNetwork LLC", "FR", null, null, null, "active", "raw", Rir: "RIPE"));
        var sut = Build(records: Array.Empty<Ip2AsnRecord>(), whois: whois);

        var r = await sut.ClassifyAsync("9.9.9.9");

        r.Source.Should().Be("WHOIS");
        r.Organization.Should().Be("SomeNetwork LLC");
        r.Country.Should().Be("FR");
    }

    [Fact]
    public async Task Classify_NothingMatches_Unknown()
    {
        var sut = Build(records: Array.Empty<Ip2AsnRecord>(), whois: null);

        var r = await sut.ClassifyAsync("9.9.9.9");

        r.IsHosting.Should().BeFalse();
        r.Source.Should().Be("Unknown");
    }

    [Fact]
    public async Task Classify_AppliesGeolocation()
    {
        var sut = Build(
            records: new[] { Rec("5.6.7.0", "5.6.7.255", 64500, "Blue Widget Co") },
            hostingAsns: new HashSet<uint> { 64500 },
            geo: new GeoLocation("Frankfurt", "HE", 50.1, 8.6, Country: "DE"));

        var r = await sut.ClassifyAsync("5.6.7.8");

        r.City.Should().Be("Frankfurt");
        r.Latitude.Should().Be(50.1);
        r.Country.Should().Be("DE", "geo-country has priority over ip2asn");
    }

    [Fact]
    public async Task Classify_PassesReputationScore()
    {
        var sut = Build(
            records: new[] { Rec("5.6.7.0", "5.6.7.255", 64500, "Blue Widget Co") },
            hostingAsns: new HashSet<uint> { 64500 },
            reputation: 5);

        (await sut.ClassifyAsync("5.6.7.8")).ReputationScore.Should().Be(5);
    }

    [Fact]
    public async Task Classify_InvalidIp_ReturnsErrorSource()
    {
        var r = await Build().ClassifyAsync("definitely-not-an-ip");

        r.IsHosting.Should().BeFalse();
        r.Source.Should().StartWith("Error");
    }
}
