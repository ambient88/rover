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
        public int ReverseCalls { get; private set; }
        public StubDns(string? ptr) => _ptr = ptr;
        public Task<IReadOnlyList<IPAddress>> ResolveAllIpAsync(string d, CancellationToken ct = default)
            => Task.FromResult((IReadOnlyList<IPAddress>)Array.Empty<IPAddress>());
        public Task<string?> ReverseDnsAsync(IPAddress ip, CancellationToken ct = default)
        {
            ReverseCalls++;
            return Task.FromResult(_ptr);
        }
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
    public async Task Classify_HostingTypeAndResultShareOnePtrLookup()
    {
        var range = new HostingIpRange
        {
            StartIp = IpConverter.IpToUint("5.6.7.0"),
            EndIp = IpConverter.IpToUint("5.6.7.255"),
            ProviderName = "RangeHost"
        };
        var dns = new StubDns("vm-42.rangehost.example");
        var website = new StubWebsite();
        var sut = new HostingClassifier(
            new StubRange(range),
            new IpRangeIndex([Rec("5.6.7.0", "5.6.7.255", 64500, "RangeHost")]),
            [64500],
            [],
            website,
            null,
            false,
            new HostingTypeResolver(dns, website),
            dns);

        var result = await sut.ClassifyAsync("5.6.7.8");

        dns.ReverseCalls.Should().Be(1);
        result.Ptr.Should().Be("vm-42.rangehost.example");
        result.HostingType.Should().Be(HostingType.Vps);
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

    [Fact]
    public async Task Classify_CuratedCdnAsn_OverridesHostingCategory()
    {
        var sut = Build(
            records: new[] { Rec("23.1.2.0", "23.1.2.255", 20940, "Akamai Technologies") },
            hostingAsns: new HashSet<uint> { 20940 });

        var r = await sut.ClassifyAsync("23.1.2.5");

        r.IsHosting.Should().BeFalse("a curated CDN is not rentable hosting");
        r.HostingType.Should().Be(HostingType.Cdn, "it is tagged as CDN instead");
    }

    [Fact]
    public async Task Classify_CuratedCdnAsn_OverridesHostingRange()
    {
        var range = new HostingIpRange
        {
            StartIp = IpConverter.IpToUint("23.1.2.0"),
            EndIp = IpConverter.IpToUint("23.1.2.255"),
            ProviderName = "Akamai Technologies"
        };
        var sut = Build(
            range: range,
            records: [Rec("23.1.2.0", "23.1.2.255", 20940, "Akamai Technologies")],
            hostingAsns: [20940]);

        var result = await sut.ClassifyAsync("23.1.2.5");

        result.IsHosting.Should().BeFalse();
        result.HostingType.Should().Be(HostingType.Cdn);
    }

    [Fact]
    public async Task Classify_HostingWithWhois_ResolvesWebsiteAndDates()
    {
        var whois = new StubWhois(new WhoisResult(
            "HostingCorp", "DE", null, new DateTime(2019, 1, 1), new DateTime(2020, 6, 1),
            "active", "raw", AbuseEmail: "abuse@hostingcorp.example", Rir: "RIPE"));
        var website = new StubWebsite { Website = "https://hostingcorp.example" };
        var sut = Build(
            records: new[] { Rec("5.6.7.0", "5.6.7.255", 64500, "HostingCorp") },
            hostingAsns: new HashSet<uint> { 64500 },
            whois: whois, website: website);

        var r = await sut.ClassifyAsync("5.6.7.8");

        r.IsHosting.Should().BeTrue();
        r.Website.Should().Be("https://hostingcorp.example");
        r.RegistrationDate.Should().Be(new DateTime(2019, 1, 1));
        r.AbuseEmail.Should().Be("abuse@hostingcorp.example");
    }

    [Fact]
    public async Task Classify_Hosting_PopulatesPeeringCountFromPeeringDb()
    {
        var website = new StubWebsite
        {
            Info = new PeeringDbNetworkInfo("https://hostco.example", "content", IxCount: 7, NetId: 99),
        };
        var sut = Build(
            records: new[] { Rec("5.6.7.0", "5.6.7.255", 64500, "HostCo") },
            hostingAsns: new HashSet<uint> { 64500 },
            website: website);

        var r = await sut.ClassifyAsync("5.6.7.8");

        r.IsHosting.Should().BeTrue();
        r.PeeringCount.Should().Be(7);
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

    // WHOIS org that is a known non-hosting org flips an IP2ASN "hosting" verdict back to false.
    [Fact]
    public async Task Classify_WhoisNonHostingOrg_OverridesHosting()
    {
        var whois = new StubWhois(new WhoisResult(
            "Google LLC", "US", null, null, null, "active", "raw", Rir: "ARIN"));
        var sut = Build(
            records: new[] { Rec("5.6.7.0", "5.6.7.255", 64500, "SomeHost") },
            hostingAsns: new HashSet<uint> { 64500 },
            whois: whois);

        var r = await sut.ClassifyAsync("5.6.7.8");

        r.IsHosting.Should().BeFalse("WHOIS revealed a non-hosting organization");
    }

    // Unknown ASN (neither hosting nor non-hosting) is upgraded to hosting via the PeeringDB fallback.
    [Fact]
    public async Task Classify_PeeringDbContentType_UpgradesToHosting()
    {
        var website = new StubWebsite
        {
            Info = new PeeringDbNetworkInfo("https://prov.example", "content", IxCount: 4, NetId: 7),
        };
        var sut = Build(
            records: new[] { Rec("5.6.7.0", "5.6.7.255", 64502, "Mystery Networks") },
            hostingAsns: new HashSet<uint>(),
            website: website);

        var r = await sut.ClassifyAsync("5.6.7.8");

        r.IsHosting.Should().BeTrue("PeeringDB info_type=content marks it as hosting");
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

    [Fact]
    public async Task Classify_RouterPtr_DowngradesHostingToInfrastructure()
    {
        var sut = Build(
            records: new[] { Rec("5.6.7.0", "5.6.7.255", 64500, "CarrierHost") },
            hostingAsns: new HashSet<uint> { 64500 },
            ptr: "ae2.cr6-cph1.ip4.gtt.net");

        var r = await sut.ClassifyAsync("5.6.7.8");

        r.IsHosting.Should().BeFalse("a router interface PTR marks backbone gear, not rentable hosting");
    }

    [Fact]
    public async Task Classify_VpsPtr_UpgradesNonHostingAndResolvesWebsite()
    {
        // Core misses hosting (ASN not in the set), but the PTR names a VPS instance.
        var sut = Build(
            records: new[] { Rec("5.6.7.0", "5.6.7.255", 64502, "Quiet Networks") },
            hostingAsns: new HashSet<uint>(),
            ptr: "vm-42.quiethost.example");

        var r = await sut.ClassifyAsync("5.6.7.8");

        r.IsHosting.Should().BeTrue("the PTR explicitly names a VPS instance");
        r.HostingType.Should().Be(HostingType.Vps);
    }

    [Fact]
    public async Task Classify_RangeHitWithNetId_RequestsIxLocations()
    {
        var range = new HostingIpRange
        {
            StartIp = IpConverter.IpToUint("5.6.7.0"), EndIp = IpConverter.IpToUint("5.6.7.255"),
            ProviderName = "RangeHost",
        };
        var website = new StubWebsite
        {
            Info = new PeeringDbNetworkInfo("https://rangehost.example", "hosting", IxCount: 3, NetId: 42),
        };
        var sut = Build(
            range: range,
            records: new[] { Rec("5.6.7.0", "5.6.7.255", 64500, "RangeHost") },
            website: website);

        var r = await sut.ClassifyAsync("5.6.7.8");

        r.PeeringCount.Should().Be(3);
    }

    [Fact]
    public async Task Classify_WhoisHostingOrgWithoutLocalWebsite_FallsBackToPeeringDb()
    {
        // Neither the local map nor WHOIS provide a website, so the PeeringDB path runs.
        var whois = new StubWhois(new WhoisResult(
            "HostingCorp", "DE", null, null, null, "active", "raw", Rir: "RIPE"));
        var sut = Build(
            records: new[] { Rec("5.6.7.0", "5.6.7.255", 64500, "HostingCorp") },
            hostingAsns: new HashSet<uint> { 64500 },
            whois: whois);

        var r = await sut.ClassifyAsync("5.6.7.8");

        r.IsHosting.Should().BeTrue();
        r.Website.Should().BeNull("no source had a website, but the lookup chain must not fail");
    }

    [Fact]
    public async Task Classify_WhoisFallback_NonHostingOrg_ShortCircuits()
    {
        var whois = new StubWhois(new WhoisResult(
            "Google LLC", "US", null, null, null, "active", "raw",
            AbuseEmail: "abuse@google.example", Rir: "ARIN"));
        var sut = Build(records: Array.Empty<Ip2AsnRecord>(), whois: whois);

        var r = await sut.ClassifyAsync("9.9.9.9");

        r.IsHosting.Should().BeFalse();
        r.Source.Should().Be("WHOIS");
        r.Rir.Should().Be("ARIN");
    }

    [Fact]
    public async Task Classify_WhoisFallback_HostingKeywordOrg_ResolvesTypeAndWebsite()
    {
        var whois = new StubWhois(new WhoisResult(
            "SuperHosting Ltd", "BG", "https://superhosting.example", null, null, "active", "raw", Rir: "RIPE"));
        var sut = Build(records: Array.Empty<Ip2AsnRecord>(), whois: whois);

        var r = await sut.ClassifyAsync("9.9.9.9");

        r.IsHosting.Should().BeTrue("the organization name carries a hosting keyword");
        r.Source.Should().Be("WHOIS");
        r.HostingType.Should().Be(HostingType.Vps);
        r.Website.Should().Be("https://superhosting.example");
    }

    [Fact]
    public async Task Classify_WhoisFallback_NullOrganization_EndsUnknown()
    {
        var whois = new StubWhois(new WhoisResult(
            null, "FR", null, null, null, null, "raw"));
        var sut = Build(records: Array.Empty<Ip2AsnRecord>(), whois: whois);

        var r = await sut.ClassifyAsync("9.9.9.9");

        r.Source.Should().Be("Unknown");
    }

    private sealed class ThrowingWhois(Exception ex) : IWhoisResolver
    {
        public Task<WhoisResult?> ResolveAsync(string ip, CancellationToken ct = default) => throw ex;
    }

    [Fact]
    public async Task Classify_CancellationInsideCore_PropagatesInsteadOfErrorResult()
    {
        var sut = Build(
            records: Array.Empty<Ip2AsnRecord>(),
            whois: new ThrowingWhois(new OperationCanceledException()));

        var act = () => sut.ClassifyAsync("9.9.9.9");

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    [Fact]
    public async Task Classify_OutOfMemoryInsideCore_PropagatesInsteadOfErrorResult()
    {
        var sut = Build(
            records: Array.Empty<Ip2AsnRecord>(),
            whois: new ThrowingWhois(new OutOfMemoryException()));

        var act = () => sut.ClassifyAsync("9.9.9.9");

        await act.Should().ThrowAsync<OutOfMemoryException>();
    }

    private sealed class DisposableGeo : IGeolocator
    {
        public int DisposeCalls { get; private set; }
        public GeoLocation? Locate(string ip) => null;
        public void Dispose() => DisposeCalls++;
    }

    private sealed class DisposableResource : IDisposable
    {
        public int DisposeCalls { get; private set; }
        public void Dispose() => DisposeCalls++;
    }

    [Fact]
    public void Dispose_ReleasesGeolocatorAndOwnedResourceOnce()
    {
        var geo = new DisposableGeo();
        var owned = new DisposableResource();
        var sut = new HostingClassifier(
            new StubRange(null), new IpRangeIndex(Array.Empty<Ip2AsnRecord>()),
            [], [], new StubWebsite(), null, false,
            new StubHostingType(), new StubDns(null), geo,
            reputationChecker: null, ownedResource: owned);

        sut.Dispose();
        sut.Dispose();

        geo.DisposeCalls.Should().Be(1, "double dispose must be idempotent");
        owned.DisposeCalls.Should().Be(1);
    }
}
