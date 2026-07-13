using FluentAssertions;
using System.Net;
using SubnetSearch.Network;
using SubnetSearch.Network.Http;
using SubnetSearch.Network.Recommend;

namespace SubnetSearch.Tests;

// Офлайн-покрытие server-таксономии: --type алиасы vps/dedicated/server/hosting/cloud дают
// одинаковые PeeringDB info_types (различие членства применяется allowlist'ом, не на info_type).
// Членство server-фильтра проверяется через ServerProviders.IsAllowed (см. ServerProvidersTests) и
// ProviderFinder.ApplyServerAllowlist (тест ниже). Старая subtractive-модель ApplyTaxonomyFilter
// удалена вместе с предикатами Is*Filter.
public class ProviderFinderTests
{
    [Fact]
    public async Task FindByAsnList_LocalPrefixesSkipBgpView()
    {
        var pdbHandler = TestHttpMessageHandler.Always(HttpStatusCode.OK, "{\"data\":[]}");
        var ripeHandler = TestHttpMessageHandler.Always(HttpStatusCode.ServiceUnavailable, "{}");
        var bgpHandler = TestHttpMessageHandler.Always(HttpStatusCode.ServiceUnavailable, "{}");
        using var pdbHttp = new HttpClient(pdbHandler);
        using var ripeHttp = new HttpClient(ripeHandler);
        using var bgpHttp = new HttpClient(bgpHandler);
        var finder = new ProviderFinder(
            pdbHttp,
            new RipeStatClient(ripeHttp),
            bgpView: new BgpViewClient(bgpHttp));
        var localPrefixes = new Dictionary<uint, IReadOnlyList<string>>
        {
            [64500] = ["10.0.0.0/24"]
        };
        var names = new Dictionary<uint, string> { [64500] = "Example" };

        var result = await finder.FindByAsnListAsync(
            [(64500, 1)], localPrefixFallback: localPrefixes, nameFallback: names);

        bgpHandler.Requests.Should().BeEmpty();
        result.Should().ContainSingle();
        result[0].Prefixes.Should().Equal("10.0.0.0/24");
    }

    [Fact]
    public async Task PeeringDbRequests_UseConfiguredKeyPerRequest()
    {
        var authorization = new List<string?>();
        var pdbHandler = TestHttpMessageHandler.Custom(request =>
        {
            authorization.Add(request.Headers.Authorization?.ToString());
            string url = request.RequestUri!.AbsoluteUri;
            string body = url.Contains("/api/ix?", StringComparison.Ordinal)
                ? "{\"data\":[{\"id\":1}]}"
                : "{\"data\":[]}";
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(body)
            };
        });
        using var pdbHttp = new HttpClient(pdbHandler);
        using var ripeHttp = new HttpClient(
            TestHttpMessageHandler.Always(HttpStatusCode.ServiceUnavailable, "{}"));
        var finder = new ProviderFinder(
            pdbHttp, new RipeStatClient(ripeHttp), peeringDbKey: "  secret\r\n");

        await finder.FindGlobalAsync(infoTypes: ["Content"]);
        await finder.FindByRegionAsync("test");
        await finder.FindByAsnListAsync([(64500, 1)]);

        authorization.Should().NotBeEmpty();
        authorization.Should().OnlyContain(value => value == "Api-Key secret");
        pdbHttp.DefaultRequestHeaders.Authorization.Should().BeNull();
    }

    [Theory]
    [InlineData("vps")]
    [InlineData("VPS")]
    [InlineData("dedicated")]
    [InlineData("server")]
    [InlineData("hosting")]
    [InlineData("cloud")]
    public void ResolveInfoTypes_ServerFamily_ReturnsContentNspEnterprise(string type)
    {
        ProviderFinder.ResolveInfoTypes(type).Should().BeEquivalentTo(new[] { "Content", "NSP", "Enterprise" });
    }

    [Fact]
    public void ResolveInfoTypes_Nonsense_ReturnsNull() // валидация не ослаблена (T-2.1-02)
    {
        ProviderFinder.ResolveInfoTypes("nonsense").Should().BeNull();
    }

    [Fact]
    public void ResolveInfoTypes_Null_ReturnsNull()
    {
        ProviderFinder.ResolveInfoTypes(null).Should().BeNull();
    }

    // Регресс: dedicated остаётся «server-подобным» для CDN/AI-исключений (D-03).
    [Theory]
    [InlineData("vps")]
    [InlineData("dedicated")]
    public void ShouldExcludeCdnAndAi_StillTrue_ForVpsAndDedicated(string type)
    {
        ProviderFinder.ShouldExcludeCdn(type).Should().BeTrue();
        ProviderFinder.ShouldExcludeAi(type).Should().BeTrue();
    }

    // ShouldIncludeUnverifiedHostingCandidate: candidates whose local ASN type is unknown
    // (not "hosting"/"cloud", not an explicit reject). Regression coverage for wholesale NSP
    // carriers that used to slip through the local IP-range whitelist unconditionally:
    // Hurricane Electric (AS6939), Colt (AS8220), Equinix (AS15830), M247 (AS9009),
    // DataBank (AS13767) — all PeeringDB info_type=NSP, no positive vpsh tag.

    [Theory]
    [InlineData(true)]  // in whitelist — used to be enough on its own
    [InlineData(false)]
    public void NspCandidate_AlwaysRejected_RegardlessOfWhitelist(bool inWhitelist)
    {
        ProviderFinder.ShouldIncludeUnverifiedHostingCandidate(
            infoType: "NSP", caidaClassification: null, inWhitelist: inWhitelist,
            totalIpCount: 10_000_000, strictContentFilter: false)
            .Should().BeFalse();
    }

    [Theory]
    [InlineData("Enterprise")]
    [InlineData("Transit/Access")]
    public void CaidaNonHostingClass_Rejected_RegardlessOfWhitelist(string caidaClass)
    {
        ProviderFinder.ShouldIncludeUnverifiedHostingCandidate(
            infoType: "Content", caidaClassification: caidaClass, inWhitelist: true,
            totalIpCount: 10_000_000, strictContentFilter: false)
            .Should().BeFalse();
    }

    [Fact]
    public void ContentCandidate_InWhitelist_Passes_EvenWithSmallIpPool()
    {
        ProviderFinder.ShouldIncludeUnverifiedHostingCandidate(
            infoType: "Content", caidaClassification: null, inWhitelist: true,
            totalIpCount: 10, strictContentFilter: false)
            .Should().BeTrue();
    }

    [Fact]
    public void ContentCandidate_NotInWhitelist_PassesOnSize_WhenLenient()
    {
        ProviderFinder.ShouldIncludeUnverifiedHostingCandidate(
            infoType: "Content", caidaClassification: null, inWhitelist: false,
            totalIpCount: 1024, strictContentFilter: false)
            .Should().BeTrue();
    }

    [Fact]
    public void ContentCandidate_NotInWhitelist_RejectedBelowSizeThreshold()
    {
        ProviderFinder.ShouldIncludeUnverifiedHostingCandidate(
            infoType: "Content", caidaClassification: null, inWhitelist: false,
            totalIpCount: 1023, strictContentFilter: false)
            .Should().BeFalse();
    }

    [Fact]
    public void ContentCandidate_NotInWhitelist_RejectedInStrictMode_EvenWithLargeIpPool()
    {
        ProviderFinder.ShouldIncludeUnverifiedHostingCandidate(
            infoType: "Content", caidaClassification: null, inWhitelist: false,
            totalIpCount: 10_000_000, strictContentFilter: true)
            .Should().BeFalse();
    }

    // ── PeeringDB per-ASN кэш (Phase 10, «ещё быстрее»): pdb_{asn} в ripe_cache ──

    [Fact]
    public void SerializePdbNet_RoundTripsFoundRecord() // запись существует в PeeringDB
    {
        var c = new ProviderCandidate(24940, "Hetzner", "DE", "https://hetzner.com", "Content", 87, null, []);
        var json = ProviderFinder.SerializePdbNet(c, found: true);
        var back = ProviderFinder.DeserializePdbNetOrNull(json);
        back.Should().NotBeNull();
        back!.Found.Should().BeTrue();
        back.Name.Should().Be("Hetzner");
        back.Country.Should().Be("DE");
        back.InfoType.Should().Be("Content");
        back.PeeringCount.Should().Be(87);
    }

    [Fact]
    public void SerializePdbNet_RoundTripsNotFound() // негативный кэш: записи нет в PeeringDB
    {
        var json = ProviderFinder.SerializePdbNet(null, found: false);
        var back = ProviderFinder.DeserializePdbNetOrNull(json);
        back.Should().NotBeNull();
        back!.Found.Should().BeFalse();
        back.Name.Should().BeNull();
    }

    [Fact]
    public void DeserializePdbNetOrNull_ToleratesCorruptJson()
        => ProviderFinder.DeserializePdbNetOrNull("{ not json ]").Should().BeNull();

    [Fact]
    public async Task ApplyServerAllowlist_KeepsOnlyCore_DropsEverythingElse() // pure allowlist
    {
        // core: только Hetzner(vps). Ни карьер, ни vpsh-хвост НЕ проходят — гейт убран.
        var basePath = Path.Combine(Path.GetTempPath(), $"sp-{Guid.NewGuid():N}.json");
        File.WriteAllText(basePath, """{"providers":[{"asn":24940,"name":"Hetzner","types":["vps"]}]}""");
        var sp = await ServerProviders.LoadAsync(basePath, basePath + ".x");
        File.Delete(basePath);

        var candidates = new[]
        {
            new ProviderCandidate(24940, "Hetzner", "DE", null, "Content", 1, null, []),
            new ProviderCandidate(31027, "GlobalConnect", "DK", null, "NSP", 1, null, []),
            new ProviderCandidate(215439, "PLAY2GO", "PL", null, null, 1, null, []),
        };

        var kept = ProviderFinder.ApplyServerAllowlist(candidates, "vps", sp)
                                 .Select(c => c.Asn).ToHashSet();

        kept.Should().Contain(24940, "в ядре");
        kept.Should().NotContain(31027, "карьер не в ядре");
        kept.Should().NotContain(215439, "vpsh-хвост больше не проходит автоматически");
    }

    [Theory]
    [InlineData("hosting")] // BL-01: hosting — алиас server, должен применять allowlist
    [InlineData("HOSTING")]
    [InlineData("Server")]  // WR-01: регистр
    [InlineData("SERVER")]
    public async Task ApplyServerAllowlist_HostingAndCaseAliases_ApplyAllowlist(string type)
    {
        var basePath = Path.Combine(Path.GetTempPath(), $"sp-{Guid.NewGuid():N}.json");
        File.WriteAllText(basePath, """{"providers":[{"asn":24940,"name":"Hetzner","types":["vps"]}]}""");
        var sp = await ServerProviders.LoadAsync(basePath, basePath + ".x");
        File.Delete(basePath);

        var candidates = new[]
        {
            new ProviderCandidate(24940, "Hetzner", "DE", null, "Content", 1, null, []),
            new ProviderCandidate(31027, "GlobalConnect", "DK", null, "NSP", 1, null, []),
        };

        var kept = ProviderFinder.ApplyServerAllowlist(candidates, type, sp)
                                 .Select(c => c.Asn).ToHashSet();

        kept.Should().Contain(24940, "ядро видно под алиасом server");
        kept.Should().NotContain(31027, $"allowlist применён для --type {type}");
    }

    [Theory]
    [InlineData("cdn")]
    [InlineData("nsp")]
    [InlineData("ai")]
    [InlineData(null)]
    public async Task ApplyServerAllowlist_NonServerTypes_ReturnInputUnchanged(string? type)
    {
        var basePath = Path.Combine(Path.GetTempPath(), $"sp-{Guid.NewGuid():N}.json");
        File.WriteAllText(basePath, """{"providers":[{"asn":24940,"name":"Hetzner","types":["vps"]}]}""");
        var sp = await ServerProviders.LoadAsync(basePath, basePath + ".x");
        File.Delete(basePath);

        var candidates = new[]
        {
            new ProviderCandidate(24940, "Hetzner", "DE", null, "Content", 1, null, []),
            new ProviderCandidate(31027, "GlobalConnect", "DK", null, "NSP", 1, null, []),
        };

        var kept = ProviderFinder.ApplyServerAllowlist(candidates, type, sp)
                                 .Select(c => c.Asn).ToHashSet();

        kept.Should().BeEquivalentTo(new uint[] { 24940, 31027 }, "не-server тип не трогает набор");
    }

    [Theory]
    [InlineData("vps",       null,        false, true)]   // server + global + no from → core-first
    [InlineData("server",    null,        false, true)]
    [InlineData("cloud",     null,        false, true)]
    [InlineData("dedicated", null,        false, true)]
    [InlineData("VPS",       null,        false, true)]   // регистр
    [InlineData("vps",       "Frankfurt", false, false)]  // region → нет
    [InlineData("vps",       null,        true,  false)]  // --from → нет
    [InlineData("cdn",       null,        false, false)]  // не-server → нет
    [InlineData("nsp",       null,        false, false)]
    [InlineData(null,        null,        false, false)]  // без типа → нет
    public void UseCoreFirstSource_Matrix(string? type, string? region, bool hasFrom, bool expected)
        => ProviderFinder.UseCoreFirstSource(type, region, hasFrom).Should().Be(expected);

    [Fact]
    public void BackfillNameStubs_AddsOnlyMissingCoreAsns() // W2: core-член не теряется при 429
    {
        var asnList = new (uint Asn, int Coverage)[] { (100, 5), (200, 3), (300, 0) };
        var existing = new HashSet<uint> { 100 };                       // 100 уже дал кандидата
        var names = new Dictionary<uint, string> { [200] = "Host-B", [300] = "Host-C" };

        var stubs = ProviderFinder.BackfillNameStubs(asnList, existing, names);

        // 100 пропущен (уже есть); 200 и 300 добираются стабом с именем и покрытием.
        stubs.Select(s => s.Asn).Should().BeEquivalentTo(new uint[] { 200, 300 });
        stubs.First(s => s.Asn == 200).Name.Should().Be("Host-B");
        stubs.First(s => s.Asn == 200).CoverageCount.Should().Be(3);
    }

    [Fact]
    public void BackfillNameStubs_NonCoreAsnCannotEnter() // не-core (нет в nameFallback) не добавляется
    {
        var asnList = new (uint Asn, int Coverage)[] { (999, 10) };     // не в nameFallback
        var stubs = ProviderFinder.BackfillNameStubs(asnList, new HashSet<uint>(),
            new Dictionary<uint, string> { [200] = "Host-B" });
        stubs.Should().BeEmpty();
    }

    [Fact]
    public void BackfillNameStubs_NullFallback_ReturnsEmpty()
        => ProviderFinder.BackfillNameStubs(
               new (uint, int)[] { (100, 1) }, new HashSet<uint>(), null).Should().BeEmpty();

    [Theory]
    [InlineData("10.0.0.0/24", 256)]
    [InlineData("10.0.0.0/32", 1)]
    [InlineData("1.2.3.0-1.2.3.99", 100)]   // невыровненный диапазон из ip2asn
    [InlineData("1.2.3.4-1.2.3.4", 1)]
    [InlineData("garbage", 0)]
    [InlineData("garbage/0", 0)]
    public void CountIpsInCidr_HandlesCidrAndRanges(string s, long expected)
        => ProviderFinder.CountIpsInCidr(s).Should().Be(expected);

    [Fact]
    public void FilterAsnsByCountry_IntersectsCountries()
    {
        var map = new Dictionary<uint, HashSet<string>>
        {
            [1] = new(StringComparer.OrdinalIgnoreCase) { "RU", "NL" },
            [2] = new(StringComparer.OrdinalIgnoreCase) { "DE" },
            [3] = new(StringComparer.OrdinalIgnoreCase),          // без страны
        };
        uint[] input = [1, 2, 3, 99];                            // 99 — вне карты

        ProviderFinder.FilterAsnsByCountry(input, map, ["RU"])
            .Should().BeEquivalentTo(new uint[] { 1 });
        ProviderFinder.FilterAsnsByCountry(input, map, ["de", "nl"]) // регистр
            .Should().BeEquivalentTo(new uint[] { 1, 2 });
        ProviderFinder.FilterAsnsByCountry(input, map, [])           // нет кодов → все на входе
            .Should().BeEquivalentTo(new uint[] { 1, 2, 3, 99 });
    }
}
