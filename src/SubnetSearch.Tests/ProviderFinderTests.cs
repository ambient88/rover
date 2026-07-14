using FluentAssertions;
using System.Net;
using SubnetSearch.Core.Models.Classification;
using SubnetSearch.Network;
using SubnetSearch.Network.Http;
using SubnetSearch.Network.Recommend;

namespace SubnetSearch.Tests;

// Covers server taxonomy without network access. The vps, dedicated, server, hosting, and cloud aliases
// share PeeringDB info_types, while the curated allowlist determines membership.
// ServerProviders.IsAllowed and ProviderFinder.ApplyServerAllowlist enforce the final server filter.
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

        ripeHandler.Requests.Should().BeEmpty();
        bgpHandler.Requests.Should().BeEmpty();
        result.Should().ContainSingle();
        result[0].Prefixes.Should().Equal("10.0.0.0/24");
    }

    [Fact]
    public async Task FindByAsnList_CachedPeeringDbMetadataOverridesLocalFallback()
    {
        string dataDir = Directory.CreateTempSubdirectory().FullName;
        try
        {
            var cache = new RipeStatCache(dataDir);
            cache.Set(
                "pdb_50340",
                ProviderFinder.SerializePdbNet(
                    new ProviderCandidate(
                        50340, "Selectel MSK", null, "https://www.selectel.com",
                        "Content", 7, null, []),
                    found: true),
                TimeSpan.FromHours(8));
            var pdbHandler = TestHttpMessageHandler.Always(HttpStatusCode.OK, "{\"data\":[]}");
            var ripeHandler = TestHttpMessageHandler.Always(HttpStatusCode.ServiceUnavailable, "{}");
            using var pdbHttp = new HttpClient(pdbHandler);
            using var ripeHttp = new HttpClient(ripeHandler);
            var finder = new ProviderFinder(
                pdbHttp,
                new RipeStatClient(ripeHttp, cache),
                ripeCache: cache);
            var localPrefixes = new Dictionary<uint, IReadOnlyList<string>>
            {
                [50340] = ["31.184.192.0/20"]
            };
            var localNames = new Dictionary<uint, string>
            {
                [50340] = "Selectel - Moscow"
            };

            var result = await finder.FindByAsnListAsync(
                [(50340, 1)],
                localPrefixFallback: localPrefixes,
                nameFallback: localNames);

            pdbHandler.Requests.Should().BeEmpty();
            result.Should().ContainSingle();
            result[0].Name.Should().Be("Selectel MSK");
            result[0].Website.Should().Be("https://www.selectel.com");
            result[0].PeeringCount.Should().Be(7);
        }
        finally
        {
            Directory.Delete(dataDir, true);
        }
    }

    [Fact]
    public async Task FindByAsnList_CachedMetadataAfterNetworkCapIsStillUsed()
    {
        string dataDir = Directory.CreateTempSubdirectory().FullName;
        try
        {
            var cache = new RipeStatCache(dataDir);
            cache.Set(
                "pdb_64550",
                ProviderFinder.SerializePdbNet(
                    new ProviderCandidate(
                        64550, "Cached Provider", "DE", "https://cached.example",
                        "Content", 12, null, []),
                    found: true),
                TimeSpan.FromHours(8));
            var pdbHandler = TestHttpMessageHandler.Always(HttpStatusCode.OK, "{\"data\":[]}");
            using var pdbHttp = new HttpClient(pdbHandler);
            using var ripeHttp = new HttpClient(
                TestHttpMessageHandler.Always(HttpStatusCode.ServiceUnavailable, "{}"));
            var finder = new ProviderFinder(
                pdbHttp,
                new RipeStatClient(ripeHttp, cache),
                ripeCache: cache);
            var asns = Enumerable.Range(64500, 51)
                .Select(asn => ((uint)asn, 1))
                .ToArray();
            var localPrefixes = new Dictionary<uint, IReadOnlyList<string>>
            {
                [64550] = ["10.50.0.0/24"]
            };

            var result = await finder.FindByAsnListAsync(
                asns,
                localPrefixFallback: localPrefixes,
                nameFallback: new Dictionary<uint, string>());

            result.Should().ContainSingle(candidate => candidate.Asn == 64550);
            result.Single(candidate => candidate.Asn == 64550).Website
                .Should().Be("https://cached.example");
            pdbHandler.Requests.Should().NotContain(request =>
                request.RequestUri!.Query.Contains("asn=64550", StringComparison.Ordinal));
        }
        finally
        {
            Directory.Delete(dataDir, true);
        }
    }

    [Fact]
    public async Task FindByAsnList_StaleBulkCachePreservesMetadataWithoutNetwork()
    {
        string dataDir = Directory.CreateTempSubdirectory().FullName;
        try
        {
            await File.WriteAllTextAsync(
                Path.Combine(dataDir, "peeringdb-content.json"),
                """
                {"FetchedAt":"2020-01-01T00:00:00Z","Candidates":[{"Asn":50340,"Name":"Selectel MSK","Country":"RU","Website":"https://www.selectel.com","InfoType":"Content","PeeringCount":7}]}
                """);
            var pdbHandler = TestHttpMessageHandler.Always(HttpStatusCode.OK, "{\"data\":[]}");
            using var pdbHttp = new HttpClient(pdbHandler);
            using var ripeHttp = new HttpClient(
                TestHttpMessageHandler.Always(HttpStatusCode.ServiceUnavailable, "{}"));
            var finder = new ProviderFinder(
                pdbHttp,
                new RipeStatClient(ripeHttp),
                cacheDir: dataDir);

            var result = await finder.FindByAsnListAsync(
                [(50340, 1)],
                localPrefixFallback: new Dictionary<uint, IReadOnlyList<string>>
                {
                    [50340] = ["31.184.192.0/20"]
                },
                nameFallback: new Dictionary<uint, string>
                {
                    [50340] = "Selectel - Moscow"
                });

            pdbHandler.Requests.Should().BeEmpty();
            result.Should().ContainSingle();
            result[0].Name.Should().Be("Selectel MSK");
            result[0].Website.Should().Be("https://www.selectel.com");
            result[0].PeeringCount.Should().Be(7);
        }
        finally
        {
            Directory.Delete(dataDir, true);
        }
    }

    [Fact]
    public async Task FindByAsnList_CompleteBulkCacheSkipsNetworkForMissingAsn()
    {
        string dataDir = Directory.CreateTempSubdirectory().FullName;
        try
        {
            const string emptyCache =
                "{\"FetchedAt\":\"2020-01-01T00:00:00Z\",\"Candidates\":[]}";
            foreach (string type in new[] { "content", "nsp", "enterprise" })
            {
                await File.WriteAllTextAsync(
                    Path.Combine(dataDir, $"peeringdb-{type}.json"), emptyCache);
            }

            var pdbHandler = TestHttpMessageHandler.Always(HttpStatusCode.OK, "{\"data\":[]}");
            using var pdbHttp = new HttpClient(pdbHandler);
            using var ripeHttp = new HttpClient(
                TestHttpMessageHandler.Always(HttpStatusCode.ServiceUnavailable, "{}"));
            var finder = new ProviderFinder(
                pdbHttp,
                new RipeStatClient(ripeHttp),
                cacheDir: dataDir);

            var result = await finder.FindByAsnListAsync(
                [(64500, 1)],
                localPrefixFallback: new Dictionary<uint, IReadOnlyList<string>>
                {
                    [64500] = ["10.0.0.0/24"]
                },
                nameFallback: new Dictionary<uint, string>
                {
                    [64500] = "Local Provider"
                });

            pdbHandler.Requests.Should().BeEmpty();
            result.Should().ContainSingle();
            result[0].Name.Should().Be("Local Provider");
        }
        finally
        {
            Directory.Delete(dataDir, true);
        }
    }

    [Fact]
    public async Task FindByAsnList_CachedTypeMismatchIsNotBackfilled()
    {
        string dataDir = Directory.CreateTempSubdirectory().FullName;
        try
        {
            var cache = new RipeStatCache(dataDir);
            cache.Set(
                "pdb_64500",
                ProviderFinder.SerializePdbNet(
                    new ProviderCandidate(
                        64500, "Transit Provider", null, null, "NSP", 3, null, []),
                    found: true),
                TimeSpan.FromHours(8));
            using var pdbHttp = new HttpClient(
                TestHttpMessageHandler.Always(HttpStatusCode.OK, "{\"data\":[]}"));
            using var ripeHttp = new HttpClient(
                TestHttpMessageHandler.Always(HttpStatusCode.ServiceUnavailable, "{}"));
            var finder = new ProviderFinder(
                pdbHttp,
                new RipeStatClient(ripeHttp, cache),
                ripeCache: cache);

            var result = await finder.FindByAsnListAsync(
                [(64500, 1)],
                infoTypes: ["Content"],
                localPrefixFallback: new Dictionary<uint, IReadOnlyList<string>>
                {
                    [64500] = ["10.0.0.0/24"]
                },
                nameFallback: new Dictionary<uint, string>
                {
                    [64500] = "Transit Provider"
                });

            result.Should().BeEmpty();
        }
        finally
        {
            Directory.Delete(dataDir, true);
        }
    }

    [Fact]
    public async Task FindByAsnList_AiOnlyDoesNotBackfillNonAiProvider()
    {
        string dataDir = Directory.CreateTempSubdirectory().FullName;
        try
        {
            var cache = new RipeStatCache(dataDir);
            cache.Set(
                "pdb_64500",
                ProviderFinder.SerializePdbNet(
                    new ProviderCandidate(
                        64500, "Generic Hosting", null, null, "Content", 3, null, []),
                    found: true),
                TimeSpan.FromHours(8));
            using var pdbHttp = new HttpClient(
                TestHttpMessageHandler.Always(HttpStatusCode.OK, "{\"data\":[]}"));
            using var ripeHttp = new HttpClient(
                TestHttpMessageHandler.Always(HttpStatusCode.ServiceUnavailable, "{}"));
            var finder = new ProviderFinder(
                pdbHttp,
                new RipeStatClient(ripeHttp, cache),
                ripeCache: cache);

            var result = await finder.FindByAsnListAsync(
                [(64500, 1)],
                infoTypes: ["Content", "NSP", "Enterprise"],
                localPrefixFallback: new Dictionary<uint, IReadOnlyList<string>>
                {
                    [64500] = ["10.0.0.0/24"]
                },
                nameFallback: new Dictionary<uint, string>
                {
                    [64500] = "Generic Hosting"
                },
                aiOnly: true);

            result.Should().BeEmpty();
        }
        finally
        {
            Directory.Delete(dataDir, true);
        }
    }

    [Fact]
    public async Task FindByAsnList_LivePeeringDbMetadataPreservesWebsiteAndPeeringCount()
    {
        const string response =
            "{\"data\":[{\"asn\":50340,\"name\":\"Selectel MSK\",\"country\":\"RU\","
            + "\"website\":\"https://www.selectel.com\",\"info_type\":\"Content\",\"ix_count\":7}]}";
        var pdbHandler = TestHttpMessageHandler.Always(HttpStatusCode.OK, response);
        using var pdbHttp = new HttpClient(pdbHandler);
        using var ripeHttp = new HttpClient(
            TestHttpMessageHandler.Always(HttpStatusCode.ServiceUnavailable, "{}"));
        var finder = new ProviderFinder(pdbHttp, new RipeStatClient(ripeHttp));

        var result = await finder.FindByAsnListAsync(
            [(50340, 1)],
            localPrefixFallback: new Dictionary<uint, IReadOnlyList<string>>
            {
                [50340] = ["31.184.192.0/20"]
            },
            nameFallback: new Dictionary<uint, string>
            {
                [50340] = "Selectel - Moscow"
            });

        result.Should().ContainSingle();
        result[0].Name.Should().Be("Selectel MSK");
        result[0].Website.Should().Be("https://www.selectel.com");
        result[0].PeeringCount.Should().Be(7);
    }

    [Fact]
    public async Task FindByAsnList_AutoNameUsesMostFrequentLocalDescription()
    {
        var pdbHandler = TestHttpMessageHandler.Always(HttpStatusCode.OK, "{\"data\":[]}");
        using var pdbHttp = new HttpClient(pdbHandler);
        using var ripeHttp = new HttpClient(
            TestHttpMessageHandler.Always(HttpStatusCode.ServiceUnavailable, "{}"));
        var finder = new ProviderFinder(
            pdbHttp,
            new RipeStatClient(ripeHttp),
            localIp2AsnRecords:
            [
                new Ip2AsnRecord
                {
                    StartIp = 0x0A000000,
                    EndIp = 0x0A0000FF,
                    Asn = 64500,
                    Country = "ZZ",
                    Description = "Regional Name"
                },
                new Ip2AsnRecord
                {
                    StartIp = 0x0A000100,
                    EndIp = 0x0A0001FF,
                    Asn = 64500,
                    Country = "ZZ",
                    Description = "Canonical Name"
                },
                new Ip2AsnRecord
                {
                    StartIp = 0x0A000200,
                    EndIp = 0x0A0002FF,
                    Asn = 64500,
                    Country = "ZZ",
                    Description = "Canonical Name"
                }
            ]);

        var result = await finder.FindByAsnListAsync([(64500, 1)]);

        result.Should().ContainSingle();
        result[0].Name.Should().Be("Canonical Name");
    }

    [Fact]
    public async Task FindByAsnList_LocalIp2AsnRecordsSkipRipeStat()
    {
        const string peeringDbResponse =
            "{\"data\":[{\"asn\":64500,\"name\":\"Example\",\"info_type\":\"Content\"}]}";
        var pdbHandler = TestHttpMessageHandler.Always(HttpStatusCode.OK, peeringDbResponse);
        var ripeHandler = TestHttpMessageHandler.Always(HttpStatusCode.ServiceUnavailable, "{}");
        using var pdbHttp = new HttpClient(pdbHandler);
        using var ripeHttp = new HttpClient(ripeHandler);
        var finder = new ProviderFinder(
            pdbHttp,
            new RipeStatClient(ripeHttp),
            localIp2AsnRecords:
            [
                new Ip2AsnRecord
                {
                    StartIp = 0x0A000000,
                    EndIp = 0x0A0000FF,
                    Asn = 64500,
                    Country = "ZZ",
                    Description = "Example"
                }
            ]);

        var result = await finder.FindByAsnListAsync([(64500, 1)]);

        ripeHandler.Requests.Should().BeEmpty();
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
    public void ResolveInfoTypes_Nonsense_ReturnsNull()
    {
        ProviderFinder.ResolveInfoTypes("nonsense").Should().BeNull();
    }

    [Fact]
    public void ResolveInfoTypes_Null_ReturnsNull()
    {
        ProviderFinder.ResolveInfoTypes(null).Should().BeNull();
    }

    // Dedicated remains a server-related type for CDN and AI exclusions.
    [Theory]
    [InlineData("vps")]
    [InlineData("dedicated")]
    public void ShouldExcludeCdnAndAi_StillTrue_ForVpsAndDedicated(string type)
    {
        ProviderFinder.ShouldExcludeCdn(type).Should().BeTrue();
        ProviderFinder.ShouldExcludeAi(type).Should().BeTrue();
    }

    // ShouldIncludeUnverifiedHostingCandidate: candidates whose local ASN type is unknown
    // (not "hosting" or "cloud" and not an explicit reject). This covers wholesale NSP
    // carriers that used to slip through the local IP-range whitelist unconditionally:
    // Hurricane Electric (AS6939), Colt (AS8220), Equinix (AS15830), M247 (AS9009),
    // DataBank AS13767 uses PeeringDB info_type NSP and has no positive vpsh tag.

    [Theory]
    [InlineData(true)]  // The allowlist alone used to be sufficient.
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

    // PeeringDB stores per-ASN records under pdb_{asn} in ripe_cache.

    [Fact]
    public void SerializePdbNet_RoundTripsFoundRecord() // The PeeringDB record exists.
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
    public void SerializePdbNet_RoundTripsNotFound() // Negative cache entry for a missing PeeringDB record.
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
        // Only Hetzner belongs to the core. Carrier and unrelated vpsh entries do not pass.
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
    [InlineData("hosting")] // Hosting is a server alias and uses the allowlist.
    [InlineData("HOSTING")]
    [InlineData("Server")]  // Case-insensitive input.
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
    [InlineData("vps",       null,        false, true)]   // Global server search without --from uses the core first.
    [InlineData("server",    null,        false, true)]
    [InlineData("cloud",     null,        false, true)]
    [InlineData("dedicated", null,        false, true)]
    [InlineData("VPS",       null,        false, true)]   // Case-insensitive input.
    [InlineData("vps",       "Frankfurt", false, false)]  // Region search does not use core-first.
    [InlineData("vps",       null,        true,  false)]  // --from does not use core-first.
    [InlineData("cdn",       null,        false, false)]  // Non-server types do not use core-first.
    [InlineData("nsp",       null,        false, false)]
    [InlineData(null,        null,        false, false)]  // Missing type does not use core-first.
    public void UseCoreFirstSource_Matrix(string? type, string? region, bool hasFrom, bool expected)
        => ProviderFinder.UseCoreFirstSource(type, region, hasFrom).Should().Be(expected);

    [Fact]
    public void BackfillNameStubs_AddsOnlyMissingCoreAsns() // A rate limit must not drop a core member.
    {
        var asnList = new (uint Asn, int Coverage)[] { (100, 5), (200, 3), (300, 0) };
        var existing = new HashSet<uint> { 100 };                       // ASN 100 already produced a candidate.
        var names = new Dictionary<uint, string> { [200] = "Host-B", [300] = "Host-C" };

        var stubs = ProviderFinder.BackfillNameStubs(asnList, existing, names);

        // ASN 100 already exists. Name stubs add ASNs 200 and 300 with their coverage values.
        stubs.Select(s => s.Asn).Should().BeEquivalentTo(new uint[] { 200, 300 });
        stubs.First(s => s.Asn == 200).Name.Should().Be("Host-B");
        stubs.First(s => s.Asn == 200).CoverageCount.Should().Be(3);
    }

    [Fact]
    public void BackfillNameStubs_NonCoreAsnCannotEnter() // ASNs outside nameFallback are not added.
    {
        var asnList = new (uint Asn, int Coverage)[] { (999, 10) };     // Absent from nameFallback.
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
    [InlineData("1.2.3.0-1.2.3.99", 100)]   // Unaligned range from ip2asn.
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
            [3] = new(StringComparer.OrdinalIgnoreCase),          // No country data.
        };
        uint[] input = [1, 2, 3, 99];                            // ASN 99 is absent from the map.

        ProviderFinder.FilterAsnsByCountry(input, map, ["RU"])
            .Should().BeEquivalentTo(new uint[] { 1 });
        ProviderFinder.FilterAsnsByCountry(input, map, ["de", "nl"]) // Case-insensitive country codes.
            .Should().BeEquivalentTo(new uint[] { 1, 2 });
        ProviderFinder.FilterAsnsByCountry(input, map, [])           // Empty filters preserve all input.
            .Should().BeEquivalentTo(new uint[] { 1, 2, 3, 99 });
    }
}
