using System.Net;
using FluentAssertions;
using SubnetSearch.Core.Models.Classification;
using SubnetSearch.Network;
using SubnetSearch.Network.Recommend;

namespace SubnetSearch.Tests;

// Failure-path coverage for ProviderFinder: PeeringDB cache staleness and corruption,
// phase-budget expiry fallbacks to local ip2asn data, per-request error swallowing,
// local ASN-type prefilters, and the name-stub backfill that keeps core members alive.
public sealed class ProviderFinderFallbackTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory().FullName;
    public void Dispose() { if (Directory.Exists(_dir)) Directory.Delete(_dir, true); }

    // Async handler: routes by URL substring; unmatched URLs get an empty data set.
    private sealed class AsyncStub(Func<string, CancellationToken, Task<HttpResponseMessage>> respond)
        : HttpMessageHandler
    {
        public int Calls;

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken ct)
        {
            Interlocked.Increment(ref Calls);
            return await respond(request.RequestUri!.AbsoluteUri, ct);
        }
    }

    private static HttpResponseMessage Json(string body)
        => new(HttpStatusCode.OK) { Content = new StringContent(body) };

    private static HttpClient RipeOk(string prefix = "1.2.3.0/24")
        => new(TestHttpMessageHandler.Custom(req =>
        {
            string url = req.RequestUri!.AbsoluteUri;
            string body = url.Contains("announced-prefixes")
                ? "{\"status\":\"ok\",\"data\":{\"prefixes\":[{\"prefix\":\"" + prefix + "\"}]}}"
                : url.Contains("asn-neighbours")
                    ? """{"status":"ok","data":{"neighbours":[{"asn":100,"type":"left","power":9}]}}"""
                    : """{"status":"ok","data":{"holder":"SENKO-AS Senko Digital LLC","announced":true}}""";
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body) };
        }));

    private static Ip2AsnRecord[] LocalRecords(uint asn) =>
    [
        new()
        {
            StartIp = 16909056, EndIp = 16909311, // 1.2.3.0 - 1.2.3.255
            Asn = asn, Country = "DE", Description = "Local",
        },
    ];

    // ── Static alias mapping ──

    [Theory]
    [InlineData("cdn",     new[] { "Content" })]
    [InlineData("content", new[] { "Content" })]
    [InlineData("nsp",     new[] { "NSP" })]
    [InlineData("isp",     new[] { "NSP" })]
    [InlineData("transit", new[] { "NSP" })]
    [InlineData("ai",      new[] { "Content", "NSP", "Enterprise" })]
    public void ResolveInfoTypes_MapsAliases(string filter, string[] expected)
        => ProviderFinder.ResolveInfoTypes(filter).Should().Equal(expected);

    [Theory]
    [InlineData("ai",  true)]
    [InlineData("vps", false)]
    [InlineData(null,  false)]
    public void ShouldFilterAiOnly_OnlyForAi(string? filter, bool expected)
        => ProviderFinder.ShouldFilterAiOnly(filter).Should().Be(expected);

    // ── FindGlobalAsync: local ASN-type prefilter and PeeringDB cache handling ──

    [Fact]
    public async Task FindGlobal_LocalTypePrefilter_DropsIspKeepsHostingAndWhitelisted()
    {
        using var pdb = new HttpClient(TestHttpMessageHandler.Custom(req =>
            Json("""
            {"data":[
              {"asn":64500,"name":"HostCo","info_type":"Content","ix_count":9},
              {"asn":64501,"name":"IspCo","info_type":"Content","ix_count":8},
              {"asn":64502,"name":"UnknownCo","info_type":"Content","ix_count":7}
            ]}
            """)));
        using var ripe = RipeOk();
        var statuses = new List<string>();
        var finder = new ProviderFinder(
            pdb, new RipeStatClient(ripe),
            asnTypes: new Dictionary<uint, string> { [64500] = "hosting", [64501] = "isp" });

        var result = await finder.FindGlobalAsync(
            infoTypes: ["Content"], excludeCdn: true,
            localHostingWhitelist: [64502],
            onStatus: statuses.Add);

        result.Should().Contain(c => c.Asn == 64500, "an explicit hosting type passes");
        result.Should().Contain(c => c.Asn == 64502, "an unknown type is rescued by the whitelist");
        result.Should().NotContain(c => c.Asn == 64501, "an explicit ISP type is rejected");
        statuses.Should().Contain(s => s.Contains("ASN type (local)"));
    }

    [Fact]
    public async Task FindGlobal_StaleDiskCache_Refetches()
    {
        string stale = DateTimeOffset.UtcNow.AddDays(-2).ToString("O");
        await File.WriteAllTextAsync(Path.Combine(_dir, "peeringdb-content.json"),
            $$"""{"FetchedAt":"{{stale}}","Candidates":[{"Asn":11111,"Name":"Stale"}]}""");
        var handler = TestHttpMessageHandler.Custom(_ =>
            Json("""{"data":[{"asn":64500,"name":"Fresh","info_type":"Content"}]}"""));
        using var pdb = new HttpClient(handler);
        using var ripe = RipeOk();
        var finder = new ProviderFinder(pdb, new RipeStatClient(ripe), cacheDir: _dir);

        var result = await finder.FindGlobalAsync(infoTypes: ["Content"]);

        handler.Requests.Should().NotBeEmpty("a stale cache must not be served");
        result.Should().Contain(c => c.Asn == 64500);
    }

    [Fact]
    public async Task FindGlobal_CorruptDiskCache_Refetches()
    {
        await File.WriteAllTextAsync(Path.Combine(_dir, "peeringdb-content.json"), "{ broken");
        using var pdb = new HttpClient(TestHttpMessageHandler.Custom(_ =>
            Json("""{"data":[{"asn":64500,"name":"Fresh","info_type":"Content"}]}""")));
        using var ripe = RipeOk();
        var finder = new ProviderFinder(pdb, new RipeStatClient(ripe), cacheDir: _dir);

        var result = await finder.FindGlobalAsync(infoTypes: ["Content"]);

        result.Should().Contain(c => c.Asn == 64500);
    }

    [Fact]
    public async Task FindGlobal_UnwritableCacheDir_StillReturnsResults()
    {
        // A directory squatting on the cache file name makes the cache write fail soft.
        Directory.CreateDirectory(Path.Combine(_dir, "peeringdb-content.json"));
        using var pdb = new HttpClient(TestHttpMessageHandler.Custom(_ =>
            Json("""{"data":[{"asn":64500,"name":"Fresh","info_type":"Content"}]}""")));
        using var ripe = RipeOk();
        var finder = new ProviderFinder(pdb, new RipeStatClient(ripe), cacheDir: _dir);

        var result = await finder.FindGlobalAsync(infoTypes: ["Content"]);

        result.Should().Contain(c => c.Asn == 64500);
    }

    // ── FindByRegionAsync: failure and budget-expiry paths ──

    [Fact]
    public async Task FindByRegion_IxSearchFails_ReturnsEmpty()
    {
        using var pdb = new HttpClient(TestHttpMessageHandler.Throws(new HttpRequestException("down")));
        using var ripe = RipeOk();
        var finder = new ProviderFinder(pdb, new RipeStatClient(ripe));

        (await finder.FindByRegionAsync("frankfurt")).Should().BeEmpty();
    }

    [Fact]
    public async Task FindByRegion_IxSearchTimesOutInternally_ReturnsEmpty()
    {
        // A plain OCE without caller cancellation means the phase budget expired.
        using var pdb = new HttpClient(TestHttpMessageHandler.Throws(new OperationCanceledException()));
        using var ripe = RipeOk();
        var finder = new ProviderFinder(pdb, new RipeStatClient(ripe));

        (await finder.FindByRegionAsync("frankfurt")).Should().BeEmpty();
    }

    [Fact]
    public async Task FindByRegion_UserCancelDuringIxSearch_Propagates()
    {
        using var cts = new CancellationTokenSource();
        using var pdb = new HttpClient(TestHttpMessageHandler.Custom(_ =>
        {
            cts.Cancel();
            throw new OperationCanceledException(cts.Token);
        }));
        using var ripe = RipeOk();
        var finder = new ProviderFinder(pdb, new RipeStatClient(ripe));

        var act = () => finder.FindByRegionAsync("frankfurt", ct: cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    [Fact]
    public async Task FindByRegion_UserCancelDuringEnrichment_Propagates()
    {
        using var cts = new CancellationTokenSource();
        using var pdb = new HttpClient(TestHttpMessageHandler.Custom(req =>
        {
            string url = req.RequestUri!.AbsoluteUri;
            if (url.Contains("/ix?")) return Json("""{"data":[{"id":10}]}""");
            if (url.Contains("/netixlan?")) return Json("""{"data":[{"net_id":20}]}""");
            if (url.Contains("/net/")) return Json(
                """{"data":[{"asn":64500,"name":"HostCo","info_type":"Content"}]}""");
            return Json("""{"data":[]}""");
        }));
        var ripeStub = new AsyncStub((url, _) =>
        {
            if (url.Contains("announced-prefixes"))
            {
                cts.Cancel();
                throw new OperationCanceledException(cts.Token);
            }
            return Task.FromResult(Json("""{"status":"ok","data":{}}"""));
        });
        using var ripe = new HttpClient(ripeStub);
        var finder = new ProviderFinder(pdb, new RipeStatClient(ripe));

        var act = () => finder.FindByRegionAsync("frankfurt", ct: cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    [Fact]
    public async Task FindByRegion_NetixlanFailures_AreSwallowedPerIx()
    {
        using var pdb = new HttpClient(TestHttpMessageHandler.Custom(url =>
            url.RequestUri!.AbsoluteUri.Contains("/ix?")
                ? Json("""{"data":[{"id":10}]}""")
                : throw new InvalidOperationException("netixlan down")));
        using var ripe = RipeOk();
        var finder = new ProviderFinder(pdb, new RipeStatClient(ripe));

        (await finder.FindByRegionAsync("frankfurt")).Should().BeEmpty();
    }

    [Fact]
    public async Task FindByRegion_NetixlanCancelledInternally_FailsSoft()
    {
        using var pdb = new HttpClient(TestHttpMessageHandler.Custom(url =>
            url.RequestUri!.AbsoluteUri.Contains("/ix?")
                ? Json("""{"data":[{"id":10}]}""")
                : throw new OperationCanceledException()));
        using var ripe = RipeOk();
        var finder = new ProviderFinder(pdb, new RipeStatClient(ripe));

        (await finder.FindByRegionAsync("frankfurt")).Should().BeEmpty();
    }

    [Fact]
    public async Task FindByRegion_NetFetchFailures_AreSwallowedPerNet()
    {
        using var pdb = new HttpClient(TestHttpMessageHandler.Custom(req =>
        {
            string url = req.RequestUri!.AbsoluteUri;
            if (url.Contains("/ix?")) return Json("""{"data":[{"id":10}]}""");
            if (url.Contains("/netixlan?")) return Json("""{"data":[{"net_id":20}]}""");
            throw new InvalidOperationException("net down");
        }));
        using var ripe = RipeOk();
        var finder = new ProviderFinder(pdb, new RipeStatClient(ripe));

        (await finder.FindByRegionAsync("frankfurt")).Should().BeEmpty();
    }

    [Fact]
    public async Task FindByRegion_NetFetchCancelledInternally_FailsSoft()
    {
        using var pdb = new HttpClient(TestHttpMessageHandler.Custom(req =>
        {
            string url = req.RequestUri!.AbsoluteUri;
            if (url.Contains("/ix?")) return Json("""{"data":[{"id":10}]}""");
            if (url.Contains("/netixlan?")) return Json("""{"data":[{"net_id":20}]}""");
            throw new OperationCanceledException();
        }));
        using var ripe = RipeOk();
        var finder = new ProviderFinder(pdb, new RipeStatClient(ripe));

        (await finder.FindByRegionAsync("frankfurt")).Should().BeEmpty();
    }

    [Fact]
    public async Task FindByRegion_InfoTypeFilter_DropsMismatches()
    {
        using var pdb = new HttpClient(TestHttpMessageHandler.Custom(req =>
        {
            string url = req.RequestUri!.AbsoluteUri;
            if (url.Contains("/ix?")) return Json("""{"data":[{"id":10}]}""");
            if (url.Contains("/netixlan?")) return Json("""{"data":[{"net_id":20}]}""");
            if (url.Contains("/net/")) return Json(
                """{"data":[{"asn":64500,"name":"HostCo","info_type":"Content"}]}""");
            return Json("""{"data":[]}""");
        }));
        using var ripe = RipeOk();
        var finder = new ProviderFinder(pdb, new RipeStatClient(ripe));

        (await finder.FindByRegionAsync("frankfurt", infoTypes: ["NSP"])).Should().BeEmpty();
    }

    [Fact]
    public async Task FindByRegion_BudgetExpiresDuringNetFetch_FallsBackToLocalPrefixes()
    {
        // net/20 answers instantly; net/21 outlives the 4-second phase budget, so the
        // finder returns what it has, enriched from local ip2asn data instead of RIPE.
        var pdbStub = new AsyncStub(async (url, ct) =>
        {
            if (url.Contains("/ix?")) return Json("""{"data":[{"id":10}]}""");
            if (url.Contains("/netixlan?")) return Json("""{"data":[{"net_id":20},{"net_id":21}]}""");
            if (url.Contains("/net/20")) return Json(
                """{"data":[{"asn":64500,"name":"HostCo","info_type":"Content"}]}""");
            if (url.Contains("/net/21"))
            {
                await Task.Delay(TimeSpan.FromSeconds(30), ct); // dies with the phase budget
                throw new OperationCanceledException(ct);
            }
            return Json("""{"data":[]}""");
        });
        using var pdb = new HttpClient(pdbStub);
        using var ripe = RipeOk();
        var finder = new ProviderFinder(
            pdb, new RipeStatClient(ripe), localIp2AsnRecords: LocalRecords(64500));

        var result = await finder.FindByRegionAsync("frankfurt");

        result.Should().ContainSingle(c => c.Asn == 64500)
            .Which.Prefixes.Should().NotBeEmpty("prefixes come from the local ip2asn fallback");
    }

    [Fact]
    public async Task FindByRegion_EnrichmentOutlivesBudget_FallsBackToLocalPrefixes()
    {
        // PeeringDB eats most of the 4-second phase budget, so the budget expires while
        // RIPE enrichment for the remote ASN is still in flight. The finder must retry
        // with the ASNs it can serve from local ip2asn data.
        var pdbStub = new AsyncStub(async (url, ct) =>
        {
            if (url.Contains("/ix?")) return Json("""{"data":[{"id":10}]}""");
            if (url.Contains("/netixlan?"))
            {
                await Task.Delay(TimeSpan.FromSeconds(3.5), ct); // burns the budget, stays under it
                return Json("""{"data":[{"net_id":20},{"net_id":21}]}""");
            }
            if (url.Contains("/net/20")) return Json(
                """{"data":[{"asn":64500,"name":"LocalCo","info_type":"Content"}]}""");
            if (url.Contains("/net/21")) return Json(
                """{"data":[{"asn":64999,"name":"RemoteCo","info_type":"Content"}]}""");
            return Json("""{"data":[]}""");
        });
        var ripeStub = new AsyncStub(async (url, ct) =>
        {
            if (url.Contains("announced-prefixes") && url.Contains("64999"))
            {
                // The phase budget fires mid-request; the OCE carries a cancelled token.
                await Task.Delay(TimeSpan.FromSeconds(2), ct);
                throw new OperationCanceledException(ct);
            }
            return Json(url.Contains("announced-prefixes")
                ? """{"status":"ok","data":{"prefixes":[{"prefix":"1.2.3.0/24"}]}}"""
                : """{"status":"ok","data":{}}""");
        });
        using var pdb = new HttpClient(pdbStub);
        using var ripe = new HttpClient(ripeStub);
        var finder = new ProviderFinder(
            pdb, new RipeStatClient(ripe), localIp2AsnRecords: LocalRecords(64500));

        var result = await finder.FindByRegionAsync("frankfurt");

        result.Should().ContainSingle(c => c.Asn == 64500,
            "only the locally known ASN survives the enrichment timeout");
    }

    // ── FindByAsnListAsync: filters, caches, and backfill ──

    [Fact]
    public async Task FindByAsnList_KnownCdnAsn_RemovedBeforeAnyLookup()
    {
        var handler = TestHttpMessageHandler.Always(HttpStatusCode.OK, """{"data":[]}""");
        using var pdb = new HttpClient(handler);
        using var ripe = RipeOk();
        string exclPath = Path.Combine(_dir, "excl.json");
        await File.WriteAllTextAsync(exclPath, """{"knownCdns":[{"asn":64999,"org":"TestCdn"}]}""");
        var exclusions = await AsnExclusions.LoadAsync(exclPath);
        var finder = new ProviderFinder(pdb, new RipeStatClient(ripe), exclusions: exclusions);

        var result = await finder.FindByAsnListAsync([(64999u, 5)], excludeCdn: true);

        result.Should().BeEmpty();
        handler.Requests.Should().BeEmpty("a known CDN ASN is dropped before PeeringDB");
    }

    [Fact]
    public async Task FindByAsnList_TypeFilterWithLocalIspVerdict_SkipsPeeringDb()
    {
        var handler = TestHttpMessageHandler.Always(HttpStatusCode.OK, """{"data":[]}""");
        using var pdb = new HttpClient(handler);
        using var ripe = RipeOk();
        var finder = new ProviderFinder(
            pdb, new RipeStatClient(ripe),
            asnTypes: new Dictionary<uint, string> { [64500] = "isp" });

        var result = await finder.FindByAsnListAsync([(64500u, 5)], infoTypes: ["Content"]);

        result.Should().BeEmpty();
        handler.Requests.Should().BeEmpty("the cheap local verdict already excluded the ASN");
    }

    [Fact]
    public async Task FindByAsnList_GovernmentNetwork_IsHardBlocked()
    {
        using var pdb = new HttpClient(TestHttpMessageHandler.Custom(_ =>
            Json("""{"data":[{"asn":64500,"name":"GovNet","info_type":"Government"}]}""")));
        using var ripe = RipeOk();
        var finder = new ProviderFinder(pdb, new RipeStatClient(ripe));

        (await finder.FindByAsnListAsync([(64500u, 1)])).Should().BeEmpty();
    }

    [Fact]
    public async Task FindByAsnList_ExcludeCdnWithExplicitIspType_DropsInEnrichment()
    {
        using var pdb = new HttpClient(TestHttpMessageHandler.Custom(_ =>
            Json("""{"data":[{"asn":64500,"name":"WireCo","info_type":"Content"}]}""")));
        using var ripe = RipeOk();
        var finder = new ProviderFinder(
            pdb, new RipeStatClient(ripe),
            asnTypes: new Dictionary<uint, string> { [64500] = "isp" });

        // No info-type filter: the ASN reaches enrichment, where the local verdict kills it.
        (await finder.FindByAsnListAsync([(64500u, 1)], excludeCdn: true)).Should().BeEmpty();
    }

    [Fact]
    public async Task FindByAsnList_ExcludeCdnUnknownNspWithoutSignals_IsDropped()
    {
        using var pdb = new HttpClient(TestHttpMessageHandler.Custom(_ =>
            Json("""{"data":[{"asn":64500,"name":"CarrierCo","info_type":"NSP"}]}""")));
        using var ripe = RipeOk();
        var finder = new ProviderFinder(
            pdb, new RipeStatClient(ripe),
            asnTypes: new Dictionary<uint, string>());

        var result = await finder.FindByAsnListAsync([(64500u, 1)], excludeCdn: true);

        result.Should().BeEmpty("an unverified NSP without whitelist membership does not pass");
    }

    [Fact]
    public async Task FindByAsnList_CachedRipePrefixes_SkipAnnouncedPrefixCall()
    {
        using var pdb = new HttpClient(TestHttpMessageHandler.Custom(_ =>
            Json("""{"data":[{"asn":64500,"name":"HostCo","info_type":"Content"}]}""")));
        var ripeHandler = TestHttpMessageHandler.Always(HttpStatusCode.OK, """{"status":"ok","data":{}}""");
        using var ripe = new HttpClient(ripeHandler);
        var cache = new RipeStatCache(_dir);
        var ripeClient = new RipeStatClient(ripe, cache);
        ripeClient.CachePrefixes(64500, ["7.7.7.0/24"], []);
        var finder = new ProviderFinder(pdb, ripeClient, ripeCache: cache);

        var result = await finder.FindByAsnListAsync([(64500u, 1)]);

        result.Should().ContainSingle().Which.Prefixes.Should().Contain("7.7.7.0/24");
        ripeHandler.Requests.Should().NotContain(
            r => r.RequestUri!.AbsoluteUri.Contains("announced-prefixes"));
    }

    [Fact]
    public async Task FindByAsnList_RateLimited_ReportsOnceAndBackfillsCoreNames()
    {
        using var pdb = new HttpClient(TestHttpMessageHandler.Always(
            HttpStatusCode.TooManyRequests, ""));
        using var ripe = RipeOk();
        var finder = new ProviderFinder(pdb, new RipeStatClient(ripe));
        var errors = new List<string>();

        var result = await finder.FindByAsnListAsync(
            [(64500u, 3)],
            onError: errors.Add,
            nameFallback: new Dictionary<uint, string> { [64500] = "CoreName" },
            localPrefixFallback: new Dictionary<uint, IReadOnlyList<string>>
            {
                [64500] = new[] { "1.2.3.0/24" },
            });

        errors.Should().ContainSingle().Which.Should().Contain("429");
        result.Should().ContainSingle(c => c.Asn == 64500)
            .Which.Name.Should().Be("CoreName", "the name stub keeps the core member alive");
    }

    [Fact]
    public async Task FindByAsnList_PdbNetworkError_BackfillsCoreNames()
    {
        using var pdb = new HttpClient(TestHttpMessageHandler.Throws(new HttpRequestException("down")));
        using var ripe = RipeOk();
        var finder = new ProviderFinder(pdb, new RipeStatClient(ripe));

        var result = await finder.FindByAsnListAsync(
            [(64500u, 3)],
            nameFallback: new Dictionary<uint, string> { [64500] = "CoreName" },
            localPrefixFallback: new Dictionary<uint, IReadOnlyList<string>>
            {
                [64500] = new[] { "1.2.3.0/24" },
            });

        result.Should().ContainSingle(c => c.Asn == 64500);
    }

    [Fact]
    public async Task FindByAsnList_FreshRecordFailsTypeFilter_IsExcluded()
    {
        using var pdb = new HttpClient(TestHttpMessageHandler.Custom(_ =>
            Json("""{"data":[{"asn":64500,"name":"Carrier","info_type":"NSP"}]}""")));
        using var ripe = RipeOk();
        var finder = new ProviderFinder(pdb, new RipeStatClient(ripe));

        (await finder.FindByAsnListAsync([(64500u, 1)], infoTypes: ["Content"]))
            .Should().BeEmpty();
    }

    [Fact]
    public async Task FindByAsnList_NoPdbRecordAndNoCoreName_UsesRipeOverviewHolder()
    {
        using var pdb = new HttpClient(TestHttpMessageHandler.Custom(_ => Json("""{"data":[]}""")));
        using var ripe = RipeOk();
        var finder = new ProviderFinder(pdb, new RipeStatClient(ripe));

        var result = await finder.FindByAsnListAsync(
            [(64500u, 1)],
            nameFallback: new Dictionary<uint, string>()); // deliberately empty

        result.Should().ContainSingle(c => c.Asn == 64500)
            .Which.Name.Should().Contain("Senko", "the RIPE overview holder names the stub");
    }

    [Fact]
    public async Task FindByAsnList_CorruptPdbCacheEntry_RefetchesFromNetwork()
    {
        using var pdb = new HttpClient(TestHttpMessageHandler.Custom(_ =>
            Json("""{"data":[{"asn":64500,"name":"HostCo","info_type":"Content"}]}""")));
        using var ripe = RipeOk();
        var cache = new RipeStatCache(_dir);
        cache.Set("pdb_64500", "{ broken");
        var finder = new ProviderFinder(pdb, new RipeStatClient(ripe), ripeCache: cache);

        var result = await finder.FindByAsnListAsync([(64500u, 1)]);

        result.Should().ContainSingle(c => c.Asn == 64500 && c.Name == "HostCo");
    }

    [Fact]
    public async Task FindByAsnList_SecondRun_ServesMetadataFromPdbCache()
    {
        var handler = TestHttpMessageHandler.Custom(_ =>
            Json("""{"data":[{"asn":64500,"name":"HostCo","info_type":"Content"}]}"""));
        using var pdb = new HttpClient(handler);
        using var ripe = RipeOk();
        var cache = new RipeStatCache(_dir);
        var finder = new ProviderFinder(pdb, new RipeStatClient(ripe), ripeCache: cache);

        await finder.FindByAsnListAsync([(64500u, 1)]);
        int callsAfterFirst = handler.Requests.Count(
            r => r.RequestUri!.AbsoluteUri.Contains("net?asn"));
        var second = await finder.FindByAsnListAsync([(64500u, 1)]);

        second.Should().ContainSingle(c => c.Asn == 64500 && c.Name == "HostCo");
        handler.Requests.Count(r => r.RequestUri!.AbsoluteUri.Contains("net?asn"))
            .Should().Be(callsAfterFirst, "the second run reads the pdb_ cache");
    }

    [Fact]
    public async Task FindByAsnList_CachedMissingRecord_FallsBackToCoreNameOrExcludes()
    {
        using var pdb = new HttpClient(TestHttpMessageHandler.Custom(_ => Json("""{"data":[]}""")));
        using var ripe = RipeOk();
        var cache = new RipeStatCache(_dir);
        var finder = new ProviderFinder(pdb, new RipeStatClient(ripe), ripeCache: cache);
        var names = new Dictionary<uint, string> { [64500] = "CoreName" };
        var prefixes = new Dictionary<uint, IReadOnlyList<string>>
        {
            [64500] = new[] { "1.2.3.0/24" },
        };

        // First run caches the confirmed-missing PeeringDB record.
        await finder.FindByAsnListAsync([(64500u, 1)], nameFallback: names, localPrefixFallback: prefixes);
        // Second run reads it from the cache and still keeps the core name alive.
        var second = await finder.FindByAsnListAsync(
            [(64500u, 1)], nameFallback: names, localPrefixFallback: prefixes);

        second.Should().ContainSingle(c => c.Asn == 64500 && c.Name == "CoreName");

        // With a type filter the same cached-missing record excludes the ASN instead.
        var filtered = await finder.FindByAsnListAsync(
            [(64500u, 1)], infoTypes: ["Content"], nameFallback: names, localPrefixFallback: prefixes);
        filtered.Should().BeEmpty();
    }

    [Fact]
    public async Task FindByAsnList_BulkCacheMismatch_ExcludesWithoutNetwork()
    {
        string fresh = DateTimeOffset.UtcNow.ToString("O");
        await File.WriteAllTextAsync(Path.Combine(_dir, "peeringdb-content.json"),
            $$"""{"FetchedAt":"{{fresh}}","Candidates":[{"Asn":64500,"Name":"Carrier","InfoType":"NSP"}]}""");
        var handler = TestHttpMessageHandler.Always(HttpStatusCode.OK, """{"data":[]}""");
        using var pdb = new HttpClient(handler);
        using var ripe = RipeOk();
        var finder = new ProviderFinder(pdb, new RipeStatClient(ripe), cacheDir: _dir);

        var result = await finder.FindByAsnListAsync([(64500u, 1)], infoTypes: ["Content"]);

        result.Should().BeEmpty("the bulk cache says NSP, which fails the Content filter");
        handler.Requests.Should().BeEmpty("bulk metadata answered without per-ASN lookups");
    }

    [Fact]
    public async Task FindByAsnList_CompleteBulkCacheWithoutTheAsn_ExcludesUnderTypeFilter()
    {
        string fresh = DateTimeOffset.UtcNow.ToString("O");
        await File.WriteAllTextAsync(Path.Combine(_dir, "peeringdb-content.json"),
            $$"""{"FetchedAt":"{{fresh}}","Candidates":[{"Asn":11111,"Name":"Other","InfoType":"Content"}]}""");
        var handler = TestHttpMessageHandler.Always(HttpStatusCode.OK, """{"data":[]}""");
        using var pdb = new HttpClient(handler);
        using var ripe = RipeOk();
        var finder = new ProviderFinder(pdb, new RipeStatClient(ripe), cacheDir: _dir);

        var result = await finder.FindByAsnListAsync([(64500u, 1)], infoTypes: ["Content"]);

        result.Should().BeEmpty("a complete bulk cache without the ASN is authoritative");
        handler.Requests.Should().BeEmpty();
    }

    [Fact]
    public async Task FindByAsnList_BatchBudgetExpiry_FallsBackToCoreNames()
    {
        // The per-ASN lookup keeps running past its own request timeout AND past the
        // 3-second batch budget, so the batch loop itself is what gets cancelled.
        var pdbStub = new AsyncStub(async (url, ct) =>
        {
            try { await Task.Delay(TimeSpan.FromSeconds(30), ct); }
            catch (OperationCanceledException) { }
            await Task.Delay(TimeSpan.FromSeconds(1.5), CancellationToken.None);
            throw new HttpRequestException("gave up");
        });
        using var pdb = new HttpClient(pdbStub);
        using var ripe = RipeOk();
        var finder = new ProviderFinder(pdb, new RipeStatClient(ripe));

        var result = await finder.FindByAsnListAsync(
            [(64500u, 3)],
            nameFallback: new Dictionary<uint, string> { [64500] = "CoreName" },
            localPrefixFallback: new Dictionary<uint, IReadOnlyList<string>>
            {
                [64500] = new[] { "1.2.3.0/24" },
            });

        result.Should().ContainSingle(c => c.Asn == 64500 && c.Name == "CoreName");
    }

    [Fact]
    public async Task FindByAsnList_UserCancelDuringOverviewFallback_Propagates()
    {
        using var cts = new CancellationTokenSource();
        // No PeeringDB record and no core name: the RIPE overview fallback runs and
        // the user cancels in the middle of it.
        var pdbStub = new AsyncStub((url, _) => Task.FromResult(Json("""{"data":[]}""")));
        var ripeStub = new AsyncStub((url, _) =>
        {
            if (url.Contains("as-overview"))
            {
                cts.Cancel();
                throw new OperationCanceledException(cts.Token);
            }
            return Task.FromResult(Json("""{"status":"ok","data":{}}"""));
        });
        using var pdb = new HttpClient(pdbStub);
        using var ripe = new HttpClient(ripeStub);
        var finder = new ProviderFinder(pdb, new RipeStatClient(ripe));

        var act = () => finder.FindByAsnListAsync(
            [(64500u, 1)], nameFallback: new Dictionary<uint, string>(), ct: cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    [Fact]
    public async Task FindByAsnList_BatchBudgetDuringOverviewFallback_FailsSoft()
    {
        // The overview fallback outlives the 3-second batch budget; its cancellation
        // carries the batch token, not the caller's, so the loop fails soft.
        var pdbStub = new AsyncStub((url, _) => Task.FromResult(Json("""{"data":[]}""")));
        var ripeStub = new AsyncStub(async (url, ct) =>
        {
            if (url.Contains("as-overview"))
            {
                try { await Task.Delay(TimeSpan.FromSeconds(30), ct); }
                catch (OperationCanceledException) { }
                await Task.Delay(TimeSpan.FromSeconds(1.2), CancellationToken.None);
                throw new OperationCanceledException();
            }
            return Json("""{"status":"ok","data":{}}""");
        });
        using var pdb = new HttpClient(pdbStub);
        using var ripe = new HttpClient(ripeStub);
        var finder = new ProviderFinder(pdb, new RipeStatClient(ripe));

        var result = await finder.FindByAsnListAsync(
            [(64500u, 1)], nameFallback: new Dictionary<uint, string>());

        result.Should().BeEmpty("the overview never answered and there is no core name to fall back to");
    }

    // ── Cancellation propagation from enrichment ──

    [Fact]
    public async Task FindByAsnList_UserCancelDuringPrefixFetch_Propagates()
    {
        using var cts = new CancellationTokenSource();
        using var pdb = new HttpClient(TestHttpMessageHandler.Custom(_ => Json("""{"data":[]}""")));
        var ripeStub = new AsyncStub((url, _) =>
        {
            if (url.Contains("announced-prefixes"))
            {
                cts.Cancel();
                throw new OperationCanceledException(cts.Token);
            }
            return Task.FromResult(Json(
                """{"status":"ok","data":{"holder":"SENKO-AS Senko","announced":true}}"""));
        });
        using var ripe = new HttpClient(ripeStub);
        var finder = new ProviderFinder(pdb, new RipeStatClient(ripe));

        var act = () => finder.FindByAsnListAsync([(64500u, 1)], ct: cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    [Fact]
    public async Task FindByAsnList_UserCancelDuringNeighbourFetch_Propagates()
    {
        using var cts = new CancellationTokenSource();
        using var pdb = new HttpClient(TestHttpMessageHandler.Custom(_ => Json("""{"data":[]}""")));
        var ripeStub = new AsyncStub((url, _) =>
        {
            if (url.Contains("asn-neighbours"))
            {
                cts.Cancel();
                throw new OperationCanceledException(cts.Token);
            }
            return Task.FromResult(Json(url.Contains("announced-prefixes")
                ? """{"status":"ok","data":{"prefixes":[{"prefix":"1.2.3.0/24"}]}}"""
                : """{"status":"ok","data":{"holder":"SENKO-AS Senko","announced":true}}"""));
        });
        using var ripe = new HttpClient(ripeStub);
        var finder = new ProviderFinder(pdb, new RipeStatClient(ripe));

        var act = () => finder.FindByAsnListAsync([(64500u, 1)], ct: cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }
}
