using System.Net;
using FluentAssertions;
using SubnetSearch.Classification;
using SubnetSearch.Core.Interfaces.Classification;
using SubnetSearch.Core.Models.Classification;

namespace SubnetSearch.Tests;

// HostingTypeResolver: трёхслойное определение типа хостинга (PTR → PeeringDB info_type →
// ключевые слова в имени). Здесь проверяется слой PeeringDB и маппинг info_type.
public class HostingTypeResolverTests
{
    private sealed class StubDns : IDnsResolver
    {
        private readonly string? _ptr;
        public StubDns(string? ptr) => _ptr = ptr;
        public Task<IReadOnlyList<IPAddress>> ResolveAllIpAsync(string d, CancellationToken ct = default)
            => Task.FromResult((IReadOnlyList<IPAddress>)Array.Empty<IPAddress>());
        public Task<string?> ReverseDnsAsync(IPAddress ip, CancellationToken ct = default)
            => Task.FromResult(_ptr);
    }

    private sealed class StubWebsite : IWebsiteResolver
    {
        private readonly PeeringDbNetworkInfo? _info;
        public StubWebsite(PeeringDbNetworkInfo? info) => _info = info;
        public string? GetWebsite(uint? asn, string? org, string? whoisWebsite = null) => null;
        public Task<PeeringDbNetworkInfo?> GetNetworkInfoFromPeeringDbAsync(uint asn, CancellationToken ct = default)
            => Task.FromResult(_info);
        public Task<IReadOnlyList<string>?> GetIxLocationsAsync(uint asn, CancellationToken ct = default)
            => Task.FromResult<IReadOnlyList<string>?>(null);
    }

    private static HostingTypeResolver Sut(string? ptr, PeeringDbNetworkInfo? info)
        => new(new StubDns(ptr), new StubWebsite(info));

    [Theory]
    [InlineData("hosting",    HostingType.Vps)]
    [InlineData("enterprise", HostingType.Colocation)]
    [InlineData("content",    HostingType.Cloud)]
    public async Task Resolve_MapsPeeringDbInfoType(string infoType, HostingType expected)
    {
        // PTR = null → слой 1 не срабатывает; результат берётся из PeeringDB info_type.
        var sut = Sut(ptr: null, info: new PeeringDbNetworkInfo(Website: null, InfoType: infoType));

        var result = await sut.ResolveAsync("1.2.3.4", asn: 24940, orgName: null);

        result.Should().Be(expected);
    }

    [Fact]
    public async Task Resolve_UnknownInfoType_NoOrgName_ReturnsUnknown()
    {
        var sut = Sut(ptr: null, info: new PeeringDbNetworkInfo(null, "some-other-type"));

        var result = await sut.ResolveAsync("1.2.3.4", asn: 24940, orgName: null);

        result.Should().Be(HostingType.Unknown);
    }

    [Fact]
    public async Task Resolve_NoAsn_NoOrg_ReturnsUnknown() // краевой случай: нет данных ни на одном слое
    {
        var sut = Sut(ptr: null, info: null);

        var result = await sut.ResolveAsync("1.2.3.4", asn: null, orgName: null);

        result.Should().Be(HostingType.Unknown);
    }

    [Fact]
    public async Task Resolve_NullInfoType_FallsThrough()
    {
        // PeeringDB вернул запись без info_type → слой 2 пропускается, орг-имя пустое → Unknown.
        var sut = Sut(ptr: null, info: new PeeringDbNetworkInfo(Website: "x.example", InfoType: null));

        (await sut.ResolveAsync("1.2.3.4", asn: 24940, orgName: null)).Should().Be(HostingType.Unknown);
    }

    [Fact]
    public void Constructor_NullArguments_Throw()
    {
        FluentActions.Invoking(() => new HostingTypeResolver(null!, new StubWebsite(null)))
            .Should().Throw<ArgumentNullException>();
        FluentActions.Invoking(() => new HostingTypeResolver(new StubDns(null), null!))
            .Should().Throw<ArgumentNullException>();
    }
}
