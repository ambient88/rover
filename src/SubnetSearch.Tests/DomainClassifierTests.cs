using System.Net;
using FluentAssertions;
using SubnetSearch.Classification;
using SubnetSearch.Core.Interfaces.Classification;
using SubnetSearch.Core.Models.Classification;

namespace SubnetSearch.Tests;

// DomainClassifier: резолв IP домена, параллельная классификация каждого IP, reverse DNS и
// WHOIS домена; вывод хостинг-провайдера и типа сервиса по ключевым словам в домене.
public class DomainClassifierTests
{
    private sealed class StubDns : IDnsResolver
    {
        private readonly IReadOnlyList<IPAddress> _ips;
        private readonly string? _ptr;
        public StubDns(IReadOnlyList<IPAddress> ips, string? ptr = null) { _ips = ips; _ptr = ptr; }
        public Task<IReadOnlyList<IPAddress>> ResolveAllIpAsync(string d, CancellationToken ct = default)
            => Task.FromResult(_ips);
        public Task<string?> ReverseDnsAsync(IPAddress ip, CancellationToken ct = default)
            => Task.FromResult(_ptr);
    }

    private sealed class StubIpClassifier : IIpClassifier
    {
        private readonly Func<string, ClassificationResult> _fn;
        public StubIpClassifier(Func<string, ClassificationResult> fn) => _fn = fn;
        public Task<ClassificationResult> ClassifyAsync(string ip, CancellationToken ct = default)
            => Task.FromResult(_fn(ip));
    }

    private sealed class StubWhois : IDomainWhoisResolver
    {
        private readonly DomainWhoisResult _r;
        public StubWhois(DomainWhoisResult r) => _r = r;
        public Task<DomainWhoisResult> ResolveAsync(string d, CancellationToken ct = default)
            => Task.FromResult(_r);
    }

    private static ClassificationResult Hosting(string org, bool isHosting = true)
        => new(isHosting, 24940, org, "DE", null, "test");

    private static DomainWhoisResult Whois(string? registrar, string? host)
        => new(registrar, host, null, null, new[] { "ns1.example" }, "active", null);

    // Regression for F3: a domain registered at GoDaddy but hosted at Hetzner must report Hetzner
    // as the hosting provider. The registrar stays a separate field and must NOT leak into hosting,
    // even if the WHOIS record happens to carry a (registrar-conflated) provider string.
    [Fact]
    public async Task Classify_HostingFromIp_RegistrarNeverSubstitutesHosting()
    {
        var dns = new StubDns(new[] { IPAddress.Parse("1.2.3.4") }, ptr: "host.example");
        var ipc = new StubIpClassifier(_ => Hosting("Hetzner"));
        // WHOIS supplies both a registrar and a (bogus) provider — neither may become the host.
        var who = new StubWhois(Whois("GoDaddy", "GoDaddy"));
        var sut = new DomainClassifier(ipc, who, dns);

        var result = await sut.ClassifyDomainAsync("example.com");

        result.DomainRegistrar.Should().Be("GoDaddy");
        result.DomainHostingProvider.Should().Be("Hetzner", "hosting is derived from the resolved IP, not WHOIS");
        result.DomainHostingProvider.Should().NotBe("GoDaddy", "the registrar must never be shown as the host");
        result.ResolvedIpAddresses.Should().Equal("1.2.3.4");
        result.ReverseDns.Should().Be("host.example");
        result.IpResults.Should().ContainSingle();
    }

    [Fact]
    public async Task Classify_NoWhoisProvider_DerivesFromHostingIp()
    {
        var dns = new StubDns(new[] { IPAddress.Parse("1.2.3.4"), IPAddress.Parse("5.6.7.8") });
        var ipc = new StubIpClassifier(ip => ip == "1.2.3.4"
            ? new ClassificationResult(false, 111, "NonHostingOrg", "US", null, "t")
            : Hosting("HostingCorp"));
        var who = new StubWhois(Whois("Reg", host: null)); // WHOIS не дал провайдера
        var sut = new DomainClassifier(ipc, who, dns);

        var result = await sut.ClassifyDomainAsync("example.com");

        result.DomainHostingProvider.Should().Be("HostingCorp", "берётся первый IsHosting-результат");
    }

    [Theory]
    [InlineData("vpn.example.com",     "VPN service")]
    [InlineData("myproxy.example.com", "Proxy service")]
    [InlineData("cdn.example.org",     "CDN service")]
    public async Task Classify_DetectsServiceTypeFromDomainLabels(string domain, string expected)
    {
        var dns = new StubDns(Array.Empty<IPAddress>());
        var ipc = new StubIpClassifier(_ => Hosting("x"));
        var who = new StubWhois(Whois("r", "h"));
        var sut = new DomainClassifier(ipc, who, dns);

        (await sut.ClassifyDomainAsync(domain)).DomainServiceType.Should().Be(expected);
    }

    [Fact]
    public async Task Classify_PlainDomain_NoServiceType()
    {
        var dns = new StubDns(Array.Empty<IPAddress>());
        var sut = new DomainClassifier(new StubIpClassifier(_ => Hosting("x")),
            new StubWhois(Whois("r", "h")), dns);

        (await sut.ClassifyDomainAsync("example.com")).DomainServiceType.Should().BeNull();
    }

    [Fact]
    public async Task Classify_NoResolvedIps_EmptyResultsAndNullReverseDns() // краевой случай
    {
        var dns = new StubDns(Array.Empty<IPAddress>(), ptr: "should-not-be-used");
        var sut = new DomainClassifier(new StubIpClassifier(_ => Hosting("x")),
            new StubWhois(Whois("Reg", "Prov")), dns);

        var result = await sut.ClassifyDomainAsync("example.com");

        result.IpResults.Should().BeEmpty();
        result.ResolvedIpAddresses.Should().BeEmpty();
        result.ReverseDns.Should().BeNull("reverse DNS не запрашивается без IP");
    }
}
