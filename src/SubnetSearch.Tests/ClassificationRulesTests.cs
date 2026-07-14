using FluentAssertions;
using SubnetSearch.Classification;

namespace SubnetSearch.Tests;

public class ClassificationRulesTests
{
    [Theory]
    [InlineData("hosting")]
    [InlineData("HOSTING")]
    [InlineData("cloud")]
    [InlineData("server")]
    [InlineData("datacenter")]
    [InlineData("vps")]
    [InlineData("dedicated")]
    [InlineData("cdn")]
    [InlineData("colo")]
    public void HostingKeywords_MatchExpectedTerms(string keyword)
        => ClassificationRules.HostingKeywords.Should().Contain(keyword);

    [Theory]
    [InlineData("hosting", true)]
    [InlineData("HOSTING", true)]
    [InlineData("content", true)]
    [InlineData("Content", true)]
    [InlineData("nsp",     false)]   // ISP and transit networks are not hosting.
    [InlineData("NSP",     false)]
    [InlineData("isp",     false)]
    [InlineData("ixp",     false)]
    [InlineData("edu",     false)]
    [InlineData(null,      false)]
    public void IsHostingPeeringDbType_ReturnsExpected(string? infoType, bool expected)
        => ClassificationRules.IsHostingPeeringDbType(infoType).Should().Be(expected);

    [Theory]
    [InlineData(174u,   true)]   // Cogent
    [InlineData(3257u,  true)]   // GTT
    [InlineData(1299u,  true)]   // Arelion
    [InlineData(2914u,  true)]   // NTT
    [InlineData(3356u,  true)]   // Lumen
    [InlineData(13335u, false)]  // Cloudflare is not a backbone provider.
    [InlineData(24940u, false)]  // Hetzner is not a backbone provider.
    [InlineData(0u,     false)]
    public void BackboneAsns_ContainsExpectedProviders(uint asn, bool shouldBeBackbone)
        => ClassificationRules.BackboneAsns.Contains(asn).Should().Be(shouldBeBackbone);

    [Theory]
    [InlineData("ae2.cr6-cph1.ip4.gtt.net.",       true)]   // GTT router interface
    [InlineData("xe-0-0-1.cr1-ams1.ip4.gtt.net.",  true)]   // 10GE Juniper
    [InlineData("ge-0-0-0.pe1-fra1.example.net.",  true)]   // GigaEthernet PE router
    [InlineData("bundle-ether1.core.example.com.", true)]   // Cisco Bundle-Ether
    [InlineData("hundredge0-1.bb.example.com.",    true)]   // 100GE Cisco
    [InlineData("mail.google.com.",                false)]  // regular host
    [InlineData("static.123.45.67.89.clients.your-server.de.", false)]
    [InlineData(null,                              false)]
    [InlineData("",                                false)]
    public void IsRouterPtr_DetectsRouterInterfaces(string? ptr, bool expected)
        => ClassificationRules.IsRouterPtr(ptr).Should().Be(expected);

    [Theory]
    [InlineData("Hetzner Online GmbH", false)]  // Known hosting is not NonHosting.
    [InlineData("OVH SAS",             false)]
    public void IsNonHostingOrg_ReturnsFalseForHostingOrgs(string org, bool expected)
        => ClassificationRules.IsNonHostingOrg(org).Should().Be(expected);

    [Theory]
    [InlineData("instance337049.waicore.network.", true)]   // cloud instance (waicore)
    [InlineData("instance1.example.com.",          true)]   // generic instance
    [InlineData("vm-42.provider.net.",             true)]   // VM
    [InlineData("vm42.example.com.",               true)]   // VM no dash
    [InlineData("ec2-1-2-3-4.compute.amazonaws.com.", true)] // AWS
    [InlineData("droplet.example.com.",            true)]   // DigitalOcean
    [InlineData("s263723.love-is.nexus.",          true)]   // H2NEXUS server ID
    [InlineData("s1234.hoster.net.",               true)]   // 4-digit server ID
    [InlineData("s12.example.com.",                false)]  // Two digits are too ambiguous.
    [InlineData("s1.example.com.",                 false)]  // One digit is too ambiguous.
    [InlineData("ae2.cr6-cph1.ip4.gtt.net.",       false)]  // Router names must not upgrade the result.
    [InlineData("192-168-1-1.isp.example.com.",    false)]  // residential-style reverse DNS
    [InlineData(null,                              false)]
    public void ResolveHostingTypeFromPtr_DetectsHostingPatterns(string? ptr, bool shouldDetect)
        => (ClassificationRules.ResolveHostingTypeFromPtr(ptr) != null).Should().Be(shouldDetect);
}
