using FluentAssertions;
using SubnetSearch.Core.Utilities;

namespace SubnetSearch.Tests;

public class BatchInputClassifierTests
{
    [Theory]
    [InlineData("8.8.8.8")]
    [InlineData("1.2.3.4")]
    [InlineData("192.168.0.1")]
    public void Classify_Ipv4_ReturnsIpv4(string item)
        => BatchInputClassifier.Classify(item).Should().Be(BatchInputKind.Ipv4);

    [Theory]
    [InlineData("2001:4860:4860::8888")]
    [InlineData("::1")]
    [InlineData("fe80::1")]
    public void Classify_Ipv6_ReturnsUnsupported(string item)
        => BatchInputClassifier.Classify(item).Should().Be(BatchInputKind.Ipv6Unsupported);

    [Theory]
    [InlineData("example.com")]
    [InlineData("sub.domain.co.uk")]
    public void Classify_Domain_ReturnsDomain(string item)
        => BatchInputClassifier.Classify(item).Should().Be(BatchInputKind.Domain);

    [Theory]
    [InlineData("not a host")]
    [InlineData("http://has.scheme/path")]
    [InlineData("")]
    public void Classify_Garbage_ReturnsUnrecognized(string item)
        => BatchInputClassifier.Classify(item).Should().Be(BatchInputKind.Unrecognized);
}
