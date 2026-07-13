using FluentAssertions;
using SubnetSearch.Core.Utilities;

namespace SubnetSearch.Tests;

public class SafeUrlTests
{
    [Fact]
    public void TryNormalizeHttp_AcceptsHttpUrl()
    {
        SafeUrl.TryNormalizeHttp("https://example.com/pricing", out string normalized)
            .Should().BeTrue();
        normalized.Should().Be("https://example.com/pricing");
    }

    [Theory]
    [InlineData("javascript:alert(1)")]
    [InlineData("file:///etc/passwd")]
    [InlineData("https://example.com/\nnext")]
    public void TryNormalizeHttp_RejectsUnsafeUrl(string value)
        => SafeUrl.TryNormalizeHttp(value, out _).Should().BeFalse();
}
