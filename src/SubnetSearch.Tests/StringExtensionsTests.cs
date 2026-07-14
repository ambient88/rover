using FluentAssertions;
using SubnetSearch.Core.Extensions;

namespace SubnetSearch.Tests;

public class StringExtensionsTests
{
    [Theory]
    [InlineData("short", 10, "short")]
    [InlineData("exact", 5, "exact")]
    [InlineData("", 3, "")]
    public void Truncate_KeepsStringsWithinLimit(string value, int maxLength, string expected)
        => value.Truncate(maxLength).Should().Be(expected);

    [Theory]
    [InlineData("truncated", 4, "trun...")]
    [InlineData("ab", 1, "a...")]
    public void Truncate_CutsAndAppendsEllipsis(string value, int maxLength, string expected)
        => value.Truncate(maxLength).Should().Be(expected);
}
