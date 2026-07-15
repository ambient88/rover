using FluentAssertions;
using SubnetSearch.Core.Utilities;

namespace SubnetSearch.Tests;

public class DerivedCachePathTests
{
    [Fact]
    public void OverrideRoot_WinsOverLocalData()
    {
        string path = DerivedCachePath.ForDataDirectory(
            "data", "asn", overrideRoot: @"X:\cache-root", localData: @"C:\local");

        path.Should().StartWith(@"X:\cache-root").And.EndWith("asn");
        path.Should().NotContain("local");
    }

    [Fact]
    public void WithoutOverride_UsesLocalDataSubfolder()
    {
        string path = DerivedCachePath.ForDataDirectory(
            "data", "asn", overrideRoot: null, localData: @"C:\local");

        path.Should().StartWith(Path.Combine(@"C:\local", "rover", "cache"));
        path.Should().EndWith("asn");
    }

    [Fact]
    public void EmptyLocalData_FallsBackToTempPath()
    {
        string path = DerivedCachePath.ForDataDirectory(
            "data", "asn", overrideRoot: " ", localData: "");

        path.Should().StartWith(Path.Combine(Path.GetTempPath(), "rover", "cache"));
    }

    [Fact]
    public void SameDataDirectory_ProducesStableHashSegment()
    {
        string a = DerivedCachePath.ForDataDirectory("data", "asn", @"X:\r", @"C:\l");
        string b = DerivedCachePath.ForDataDirectory("data", "geo", @"X:\r", @"C:\l");

        // Same source directory means the same 16-char hash segment.
        Path.GetDirectoryName(a).Should().Be(Path.GetDirectoryName(b));
    }

    [Fact]
    public void PublicOverload_ResolvesFromEnvironment()
    {
        // The suite runs with ROVER_CACHE_DIR set (redirected away from
        // LocalApplicationData), so the public overload must land under it.
        string? root = Environment.GetEnvironmentVariable(DerivedCachePath.CacheRootEnvVar);
        string path = DerivedCachePath.ForDataDirectory("data", "asn");

        if (!string.IsNullOrWhiteSpace(root))
            path.Should().StartWith(root);
        else
            path.Should().Contain(Path.Combine("rover", "cache"));
    }
}
