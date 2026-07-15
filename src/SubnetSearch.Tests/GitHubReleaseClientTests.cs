using System.Net;
using System.Runtime.InteropServices;
using FluentAssertions;
using SubnetSearch.Data;

namespace SubnetSearch.Tests;

// Release checks power the `update` version notice and `self-update`; every network
// or parsing failure must degrade to null instead of breaking the primary command.
public class GitHubReleaseClientTests
{
    private static GitHubReleaseClient Client(TestHttpMessageHandler h)
        => new(new HttpClient(h));

    [Fact]
    public async Task GetLatest_ParsesTagAndAssets()
    {
        const string json = """
        {"tag_name":"v1.2.3","assets":[
          {"name":"rover-win-x64.exe","browser_download_url":"https://dl/win"},
          {"name":"rover-linux-x64","browser_download_url":"https://dl/linux"}
        ]}
        """;
        var handler = TestHttpMessageHandler.Always(HttpStatusCode.OK, json);

        var release = await Client(handler).GetLatestAsync();

        release.Should().NotBeNull();
        release!.Version.Should().Be("1.2.3");
        release.AssetUrls["rover-win-x64.exe"].Should().Be("https://dl/win");
        release.AssetUrls["rover-linux-x64"].Should().Be("https://dl/linux");
        handler.Requests[0].Headers.UserAgent.Should().NotBeNull(
            "the GitHub API rejects requests without a User-Agent");
    }

    [Fact]
    public async Task GetLatest_AssetsWithoutNameOrUrl_AreSkipped()
    {
        const string json = """
        {"tag_name":"v2.0.0","assets":[
          {"name":"rover-osx-arm64"},
          {"browser_download_url":"https://dl/orphan"},
          {"name":"rover-linux-arm64","browser_download_url":"https://dl/ok"}
        ]}
        """;

        var release = await Client(TestHttpMessageHandler.Always(HttpStatusCode.OK, json)).GetLatestAsync();

        release!.AssetUrls.Should().HaveCount(1).And.ContainKey("rover-linux-arm64");
    }

    [Fact]
    public async Task GetLatest_NoTagName_ReturnsNull()
    {
        var release = await Client(TestHttpMessageHandler.Always(HttpStatusCode.OK, """{"assets":[]}"""))
            .GetLatestAsync();

        release.Should().BeNull();
    }

    [Fact]
    public async Task GetLatest_NoAssetsProperty_StillReturnsVersion()
    {
        var release = await Client(TestHttpMessageHandler.Always(HttpStatusCode.OK, """{"tag_name":"v3.0.0"}"""))
            .GetLatestAsync();

        release!.Version.Should().Be("3.0.0");
        release.AssetUrls.Should().BeEmpty();
    }

    [Fact]
    public async Task GetLatest_HttpError_ReturnsNull()
    {
        var release = await Client(TestHttpMessageHandler.Always(HttpStatusCode.Forbidden, "rate limited"))
            .GetLatestAsync();

        release.Should().BeNull("a rate-limited API check degrades silently");
    }

    [Fact]
    public async Task GetLatest_MalformedJson_ReturnsNull()
    {
        var release = await Client(TestHttpMessageHandler.Always(HttpStatusCode.OK, "{ broken"))
            .GetLatestAsync();

        release.Should().BeNull();
    }

    [Fact]
    public async Task GetLatest_NetworkFailure_ReturnsNull()
    {
        var release = await Client(TestHttpMessageHandler.Throws(new HttpRequestException("offline")))
            .GetLatestAsync();

        release.Should().BeNull();
    }

    [Fact]
    public async Task GetLatest_CancelledMidRequest_Rethrows()
    {
        using var cts = new CancellationTokenSource();
        var handler = TestHttpMessageHandler.Custom(_ =>
        {
            cts.Cancel();
            throw new OperationCanceledException(cts.Token);
        });

        var act = () => Client(handler).GetLatestAsync(cts.Token);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    [Theory]
    [InlineData("v1.2.3",              "1.2.3")]
    [InlineData("V2.0.0",              "2.0.0")]
    [InlineData("1.2.3-alpha.0+abc",   "1.2.3")]
    [InlineData("  v0.0.2  ",          "0.0.2")]
    [InlineData("0.0.1+build",         "0.0.1")]
    public void NormalizeVersion_StripsPrefixAndMetadata(string tag, string expected)
        => GitHubReleaseClient.NormalizeVersion(tag).Should().Be(expected);

    [Theory]
    [InlineData("v0.0.2", "0.0.1",        true)]
    [InlineData("v0.0.1", "0.0.1",        false)]
    [InlineData("v0.0.1", "0.0.2",        false)]
    [InlineData("v1.0.0", "0.9.9-beta+g", true)]
    [InlineData("garbage", "0.0.1",       false)] // unparseable never nudges
    [InlineData("v1.0.0", "unknown",      false)]
    public void IsNewer_ComparesNumericCores(string latest, string current, bool expected)
        => GitHubReleaseClient.IsNewer(latest, current).Should().Be(expected);

    [Theory]
    [InlineData("win",   Architecture.X64,   "rover-win-x64.exe")]
    [InlineData("linux", Architecture.X64,   "rover-linux-x64")]
    [InlineData("linux", Architecture.Arm64, "rover-linux-arm64")]
    [InlineData("osx",   Architecture.Arm64, "rover-osx-arm64")]
    [InlineData("osx",   Architecture.X64,   "rover-osx-x64")]
    public void AssetName_MatchesReleaseWorkflowNaming(string os, Architecture arch, string expected)
        => GitHubReleaseClient.AssetName(os, arch).Should().Be(expected);

    [Theory]
    [InlineData(null,      Architecture.X64)]
    [InlineData("freebsd", Architecture.X64)]
    [InlineData("win",     Architecture.Wasm)] // no published asset for this architecture
    public void AssetName_UnsupportedPlatform_ReturnsNull(string? os, Architecture arch)
        => GitHubReleaseClient.AssetName(os, arch).Should().BeNull();
}
