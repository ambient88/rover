using System.Net;
using System.Security.Cryptography;
using System.Text;
using FluentAssertions;
using SubnetSearch.Core.Models.Data;
using SubnetSearch.Data;

namespace SubnetSearch.Tests;

// Offline coverage of the fresh-download / checksum / retry / conditional paths.
public class HttpFileDownloaderTests
{
    private static string Sha256Hex(string s)
        => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(s))).ToLowerInvariant();

    private static async Task<string> ReadAll(Stream s)
    {
        using var r = new StreamReader(s);
        return await r.ReadToEndAsync();
    }

    private static DownloadOptions FreshOpts(string? checksum = null, int maxRetries = 0)
        => new() { MaxRetries = maxRetries, RetryDelayMilliseconds = 1, UseResume = false, ChecksumSha256 = checksum };

    [Fact]
    public async Task Download_Fresh_ReturnsBody()
    {
        var handler = TestHttpMessageHandler.Always(HttpStatusCode.OK, "hello-data");
        var downloader = new HttpFileDownloader(new HttpClient(handler));

        await using var s = await downloader.DownloadAsync("https://x/f", FreshOpts());

        (await ReadAll(s)).Should().Be("hello-data");
    }

    [Fact]
    public async Task Download_ChecksumMatches_Succeeds()
    {
        var handler = TestHttpMessageHandler.Always(HttpStatusCode.OK, "payload");
        var downloader = new HttpFileDownloader(new HttpClient(handler));

        await using var s = await downloader.DownloadAsync("https://x/f", FreshOpts(Sha256Hex("payload")));

        (await ReadAll(s)).Should().Be("payload");
    }

    [Fact]
    public async Task Download_ChecksumMismatch_Throws()
    {
        var handler = TestHttpMessageHandler.Always(HttpStatusCode.OK, "payload");
        var downloader = new HttpFileDownloader(new HttpClient(handler));

        await downloader.Invoking(d => d.DownloadAsync("https://x/f", FreshOpts(checksum: "deadbeef")))
            .Should().ThrowAsync<InvalidDataException>();
    }

    [Fact]
    public async Task Download_RetriesAfterTransientFailure()
    {
        int calls = 0;
        var handler = TestHttpMessageHandler.Custom(_ =>
        {
            if (++calls == 1) throw new HttpRequestException("transient");
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("ok-body") };
        });
        var downloader = new HttpFileDownloader(new HttpClient(handler));

        await using var s = await downloader.DownloadAsync(
            "https://x/f", new DownloadOptions { MaxRetries = 2, RetryDelayMilliseconds = 1, UseResume = false });

        (await ReadAll(s)).Should().Be("ok-body");
        calls.Should().Be(2, "first attempt failed, second succeeded");
    }

    [Fact]
    public async Task Download_RetryExhaustion_Throws()
    {
        var handler = TestHttpMessageHandler.Throws(new HttpRequestException("upstream down"));
        var downloader = new HttpFileDownloader(new HttpClient(handler));

        Func<Task> act = () => downloader.DownloadAsync(
            "https://x/f", new DownloadOptions { MaxRetries = 1, RetryDelayMilliseconds = 1, UseResume = false });

        await act.Should().ThrowAsync<HttpRequestException>();
    }

    [Fact]
    public async Task Conditional_ServerError_Throws()
    {
        var handler = TestHttpMessageHandler.Always(HttpStatusCode.InternalServerError, "");
        var downloader = new HttpFileDownloader(new HttpClient(handler));

        Func<Task> act = () => downloader.ConditionalDownloadAsync(
            "https://x/f", etag: null, lastModified: null, new DownloadOptions());

        await act.Should().ThrowAsync<HttpRequestException>();
    }

    [Fact]
    public async Task Conditional_NotModified_ReturnsFlag()
    {
        var handler = TestHttpMessageHandler.Custom(_ =>
            new HttpResponseMessage(HttpStatusCode.NotModified));
        var downloader = new HttpFileDownloader(new HttpClient(handler));

        var result = await downloader.ConditionalDownloadAsync(
            "https://x/f", etag: "\"v1\"", lastModified: null, new DownloadOptions());

        result.NotModified.Should().BeTrue();
        result.Content.Should().BeNull();
    }

    [Fact]
    public async Task Conditional_Modified_ReturnsStreamAndValidators()
    {
        var handler = TestHttpMessageHandler.Custom(_ =>
        {
            var resp = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("new-body") };
            resp.Headers.TryAddWithoutValidation("ETag", "\"v2\"");
            return resp;
        });
        var downloader = new HttpFileDownloader(new HttpClient(handler));

        var result = await downloader.ConditionalDownloadAsync(
            "https://x/f", etag: "\"v1\"", lastModified: null, new DownloadOptions());

        result.NotModified.Should().BeFalse();
        result.NewETag.Should().Be("\"v2\"");
        await using var content = result.Content!;
        (await ReadAll(content)).Should().Be("new-body");
    }
}
