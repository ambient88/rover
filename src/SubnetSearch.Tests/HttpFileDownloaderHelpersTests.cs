using System.Net;
using System.Net.Http.Headers;
using FluentAssertions;
using SubnetSearch.Data;

namespace SubnetSearch.Tests;

// Direct tests for the downloader's resume plumbing: If-Range selection,
// Content-Range validation edges, partial-state persistence, and the
// convenience overloads that delegate to the full download entry point.
public sealed class HttpFileDownloaderHelpersTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory().FullName;
    public void Dispose() { if (Directory.Exists(_dir)) Directory.Delete(_dir, true); }

    private static HttpFileDownloader Downloader(TestHttpMessageHandler handler)
        => new(new HttpClient(handler));

    // ── Convenience overloads ──

    [Fact]
    public async Task DownloadAsync_UrlOnlyOverload_DownloadsContent()
    {
        var handler = TestHttpMessageHandler.Always(HttpStatusCode.OK, "abc");

        await using var stream = await Downloader(handler).DownloadAsync("https://x/f");

        new StreamReader(stream).ReadToEnd().Should().Be("abc");
    }

    [Fact]
    public async Task DownloadAsync_DownloadProgressOverload_ReportsBytes()
    {
        var handler = TestHttpMessageHandler.Always(HttpStatusCode.OK, "abcd");
        long last = 0;
        var progress = new InlineProgress<SubnetSearch.Core.Models.Data.DownloadProgress>(
            p => last = p.BytesDownloaded);

        await using var stream = await Downloader(handler)
            .DownloadAsync("https://x/f", progress, CancellationToken.None);

        last.Should().Be(4);
    }

    private sealed class InlineProgress<T>(Action<T> handler) : IProgress<T>
    {
        public void Report(T value) => handler(value);
    }

    // ── IsValidContentRange edges ──

    // Malformed values come from real (buggy or hostile) servers, so they are added
    // without client-side validation, exactly as HttpClient would surface them.
    private static HttpResponseMessage RawRangeResponse(string contentRange, long? contentLength = null)
    {
        var resp = new HttpResponseMessage(HttpStatusCode.PartialContent)
        {
            Content = new ByteArrayContent([])
        };
        resp.Content.Headers.TryAddWithoutValidation("Content-Range", contentRange);
        if (contentLength.HasValue)
            resp.Content.Headers.ContentLength = contentLength;
        return resp;
    }

    [Fact]
    public void IsValidContentRange_RangeEndBeforeExistingLength_IsRejected()
    {
        using var resp = RawRangeResponse("bytes 100-50/*");

        HttpFileDownloader.IsValidContentRange(resp, existingLength: 100).Should().BeFalse();
    }

    [Fact]
    public void IsValidContentRange_RangeEndBeyondTotal_IsRejected()
    {
        using var resp = RawRangeResponse("bytes 100-200/150");

        HttpFileDownloader.IsValidContentRange(resp, existingLength: 100).Should().BeFalse();
    }

    [Fact]
    public void IsValidContentRange_ConsistentRange_IsAccepted()
    {
        using var resp = RawRangeResponse("bytes 100-199/200", contentLength: 100);

        HttpFileDownloader.IsValidContentRange(resp, existingLength: 100).Should().BeTrue();
    }

    // Pure-core edges: value combinations the .NET header parser refuses to construct
    // must still be rejected by the validation itself.
    [Theory]
    [InlineData("bytes", 100L, 50L, null, null, 100L, false)]  // range ends before the resume point
    [InlineData("bytes", 100L, 200L, 150L, null, 100L, false)] // range ends beyond the declared total
    [InlineData("bytes", 100L, 199L, 200L, 5L, 100L, false)]   // body length contradicts the range
    [InlineData("bytes", 100L, 199L, 200L, 100L, 100L, true)]
    [InlineData(null, 100L, 199L, 200L, 100L, 100L, false)]    // unit missing
    public void IsValidContentRangeCore_Edges(
        string? unit, long? from, long? to, long? length,
        long? contentLength, long existing, bool expected)
        => HttpFileDownloader.IsValidContentRange(unit, from, to, length, contentLength, existing)
            .Should().Be(expected);

    // ── TrySetIfRange ──

    [Fact]
    public void TrySetIfRange_PrefersETag()
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, "https://x/f");
        var state = new HttpFileDownloader.PartialDownloadState("\"abc\"", "Tue, 01 Jul 2025 10:00:00 GMT");

        HttpFileDownloader.TrySetIfRange(req, state).Should().BeTrue();
        req.Headers.IfRange!.EntityTag.Should().NotBeNull();
    }

    [Fact]
    public void TrySetIfRange_FallsBackToLastModified()
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, "https://x/f");
        var state = new HttpFileDownloader.PartialDownloadState(null, "Tue, 01 Jul 2025 10:00:00 GMT");

        HttpFileDownloader.TrySetIfRange(req, state).Should().BeTrue();
        req.Headers.IfRange!.Date.Should().NotBeNull();
    }

    [Fact]
    public void TrySetIfRange_NoValidator_ReturnsFalse()
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, "https://x/f");
        var state = new HttpFileDownloader.PartialDownloadState(null, "not-a-date");

        HttpFileDownloader.TrySetIfRange(req, state).Should().BeFalse();
        req.Headers.IfRange.Should().BeNull();
    }

    // ── Partial-state persistence ──

    [Fact]
    public async Task PartialState_PersistentRoundTrip()
    {
        var downloader = Downloader(TestHttpMessageHandler.Always(HttpStatusCode.OK, ""));
        string part = Path.Combine(_dir, "f.part");
        var state = new HttpFileDownloader.PartialDownloadState("\"tag\"", null);

        await downloader.SavePartialStateAsync("https://x/f", part, state, persistent: true, CancellationToken.None);
        var loaded = await downloader.LoadPartialStateAsync("https://x/f", part, persistent: true, CancellationToken.None);

        loaded.Should().Be(state);
    }

    [Fact]
    public async Task PartialState_NonPersistentRoundTrip_UsesMemory()
    {
        var downloader = Downloader(TestHttpMessageHandler.Always(HttpStatusCode.OK, ""));
        string part = Path.Combine(_dir, "f.part");
        var state = new HttpFileDownloader.PartialDownloadState("\"tag\"", null);

        await downloader.SavePartialStateAsync("https://x/f", part, state, persistent: false, CancellationToken.None);
        var loaded = await downloader.LoadPartialStateAsync("https://x/f", part, persistent: false, CancellationToken.None);

        loaded.Should().Be(state);
        File.Exists(part + ".meta").Should().BeFalse("non-persistent state must never touch the disk");
    }

    [Fact]
    public async Task PartialState_NoValidators_IsNotSaved()
    {
        var downloader = Downloader(TestHttpMessageHandler.Always(HttpStatusCode.OK, ""));
        string part = Path.Combine(_dir, "f.part");

        await downloader.SavePartialStateAsync("https://x/f", part,
            new HttpFileDownloader.PartialDownloadState(null, " "), persistent: true, CancellationToken.None);

        File.Exists(part + ".meta").Should().BeFalse("a state without validators cannot support If-Range");
    }

    [Fact]
    public async Task PartialState_CorruptMetaFile_LoadsAsNull()
    {
        var downloader = Downloader(TestHttpMessageHandler.Always(HttpStatusCode.OK, ""));
        string part = Path.Combine(_dir, "f.part");
        await File.WriteAllTextAsync(part + ".meta", "{ broken");

        var loaded = await downloader.LoadPartialStateAsync(
            "https://x/f", part, persistent: true, CancellationToken.None);

        loaded.Should().BeNull();
    }

    [Fact]
    public async Task PartialState_MissingMetaFile_LoadsAsNull()
    {
        var downloader = Downloader(TestHttpMessageHandler.Always(HttpStatusCode.OK, ""));

        var loaded = await downloader.LoadPartialStateAsync(
            "https://x/f", Path.Combine(_dir, "absent.part"), persistent: true, CancellationToken.None);

        loaded.Should().BeNull();
    }

    [Fact]
    public async Task RemovePartialState_LockedMetaFile_IsSwallowed()
    {
        var downloader = Downloader(TestHttpMessageHandler.Always(HttpStatusCode.OK, ""));
        string part = Path.Combine(_dir, "f.part");
        await File.WriteAllTextAsync(part + ".meta", "{}");
        using var lockHandle = new FileStream(
            part + ".meta", FileMode.Open, FileAccess.Read, FileShare.None);

        var act = () => downloader.RemovePartialState("https://x/f", part, persistent: true);

        act.Should().NotThrow("meta cleanup is best effort");
    }

    [Fact]
    public async Task RemovePartialState_ReadOnlyMetaFile_IsSwallowed()
    {
        var downloader = Downloader(TestHttpMessageHandler.Always(HttpStatusCode.OK, ""));
        string part = Path.Combine(_dir, "ro.part");
        await File.WriteAllTextAsync(part + ".meta", "{}");
        // On Windows deleting a read-only file throws and must be swallowed;
        // on Unix the delete simply succeeds (the directory governs permissions).
        File.SetAttributes(part + ".meta", FileAttributes.ReadOnly);
        try
        {
            var act = () => downloader.RemovePartialState("https://x/f", part, persistent: true);

            act.Should().NotThrow("meta cleanup is best effort even without write permission");
        }
        finally
        {
            if (File.Exists(part + ".meta"))
                File.SetAttributes(part + ".meta", FileAttributes.Normal);
        }
    }

    [Fact]
    public void RemovePartialState_NonPersistent_DropsMemoryEntry()
    {
        var downloader = Downloader(TestHttpMessageHandler.Always(HttpStatusCode.OK, ""));

        var act = () => downloader.RemovePartialState("https://x/f", "ignored", persistent: false);

        act.Should().NotThrow();
    }

    // ── ConditionalDownloadAsync edges ──

    [Fact]
    public async Task ConditionalDownload_LastModifiedOnly_SendsIfModifiedSince()
    {
        var handler = TestHttpMessageHandler.Always(HttpStatusCode.NotModified, "");
        var downloader = Downloader(handler);

        var result = await downloader.ConditionalDownloadAsync(
            "https://x/f", etag: null, lastModified: "Tue, 01 Jul 2025 10:00:00 GMT",
            new SubnetSearch.Core.Models.Data.DownloadOptions());

        result.NotModified.Should().BeTrue();
        handler.Requests[0].Headers.Contains("If-Modified-Since").Should().BeTrue();
    }

    [Fact]
    public async Task ConditionalDownload_BodyFailsMidCopy_DisposesAndRethrows()
    {
        var handler = TestHttpMessageHandler.Custom(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StreamContent(new ThrowingStream()),
        });

        var act = () => Downloader(handler).ConditionalDownloadAsync(
            "https://x/f", etag: null, lastModified: null,
            new SubnetSearch.Core.Models.Data.DownloadOptions());

        await act.Should().ThrowAsync<IOException>();
    }

    private sealed class ThrowingStream : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => 0; set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count)
            => throw new IOException("body failed");
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
