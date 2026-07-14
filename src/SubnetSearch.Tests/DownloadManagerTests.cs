using System.Net;
using FluentAssertions;
using SubnetSearch.Core.Models.Data;
using SubnetSearch.Data;

namespace SubnetSearch.Tests;

public class DownloadManagerTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory().FullName;
    public void Dispose() { if (Directory.Exists(_dir)) Directory.Delete(_dir, true); }

    private DownloadManager Manager(TestHttpMessageHandler handler, params FileDescriptor[] files)
    {
        var downloader = new HttpFileDownloader(new HttpClient(handler));
        var storage = DownloadManagerFactory.CreateStorage(_dir);
        return new DownloadManager(downloader, storage, files, new FileMetadataStore(_dir));
    }

    private static FileDescriptor Fd(string name, string url = "https://example.com/f")
        => new(url, name, 1, TimeSpan.FromDays(1));

    [Fact]
    public async Task DownloadSingleFile_Fresh_DownloadsAndSaves()
    {
        var handler = TestHttpMessageHandler.Always(HttpStatusCode.OK, "hello");
        var fd = Fd("a.txt");

        var ok = await Manager(handler, fd).DownloadSingleFileAsync(fd);

        ok.Should().BeTrue();
        (await File.ReadAllTextAsync(Path.Combine(_dir, "a.txt"))).Should().Be("hello");
    }

    [Fact]
    public async Task DownloadSingleFile_AlreadyValid_SkipsNetwork()
    {
        await File.WriteAllTextAsync(Path.Combine(_dir, "a.txt"), "already-here");
        var handler = TestHttpMessageHandler.Always(HttpStatusCode.OK, "new");
        var fd = Fd("a.txt");

        var ok = await Manager(handler, fd).DownloadSingleFileAsync(fd);

        ok.Should().BeTrue();
        handler.Requests.Should().BeEmpty("a valid existing file is not re-downloaded");
    }

    [Fact]
    public async Task DownloadAll_ReturnsSuccessfulFileNames()
    {
        var handler = TestHttpMessageHandler.Always(HttpStatusCode.OK, "payload");
        var files = new[] { Fd("one.txt", "https://x/1"), Fd("two.txt", "https://x/2") };

        var result = await Manager(handler, files)
            .DownloadAllAsync(new DownloadOptions { MaxRetries = 0, UseResume = false }, force: true);

        result.Should().BeEquivalentTo(new[] { "one.txt", "two.txt" });
    }

    [Fact]
    public async Task DownloadAllDetailed_ServerError_ReportsFailure()
    {
        var handler = TestHttpMessageHandler.Always(HttpStatusCode.InternalServerError, "");
        var fd = Fd("bad.txt");

        var result = await Manager(handler, fd).DownloadAllDetailedAsync(
            new DownloadOptions { MaxRetries = 0, UseResume = false }, force: true);

        result.Should().ContainSingle(r => !r.Success);
    }

    [Fact]
    public async Task DownloadAllDetailed_FileBelowMinSize_ReportsCorruption()
    {
        var handler = TestHttpMessageHandler.Always(HttpStatusCode.OK, "tiny");
        // MinSize far above the payload: the post-save validity check must fail.
        var fd = new FileDescriptor("https://x/f", "small.txt", 1_000, TimeSpan.FromDays(1));

        var result = await Manager(handler, fd).DownloadAllDetailedAsync(
            new DownloadOptions { MaxRetries = 0, UseResume = false }, force: true);

        result.Should().ContainSingle(r =>
            !r.Success && r.ErrorMessage == "File is corrupted after download.");
    }

    [Fact]
    public async Task DownloadSingleFile_FileBelowMinSize_Throws()
    {
        var handler = TestHttpMessageHandler.Always(HttpStatusCode.OK, "tiny");
        var fd = new FileDescriptor("https://x/f", "small.txt", 1_000, TimeSpan.FromDays(1));

        var act = () => Manager(handler, fd).DownloadSingleFileAsync(fd);

        await act.Should().ThrowAsync<InvalidDataException>();
    }
}
