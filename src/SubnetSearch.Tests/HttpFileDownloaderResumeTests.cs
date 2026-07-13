using System.Net;
using System.Net.Http.Headers;
using FluentAssertions;
using SubnetSearch.Data;
using SubnetSearch.Core.Models.Data;

namespace SubnetSearch.Tests;

public class HttpFileDownloaderResumeTests
{
    [Fact]
    public async Task DownloadManager_ClosesPersistentStreamBeforeDeletingPart()
    {
        string directory = Directory.CreateTempSubdirectory().FullName;
        string partialPath = Path.Combine(directory, "file.txt.part");
        await File.WriteAllTextAsync(partialPath, "abc");
        await File.WriteAllTextAsync(
            partialPath + ".meta", "{\"ETag\":\"\\\"v1\\\"\",\"LastModified\":null}");
        var handler = TestHttpMessageHandler.Custom(request =>
        {
            request.Headers.Range?.Ranges.Single().From.Should().Be(3);
            var content = new StringContent("def");
            content.Headers.ContentRange = ContentRangeHeaderValue.Parse("bytes 3-5/6");
            content.Headers.ContentLength = 3;
            return new HttpResponseMessage(HttpStatusCode.PartialContent) { Content = content };
        });

        try
        {
            using var client = new HttpClient(handler);
            var downloader = new HttpFileDownloader(client);
            var storage = DownloadManagerFactory.CreateStorage(directory);
            var files = new[]
            {
                new FileDescriptor(
                    "https://example.com/file", "file.txt", 1, TimeSpan.FromDays(1))
            };
            var manager = new DownloadManager(
                downloader, storage, files, new FileMetadataStore(directory));

            var result = await manager.DownloadAllDetailedAsync(new DownloadOptions
            {
                MaxRetries = 0,
                PartialDownloadsDir = directory
            });

            result.Should().ContainSingle(item => item.Success);
            (await File.ReadAllTextAsync(Path.Combine(directory, "file.txt")))
                .Should().Be("abcdef");
            File.Exists(partialPath).Should().BeFalse();
            File.Exists(Path.Combine(directory, "file.txt.meta.json")).Should().BeTrue();
        }
        finally
        {
            Directory.Delete(directory, true);
        }
    }

    [Fact]
    public async Task DownloadAsync_ResumesOnlyWithMatchingValidatorAndRange()
    {
        string directory = Directory.CreateTempSubdirectory().FullName;
        string partialPath = Path.Combine(directory, "download.part");
        await File.WriteAllTextAsync(partialPath, "abc");
        await File.WriteAllTextAsync(partialPath + ".meta", "{\"ETag\":\"\\\"v1\\\"\",\"LastModified\":null}");
        string? ifRange = null;
        var handler = TestHttpMessageHandler.Custom(request =>
        {
            ifRange = request.Headers.IfRange?.ToString();
            request.Headers.Range?.Ranges.Single().From.Should().Be(3);
            var content = new StringContent("def");
            content.Headers.ContentRange = ContentRangeHeaderValue.Parse("bytes 3-5/6");
            content.Headers.ContentLength = 3;
            return new HttpResponseMessage(HttpStatusCode.PartialContent) { Content = content };
        });

        try
        {
            using var client = new HttpClient(handler);
            var downloader = new HttpFileDownloader(client);
            await using var stream = await downloader.DownloadAsync(
                "https://example.com/file", new DownloadOptions { MaxRetries = 0 },
                progress: null, partialFilePath: partialPath);
            using var reader = new StreamReader(stream);

            (await reader.ReadToEndAsync()).Should().Be("abcdef");
            ifRange.Should().Be("\"v1\"");
            File.Exists(partialPath + ".meta").Should().BeFalse();
        }
        finally
        {
            Directory.Delete(directory, true);
        }
    }

    [Fact]
    public void IsValidContentRange_AcceptsMatchingRange()
    {
        using var response = Response("bytes 3-5/6", contentLength: 3);

        HttpFileDownloader.IsValidContentRange(response, 3).Should().BeTrue();
    }

    [Theory]
    [InlineData("bytes 2-5/6", 3, 4)]
    [InlineData("bytes 3-5/6", 3, 2)]
    [InlineData("items 3-5/6", 3, 3)]
    public void IsValidContentRange_RejectsInconsistentRange(
        string contentRange, long existingLength, long contentLength)
    {
        using var response = Response(contentRange, contentLength);

        HttpFileDownloader.IsValidContentRange(response, existingLength).Should().BeFalse();
    }

    private static HttpResponseMessage Response(string contentRange, long contentLength)
    {
        var content = new ByteArrayContent(new byte[contentLength]);
        content.Headers.ContentRange = ContentRangeHeaderValue.Parse(contentRange);
        content.Headers.ContentLength = contentLength;
        return new HttpResponseMessage(HttpStatusCode.PartialContent) { Content = content };
    }
}
