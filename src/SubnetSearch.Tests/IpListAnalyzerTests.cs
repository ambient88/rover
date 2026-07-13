using System.Net;
using FluentAssertions;
using SubnetSearch.Network.Recommend;

namespace SubnetSearch.Tests;

// Двухмаршрутная загрузка --from (диагностика 2026-07-08): основной клиент bypass-VPN
// (привязан к физическому интерфейсу) упирается в блокировку хоста провайдером
// (raw.githubusercontent.com — SYN blackhole → «The SSL connection could not be
// established»); фолбэк идёт системным маршрутом (VPN, если активен).
public class IpListAnalyzerTests
{
    private sealed class ChunkedReader(string text, int chunkSize) : TextReader
    {
        private int _position;

        public override ValueTask<int> ReadAsync(
            Memory<char> buffer,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (_position >= text.Length) return ValueTask.FromResult(0);
            int count = Math.Min(Math.Min(chunkSize, buffer.Length), text.Length - _position);
            text.AsMemory(_position, count).CopyTo(buffer);
            _position += count;
            return ValueTask.FromResult(count);
        }
    }

    // Стаб-обработчик: отдаёт заготовленный ответ либо бросает сетевую ошибку.
    private sealed class StubHandler(Func<HttpRequestMessage, HttpResponseMessage> respond)
        : HttpMessageHandler
    {
        public int Calls;
        public string? LastUrl;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken ct)
        {
            Interlocked.Increment(ref Calls);
            LastUrl = request.RequestUri?.ToString();
            return Task.FromResult(respond(request));
        }
    }

    private static (HttpClient Client, StubHandler Handler) OkClient(string body)
    {
        var h = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
            { Content = new StringContent(body) });
        return (new HttpClient(h), h);
    }

    private static (HttpClient Client, StubHandler Handler) FailingClient()
    {
        var h = new StubHandler(_ =>
            throw new HttpRequestException("The SSL connection could not be established"));
        return (new HttpClient(h), h);
    }

    [Fact]
    public async Task ReadSourceAsync_PrimarySuccess_DoesNotTouchFallback()
    {
        var (primary, ph)   = OkClient("1.2.3.4");
        var (fallback, fh)  = OkClient("не должен использоваться");

        var text = await IpListAnalyzer.ReadSourceAsync(
            "https://example.com/list.txt", primary, fallbackHttp: fallback);

        text.Should().Be("1.2.3.4");
        ph.Calls.Should().Be(1);
        fh.Calls.Should().Be(0, "при успехе основного маршрута фолбэк не трогается");
    }

    [Fact]
    public async Task ReadSourceAsync_PrimaryNetworkFailure_FallsBackToSystemRoute()
    {
        var (primary, ph)  = FailingClient();
        var (fallback, fh) = OkClient("5.6.7.8");

        var text = await IpListAnalyzer.ReadSourceAsync(
            "https://example.com/list.txt", primary, fallbackHttp: fallback);

        text.Should().Be("5.6.7.8");
        ph.Calls.Should().Be(1);
        fh.Calls.Should().Be(1, "сетевой сбой основного маршрута → вторая попытка фолбэком");
    }

    [Fact]
    public async Task ReadSourceAsync_BothRoutesFail_PropagatesError()
    {
        var (primary, _)  = FailingClient();
        var (fallback, _) = FailingClient();

        var act = () => IpListAnalyzer.ReadSourceAsync(
            "https://example.com/list.txt", primary, fallbackHttp: fallback);

        await act.Should().ThrowAsync<HttpRequestException>();
    }

    [Fact]
    public async Task ReadSourceAsync_NoFallback_PropagatesPrimaryError()
    {
        // Обратная совместимость: без fallbackHttp поведение прежнее — одна попытка.
        var (primary, ph) = FailingClient();

        var act = () => IpListAnalyzer.ReadSourceAsync(
            "https://example.com/list.txt", primary);

        await act.Should().ThrowAsync<HttpRequestException>();
        ph.Calls.Should().Be(1);
    }

    [Fact]
    public async Task ReadSourceAsync_UserCancellation_DoesNotRetryViaFallback()
    {
        // Ctrl+C — не сетевой сбой: отмена пробрасывается, фолбэк не пробуется.
        var (primary, _)   = FailingClient();
        var (fallback, fh) = OkClient("не должен использоваться");
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var act = () => IpListAnalyzer.ReadSourceAsync(
            "https://example.com/list.txt", primary, cts.Token, fallbackHttp: fallback);

        await act.Should().ThrowAsync<OperationCanceledException>();
        fh.Calls.Should().Be(0);
    }

    [Fact]
    public async Task ReadSourceAsync_DirectIpUrl_BlockedBeforeAnyRequest()
    {
        // SSRF-защита срабатывает до сети — ни один маршрут не дёргается.
        var (primary, ph)  = OkClient("x");
        var (fallback, fh) = OkClient("x");

        var act = () => IpListAnalyzer.ReadSourceAsync(
            "https://169.254.169.254/latest/meta-data", primary, fallbackHttp: fallback);

        await act.Should().ThrowAsync<ArgumentException>();
        ph.Calls.Should().Be(0);
        fh.Calls.Should().Be(0);
    }

    [Fact]
    public async Task ReadSourceAsync_FallbackBlocksHostnameResolvingToPrivateAddress()
    {
        var (primary, _) = FailingClient();
        var (fallback, fallbackHandler) = OkClient("1.2.3.4");

        var action = () => IpListAnalyzer.ReadSourceAsync(
            "https://localhost/list.txt", primary, fallbackHttp: fallback);

        await action.Should().ThrowAsync<ArgumentException>();
        fallbackHandler.Calls.Should().Be(0);
    }

    [Fact]
    public async Task ExtractIpsAsync_HandlesAddressesAcrossReadBoundaries()
    {
        using var reader = new ChunkedReader(
            "prefix 1.2.3.4\n5.6.7.8 suffix\n1.2.3.4", chunkSize: 3);

        var result = await IpListAnalyzer.ExtractIpsAsync(reader);

        result.Should().Equal("1.2.3.4", "5.6.7.8");
    }

    [Fact]
    public async Task ReadSourceAsync_GitHubBlobUrl_RewrittenForBothRoutes()
    {
        // Переписанный raw-URL используется и фолбэком — не исходный blob-URL.
        var (primary, _)   = FailingClient();
        var (fallback, fh) = OkClient("9.9.9.9");

        await IpListAnalyzer.ReadSourceAsync(
            "https://github.com/user/repo/blob/main/ips.txt", primary, fallbackHttp: fallback);

        fh.LastUrl.Should().Be("https://raw.githubusercontent.com/user/repo/main/ips.txt");
    }

    [Fact]
    public async Task ReadSourceAsync_SupportsResponseLargerThanEightMiB()
    {
        string body = new('x', 8 * 1024 * 1024 + 1);
        var (client, _) = OkClient(body);

        string result = await IpListAnalyzer.ReadSourceAsync(
            "https://example.com/list.txt", client);

        result.Length.Should().Be(body.Length);
    }

    [Fact]
    public void ExtractIps_SupportsMoreThanOneHundredThousandAddresses()
    {
        string text = string.Join('\n', Enumerable.Range(0, 100_001)
            .Select(i => $"10.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}"));

        var result = IpListAnalyzer.ExtractIps(text);

        result.Should().HaveCount(100_001);
    }

    [Theory]
    [InlineData("127.0.0.1", false)]
    [InlineData("169.254.169.254", false)]
    [InlineData("10.0.0.1", false)]
    [InlineData("::1", false)]
    [InlineData("fc00::1", false)]
    [InlineData("93.184.216.34", true)]
    [InlineData("2606:4700:4700::1111", true)]
    public void IsPublicAddress_ClassifiesNetworkBoundary(string value, bool expected)
        => IpListAnalyzer.IsPublicAddress(IPAddress.Parse(value)).Should().Be(expected);

    [Theory]
    [InlineData("https://github.com/user/repo/blob/main/ips.txt",
                "https://raw.githubusercontent.com/user/repo/main/ips.txt")]
    [InlineData("https://raw.githubusercontent.com/user/repo/main/ips.txt",
                "https://raw.githubusercontent.com/user/repo/main/ips.txt")]
    [InlineData("https://example.com/list.txt", "https://example.com/list.txt")]
    public void RewriteGitHubUrl_RewritesOnlyBlobUrls(string input, string expected)
        => IpListAnalyzer.RewriteGitHubUrl(input).Should().Be(expected);
}
