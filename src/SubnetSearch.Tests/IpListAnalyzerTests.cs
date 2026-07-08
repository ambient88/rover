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

        var act = () => IpListAnalyzer.ReadSourceAsync("https://example.com/list.txt", primary);

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
    public async Task ReadSourceAsync_GitHubBlobUrl_RewrittenForBothRoutes()
    {
        // Переписанный raw-URL используется и фолбэком — не исходный blob-URL.
        var (primary, _)   = FailingClient();
        var (fallback, fh) = OkClient("9.9.9.9");

        await IpListAnalyzer.ReadSourceAsync(
            "https://github.com/user/repo/blob/main/ips.txt", primary, fallbackHttp: fallback);

        fh.LastUrl.Should().Be("https://raw.githubusercontent.com/user/repo/main/ips.txt");
    }

    [Theory]
    [InlineData("https://github.com/user/repo/blob/main/ips.txt",
                "https://raw.githubusercontent.com/user/repo/main/ips.txt")]
    [InlineData("https://raw.githubusercontent.com/user/repo/main/ips.txt",
                "https://raw.githubusercontent.com/user/repo/main/ips.txt")]
    [InlineData("https://example.com/list.txt", "https://example.com/list.txt")]
    public void RewriteGitHubUrl_RewritesOnlyBlobUrls(string input, string expected)
        => IpListAnalyzer.RewriteGitHubUrl(input).Should().Be(expected);
}
