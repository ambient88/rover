using System.Net;
using FluentAssertions;
using SubnetSearch.Network.Recommend;

namespace SubnetSearch.Tests;

// The --from loader races a physical-interface route against the system route.
// This handles hosts blocked on the direct connection while still supporting an active VPN.
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

    private sealed class DelayedContent(string text, TimeSpan delay) : HttpContent
    {
        protected override bool TryComputeLength(out long length)
        {
            length = -1;
            return false;
        }

        protected override Task SerializeToStreamAsync(
            Stream stream,
            TransportContext? context)
            => SerializeToStreamAsync(stream, context, CancellationToken.None);

        protected override async Task SerializeToStreamAsync(
            Stream stream,
            TransportContext? context,
            CancellationToken cancellationToken)
        {
            await Task.Delay(delay, cancellationToken);
            await using var writer = new StreamWriter(stream, leaveOpen: true);
            await writer.WriteAsync(text.AsMemory(), cancellationToken);
            await writer.FlushAsync(cancellationToken);
        }
    }

    // The handler returns a prepared response or throws a network error.
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
        // Without fallbackHttp, the loader keeps the original single-attempt behavior.
        var (primary, ph) = FailingClient();

        var act = () => IpListAnalyzer.ReadSourceAsync(
            "https://example.com/list.txt", primary);

        await act.Should().ThrowAsync<HttpRequestException>();
        ph.Calls.Should().Be(1);
    }

    // Hangs until the race cancels it, then fails with a NETWORK error rather than a
    // cancellation, so the losing task ends up faulted instead of canceled.
    private sealed class FaultsOnCancelHandler : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken ct)
        {
            try { await Task.Delay(TimeSpan.FromSeconds(30), ct); }
            catch (OperationCanceledException) { }
            throw new HttpRequestException("connection torn down");
        }
    }

    [Fact]
    public async Task ReadSourceAsync_PrimaryFaultsAfterFallbackWon_FaultIsObserved()
    {
        // The primary route dies after the fallback already returned: its late fault
        // must be observed (no UnobservedTaskException), and the result stays intact.
        var primary = new HttpClient(new FaultsOnCancelHandler());
        var (fallback, _) = OkClient("9.9.9.9");

        var text = await IpListAnalyzer.ReadSourceAsync(
            "https://example.com/list.txt", primary, fallbackHttp: fallback);

        text.Should().Be("9.9.9.9");
        await Task.Delay(300); // let the losing route fault and hit the observer
    }

    [Fact]
    public async Task ReadSourceAsync_CancelledMidFlight_Rethrows()
    {
        using var cts = new CancellationTokenSource();
        var h = new StubHandler(_ =>
        {
            cts.Cancel();
            throw new OperationCanceledException(cts.Token);
        });
        var (fallback, fh) = OkClient("unused");

        var act = () => IpListAnalyzer.ReadSourceAsync(
            "https://example.com/list.txt", new HttpClient(h), cts.Token, fallbackHttp: fallback);

        await act.Should().ThrowAsync<OperationCanceledException>();
    }

    [Fact]
    public async Task ReadIpsAsync_WithFallback_PrimaryWins()
    {
        var (primary, ph)  = OkClient("1.2.3.4\n5.6.7.8\n");
        var (fallback, fh) = OkClient("9.9.9.9\n");

        var ips = await IpListAnalyzer.ReadIpsAsync(
            "https://example.com/list.txt", primary, fallbackHttp: fallback);

        ips.Should().Contain(["1.2.3.4", "5.6.7.8"]);
        ph.Calls.Should().Be(1);
    }

    [Fact]
    public async Task ReadIpsAsync_PrimaryNetworkFailure_FallsBackToSystemRoute()
    {
        var (primary, _)   = FailingClient();
        var (fallback, fh) = OkClient("9.9.9.9\n");

        var ips = await IpListAnalyzer.ReadIpsAsync(
            "https://example.com/list.txt", primary, fallbackHttp: fallback);

        ips.Should().Contain("9.9.9.9");
        fh.Calls.Should().Be(1);
    }

    [Fact]
    public async Task ReadSourceAsync_FollowsRedirectIncludingRelativeLocation()
    {
        int call = 0;
        var h = new StubHandler(_ =>
        {
            call++;
            if (call == 1)
            {
                var redirect = new HttpResponseMessage(HttpStatusCode.Found);
                redirect.Headers.Location = new Uri("/moved/list.txt", UriKind.Relative);
                return redirect;
            }
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("1.2.3.4"),
            };
        });

        var text = await IpListAnalyzer.ReadSourceAsync(
            "https://example.com/list.txt", new HttpClient(h));

        text.Should().Be("1.2.3.4");
        h.LastUrl.Should().Contain("/moved/list.txt");
    }

    [Fact]
    public async Task ReadSourceAsync_EndlessRedirects_Throw()
    {
        var h = new StubHandler(_ =>
        {
            var redirect = new HttpResponseMessage(HttpStatusCode.MovedPermanently);
            redirect.Headers.Location = new Uri("https://example.com/next.txt");
            return redirect;
        });

        var act = () => IpListAnalyzer.ReadSourceAsync(
            "https://example.com/list.txt", new HttpClient(h));

        (await act.Should().ThrowAsync<HttpRequestException>())
            .WithMessage("*redirects*");
    }

    [Fact]
    public async Task ReadIpsAsync_FollowsRedirectChain()
    {
        int call = 0;
        var h = new StubHandler(_ =>
        {
            call++;
            if (call <= 2) // two hops before the real payload
            {
                var redirect = new HttpResponseMessage(HttpStatusCode.TemporaryRedirect);
                redirect.Headers.Location = new Uri($"https://example.com/hop{call}.txt");
                return redirect;
            }
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("1.2.3.4\n"),
            };
        });

        var ips = await IpListAnalyzer.ReadIpsAsync(
            "https://example.com/list.txt", new HttpClient(h));

        ips.Should().Contain("1.2.3.4");
        call.Should().Be(3);
    }

    [Fact]
    public async Task ReadIpsAsync_EndlessRedirects_Throw()
    {
        var h = new StubHandler(_ =>
        {
            var redirect = new HttpResponseMessage(HttpStatusCode.MovedPermanently);
            redirect.Headers.Location = new Uri("https://example.com/next.txt");
            return redirect;
        });

        var act = () => IpListAnalyzer.ReadIpsAsync(
            "https://example.com/list.txt", new HttpClient(h));

        (await act.Should().ThrowAsync<HttpRequestException>())
            .WithMessage("*redirects*");
    }

    // A stream whose DisposeAsync completes asynchronously, like a real network stream
    // that still has buffered data in flight when the reader lets go of it.
    private sealed class AsyncDisposingStream(byte[] payload) : MemoryStream(payload)
    {
        public override async ValueTask DisposeAsync()
        {
            await Task.Yield();
            await base.DisposeAsync();
        }
    }

    // Hands the response stream out unwrapped, so its asynchronous DisposeAsync is
    // what the reader's await-using actually awaits.
    private sealed class RawStreamContent(Stream stream) : HttpContent
    {
        protected override Task<Stream> CreateContentReadStreamAsync()
            => Task.FromResult(stream);

        protected override Task SerializeToStreamAsync(Stream target, System.Net.TransportContext? context)
            => stream.CopyToAsync(target);

        protected override bool TryComputeLength(out long length)
        {
            length = -1;
            return false;
        }
    }

    [Fact]
    public async Task ReadIpsAsync_StreamWithAsyncDisposal_IsHandled()
    {
        var h = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new RawStreamContent(new AsyncDisposingStream("1.2.3.4\n"u8.ToArray())),
        });

        var ips = await IpListAnalyzer.ReadIpsAsync(
            "https://example.com/list.txt", new HttpClient(h));

        ips.Should().Contain("1.2.3.4");
    }

    [Fact]
    public async Task ObserveFaults_ConsumesLateFaults()
    {
        // Losing routes usually end up canceled, but a genuine late fault must be
        // observed so it cannot surface as an UnobservedTaskException.
        var faulted = Task.FromException(new InvalidOperationException("late loser"));

        IpListAnalyzer.ObserveFaults([faulted]);

        await Task.Delay(50); // let the observer continuation run
        faulted.IsFaulted.Should().BeTrue();
    }

    [Fact]
    public async Task ExtractIps_OversizedNumericToken_IsDiscarded()
    {
        // A digit run longer than the 64-char token buffer must not produce an IP.
        string text = new string('1', 100) + " 1.2.3.4 ";

        var ips = await IpListAnalyzer.ExtractIpsAsync(new StringReader(text));

        ips.Should().Equal("1.2.3.4");
    }

    [Fact]
    public async Task EnsurePublicDestination_NonHttpScheme_Throws()
    {
        var act = () => IpListAnalyzer.EnsurePublicDestinationAsync(
            new Uri("ftp://mirror.example/list.txt"), CancellationToken.None);

        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task EnsurePublicDestination_LoopbackHost_Throws()
    {
        // localhost resolves without touching the network and is never a public address.
        var act = () => IpListAnalyzer.EnsurePublicDestinationAsync(
            new Uri("http://localhost/list.txt"), CancellationToken.None);

        await act.Should().ThrowAsync<ArgumentException>();
    }

    [Fact]
    public async Task ReadSourceAsync_UserCancellation_DoesNotRetryViaFallback()
    {
        // Ctrl+C propagates cancellation without trying the fallback route.
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
        // SSRF validation rejects the URL before either network route starts.
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
        // The fallback uses the rewritten raw URL instead of the original blob URL.
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
    public async Task ReadSourceAsync_HeaderTimeoutDoesNotCancelSlowResponseBody()
    {
        var handler = new StubHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new DelayedContent("1.2.3.4", TimeSpan.FromMilliseconds(3100))
        });
        using var client = new HttpClient(handler);

        string result = await IpListAnalyzer.ReadSourceAsync(
            "https://example.com/list.txt", client);

        result.Should().Be("1.2.3.4");
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
