using System.Net;

namespace SubnetSearch.Tests;

// HttpMessageHandler test double for responses, status codes, exceptions, and request capture without network access.
internal sealed class TestHttpMessageHandler : HttpMessageHandler
{
    private readonly Func<HttpRequestMessage, HttpResponseMessage> _responder;

    public List<HttpRequestMessage> Requests { get; } = new();

    private TestHttpMessageHandler(Func<HttpRequestMessage, HttpResponseMessage> responder)
        => _responder = responder;

    // Return the same response for every request.
    public static TestHttpMessageHandler Always(HttpStatusCode status, string body)
        => new(_ => new HttpResponseMessage(status)
        {
            Content = new StringContent(body, System.Text.Encoding.UTF8, "application/json")
        });

    // Select a response by matching a substring of the absolute request URI.
    public static TestHttpMessageHandler ByUrl(
        IReadOnlyDictionary<string, (HttpStatusCode Status, string Body)> map,
        HttpStatusCode fallback = HttpStatusCode.NotFound)
        => new(req =>
        {
            var url = req.RequestUri!.AbsoluteUri;
            foreach (var kv in map)
                if (url.Contains(kv.Key, StringComparison.OrdinalIgnoreCase))
                    return new HttpResponseMessage(kv.Value.Status)
                    {
                        Content = new StringContent(kv.Value.Body, System.Text.Encoding.UTF8, "application/json")
                    };
            return new HttpResponseMessage(fallback) { Content = new StringContent("") };
        });

    // Throw the supplied exception to simulate a timeout or connection failure.
    public static TestHttpMessageHandler Throws(Exception ex)
        => new(_ => throw ex);

    // Use custom response logic.
    public static TestHttpMessageHandler Custom(Func<HttpRequestMessage, HttpResponseMessage> responder)
        => new(responder);

    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Requests.Add(request);
        return Task.FromResult(_responder(request));
    }
}
