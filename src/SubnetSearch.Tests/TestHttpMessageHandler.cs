using System.Net;

namespace SubnetSearch.Tests;

// Мок HttpMessageHandler для офлайн-тестирования HTTP-клиентов: канонические ответы,
// коды статуса, исключения и запись отправленных запросов — без реальной сети.
internal sealed class TestHttpMessageHandler : HttpMessageHandler
{
    private readonly Func<HttpRequestMessage, HttpResponseMessage> _responder;

    public List<HttpRequestMessage> Requests { get; } = new();

    private TestHttpMessageHandler(Func<HttpRequestMessage, HttpResponseMessage> responder)
        => _responder = responder;

    // Один и тот же ответ на любой запрос.
    public static TestHttpMessageHandler Always(HttpStatusCode status, string body)
        => new(_ => new HttpResponseMessage(status)
        {
            Content = new StringContent(body, System.Text.Encoding.UTF8, "application/json")
        });

    // Ответ зависит от URL запроса (ключ — подстрока абсолютного URI).
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

    // Бросает заданное исключение (симуляция таймаута/обрыва соединения).
    public static TestHttpMessageHandler Throws(Exception ex)
        => new(_ => throw ex);

    // Произвольная логика ответа.
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
