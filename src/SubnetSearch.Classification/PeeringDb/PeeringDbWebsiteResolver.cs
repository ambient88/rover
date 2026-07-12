using System.Net.Http.Json;
using System.Text.Json.Serialization;
using SubnetSearch.Core.Extensions;
using SubnetSearch.Core.Models.Classification;

namespace SubnetSearch.Classification;

public class PeeringDbWebsiteResolver
{
    private readonly HttpClient _httpClient;
    private readonly string? _apiKey;

    public PeeringDbWebsiteResolver(HttpClient httpClient, string? apiKey = null)
    {
        _httpClient = httpClient;
        // Sanitize once via the shared helper: strips CR/LF/null and normalizes an
        // empty-after-strip key (e.g. "\0"-only) to null so it is never attached as an
        // empty Api-Key credential (WR-01/WR-02).
        _apiKey = PeeringDbAuth.Sanitize(apiKey);
    }

    /// <summary>
    /// Builds a GET request and attaches the per-request Api-Key Authorization only when a key is configured.
    /// The secret lives on the individual request, never on the shared client's DefaultRequestHeaders.
    /// </summary>
    private HttpRequestMessage BuildRequest(string url)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, url);
        if (_apiKey != null)
            req.Headers.Authorization =
                new System.Net.Http.Headers.AuthenticationHeaderValue("Api-Key", _apiKey);
        return req;
    }

    /// <summary>
    /// Checks whether the PeeringDB API is reachable (returns true when the server responds with a success code).
    /// </summary>
    public async Task<PeeringDbStatus> IsAvailableAsync(CancellationToken cancellationToken = default)
    {
        var start = DateTime.UtcNow;

        try
        {
            // Diagnostic request timeout — 10 seconds.
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cts.Token, cancellationToken);
            
            using var req = BuildRequest("https://www.peeringdb.com/api/net?limit=1");
            using var response = await _httpClient.SendAsync(
                req,
                HttpCompletionOption.ResponseHeadersRead,
                linked.Token);

            var elapsed = DateTime.UtcNow - start;

            if (response.IsSuccessStatusCode)
                return new PeeringDbStatus(true, (int)response.StatusCode, null, elapsed);

            // Server returned an error status.
            var body = await response.Content.ReadAsStringAsync();
            var error = string.IsNullOrWhiteSpace(body)
                ? response.ReasonPhrase
                : body.Truncate(200);

            return new PeeringDbStatus(false, (int)response.StatusCode, error, elapsed);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            var elapsed = DateTime.UtcNow - start;
            return new PeeringDbStatus(false, null, "Request timed out (exceeded 10 seconds)", elapsed);
        }
        catch (HttpRequestException ex)
        {
            var elapsed = DateTime.UtcNow - start;
            return new PeeringDbStatus(false, null, $"Network error: {ex.Message}", elapsed);
        }
        catch (Exception ex)
        {
            var elapsed = DateTime.UtcNow - start;
            return new PeeringDbStatus(false, null, $"Unknown error: {ex.Message}", elapsed);
        }
    }

    public async Task<PeeringDbNetworkInfo?> GetNetworkInfoAsync(uint asn, CancellationToken cancellationToken = default)
    {
        try
        {
            var url = $"https://www.peeringdb.com/api/net?asn={asn}";
            using var req = BuildRequest(url);
            using var resp = await _httpClient.SendAsync(req, cancellationToken);
            var response = await resp.Content.ReadFromJsonAsync<PeeringDbResponse>(cancellationToken);
            if (response?.Data is { Length: > 0 })
            {
                var net = response.Data[0];
                return new PeeringDbNetworkInfo(net.Website, net.InfoType, net.IxCount, net.Id);
            }
        }
        // Propagate cooperative cancellation (Ctrl+C); enrichment is optional so only
        // network/JSON failures are swallowed and treated as "no data" (WR-03).
        catch (OperationCanceledException) { throw; }
        catch (HttpRequestException) { }
        catch (System.Text.Json.JsonException) { }
        return null;
    }

    public async Task<IReadOnlyList<string>?> GetIxLocationsAsync(int netId, CancellationToken cancellationToken = default)
    {
        try
        {
            var url = $"https://www.peeringdb.com/api/netixlan?net_id={netId}&status=ok";
            using var req = BuildRequest(url);
            using var resp = await _httpClient.SendAsync(req, cancellationToken);
            var response = await resp.Content.ReadFromJsonAsync<IxlanResponse>(cancellationToken);
            if (response?.Data is { Length: > 0 })
                return response.Data
                    .Select(x => x.Name)
                    .Where(n => !string.IsNullOrWhiteSpace(n))
                    .Distinct()
                    .OrderBy(n => n)
                    .ToList()!;
        }
        // Propagate cooperative cancellation (Ctrl+C); enrichment is optional so only
        // network/JSON failures are swallowed and treated as "no data" (WR-03).
        catch (OperationCanceledException) { throw; }
        catch (HttpRequestException) { }
        catch (System.Text.Json.JsonException) { }
        return null;
    }

    private record PeeringDbResponse(
        [property: JsonPropertyName("data")] NetRecord[] Data);

    private record NetRecord(
        [property: JsonPropertyName("id")]       int?    Id,
        [property: JsonPropertyName("website")]  string? Website,
        [property: JsonPropertyName("info_type")] string? InfoType,
        [property: JsonPropertyName("ix_count")] int?    IxCount);

    private record IxlanResponse(
        [property: JsonPropertyName("data")] IxlanRecord[] Data);

    private record IxlanRecord(
        [property: JsonPropertyName("name")] string? Name);

    /// <summary>
    /// Result of a PeeringDB API availability check.
    /// </summary>
    public record PeeringDbStatus(bool IsAvailable, int? HttpStatusCode, string? ErrorMessage, TimeSpan Elapsed);
}