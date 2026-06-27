using System.Net.Http.Json;
using System.Text.Json.Serialization;
using SubnetSearch.Core.Extensions;
using SubnetSearch.Core.Models.Classification;

namespace SubnetSearch.Classification;

public class PeeringDbWebsiteResolver
{
    private readonly HttpClient _httpClient;

    public PeeringDbWebsiteResolver(HttpClient httpClient)
    {
        _httpClient = httpClient;
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
            
            using var response = await _httpClient.GetAsync(
                "https://www.peeringdb.com/api/net?limit=1",
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
            var response = await _httpClient.GetFromJsonAsync<PeeringDbResponse>(url, cancellationToken);
            if (response?.Data is { Length: > 0 })
            {
                var net = response.Data[0];
                return new PeeringDbNetworkInfo(net.Website, net.InfoType, net.IxCount, net.Id);
            }
        }
        catch { }
        return null;
    }

    public async Task<IReadOnlyList<string>?> GetIxLocationsAsync(int netId, CancellationToken cancellationToken = default)
    {
        try
        {
            var url = $"https://www.peeringdb.com/api/netixlan?net_id={netId}&status=ok";
            var response = await _httpClient.GetFromJsonAsync<IxlanResponse>(url, cancellationToken);
            if (response?.Data is { Length: > 0 })
                return response.Data
                    .Select(x => x.Name)
                    .Where(n => !string.IsNullOrWhiteSpace(n))
                    .Distinct()
                    .OrderBy(n => n)
                    .ToList()!;
        }
        catch { }
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