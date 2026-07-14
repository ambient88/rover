using DnsClient;
using DnsClient.Protocol;
using SubnetSearch.Core.Interfaces.Classification;
using System.Net;

namespace SubnetSearch.Classification;

// Thin adapter for live System.Net.Dns lookups. This requires integration testing.
[System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
public class DnsResolver : IDnsResolver
{
    // LookupClient is thread-safe; one instance for the whole process.
    private static readonly LookupClient Client = new();

    public async Task<IReadOnlyList<IPAddress>> ResolveAllIpAsync(string domain, CancellationToken cancellationToken = default)
    {
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        budget.CancelAfter(TimeSpan.FromSeconds(2));
        try
        {
            var result = await Client.QueryAsync(domain, QueryType.A, QueryClass.IN, budget.Token);
            return result.Answers.OfType<ARecord>().Select(a => a.Address).ToList();
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (OperationCanceledException) { return Array.Empty<IPAddress>(); }
        catch
        {
            try
            {
                var addresses = await System.Net.Dns.GetHostAddressesAsync(domain, budget.Token);
                return addresses
                    .Where(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    .ToList();
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (OperationCanceledException) { return Array.Empty<IPAddress>(); }
            catch
            {
                return Array.Empty<IPAddress>();
            }
        }
    }

    public async Task<string?> ReverseDnsAsync(IPAddress ip, CancellationToken cancellationToken = default)
    {
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        budget.CancelAfter(TimeSpan.FromSeconds(2));
        try
        {
            var result = await Client.QueryReverseAsync(ip, budget.Token);
            var ptr = result.Answers.OfType<PtrRecord>().FirstOrDefault();
            return ptr?.PtrDomainName.Value;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (OperationCanceledException) { return null; }
        catch
        {
            try
            {
                var entry = await System.Net.Dns.GetHostEntryAsync(ip.ToString(), budget.Token);
                return entry.HostName;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
            catch (OperationCanceledException) { return null; }
            catch
            {
                return null;
            }
        }
    }
}
