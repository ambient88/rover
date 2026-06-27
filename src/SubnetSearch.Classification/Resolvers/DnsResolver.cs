using DnsClient;
using DnsClient.Protocol;
using SubnetSearch.Core.Interfaces.Classification;
using System.Net;

namespace SubnetSearch.Classification;

public class DnsResolver : IDnsResolver
{
    // LookupClient потокобезопасен, один экземпляр на весь процесс.
    private static readonly LookupClient Client = new();

    public async Task<IReadOnlyList<IPAddress>> ResolveAllIpAsync(string domain, CancellationToken cancellationToken = default)
    {
        try
        {
            var result = await Client.QueryAsync(domain, QueryType.A, QueryClass.IN, cancellationToken);
            return result.Answers.OfType<ARecord>().Select(a => a.Address).ToList();
        }
        catch (OperationCanceledException) { throw; }
        catch
        {
            try
            {
                var addresses = await System.Net.Dns.GetHostAddressesAsync(domain, cancellationToken);
                return addresses
                    .Where(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    .ToList();
            }
            catch (OperationCanceledException) { throw; }
            catch
            {
                return Array.Empty<IPAddress>();
            }
        }
    }

    public async Task<string?> ReverseDnsAsync(IPAddress ip, CancellationToken cancellationToken = default)
    {
        try
        {
            var result = await Client.QueryReverseAsync(ip, cancellationToken);
            var ptr = result.Answers.OfType<PtrRecord>().FirstOrDefault();
            return ptr?.PtrDomainName.Value;
        }
        catch (OperationCanceledException) { throw; }
        catch
        {
            try
            {
                var entry = await System.Net.Dns.GetHostEntryAsync(ip.ToString(), cancellationToken);
                return entry.HostName;
            }
            catch (OperationCanceledException) { throw; }
            catch
            {
                return null;
            }
        }
    }
}
