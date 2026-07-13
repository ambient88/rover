using System.Net;
using System.Net.Sockets;

namespace SubnetSearch.Core.Utilities;

/// <summary>
/// Classifies one line before it enters the IPv4-only batch pipeline.
/// </summary>
public enum BatchInputKind
{
    Ipv4,
    Domain,
    Ipv6Unsupported,
    Unrecognized,
}

public static class BatchInputClassifier
{
    public static BatchInputKind Classify(string item)
    {
        // IP literals are checked first: Uri.CheckHostName would also report IPv4/IPv6 for them,
        // but we need the address family to reject IPv6 explicitly.
        if (IPAddress.TryParse(item, out var ip))
            return ip.AddressFamily == AddressFamily.InterNetwork
                ? BatchInputKind.Ipv4
                : BatchInputKind.Ipv6Unsupported;

        return Uri.CheckHostName(item) == UriHostNameType.Dns
            ? BatchInputKind.Domain
            : BatchInputKind.Unrecognized;
    }
}
