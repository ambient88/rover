using System.Net;
using System.Net.Sockets;

namespace SubnetSearch.Core.Utilities;

/// <summary>
/// Triage for a single batch-input line (file list / stdin): is it an IPv4 address, a domain,
/// an unsupported IPv6 address, or unrecognized? The classification pipeline is IPv4-only, so an
/// IPv6 address must be filtered out at input time — otherwise it reaches the hosting classifier,
/// faults its task, and aborts the whole batch (F18).
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
