using SubnetSearch.Core.Models.Classification;

namespace SubnetSearch.Core.Interfaces.Classification;

public interface IGeolocator : IDisposable
{
    GeoLocation? Locate(string ipAddress);

    Task<GeoLocation?> LocateAsync(string ipAddress, CancellationToken ct = default)
        => Task.FromResult(Locate(ipAddress));
}
