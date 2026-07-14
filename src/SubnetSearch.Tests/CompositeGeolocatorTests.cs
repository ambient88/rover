using FluentAssertions;
using SubnetSearch.Classification;
using SubnetSearch.Core.Interfaces.Classification;
using SubnetSearch.Core.Models.Classification;

namespace SubnetSearch.Tests;

// CompositeGeolocator uses the fallback source to fill fields missing from the primary result.
public class CompositeGeolocatorTests
{
    private sealed class StubGeo : IGeolocator
    {
        private readonly GeoLocation? _result;
        public bool Called { get; private set; }
        public bool Disposed { get; private set; }
        public StubGeo(GeoLocation? result) => _result = result;

        public GeoLocation? Locate(string ip) { Called = true; return _result; }
        public Task<GeoLocation?> LocateAsync(string ip, CancellationToken ct = default)
        { Called = true; return Task.FromResult(_result); }
        public void Dispose() => Disposed = true;
    }

    [Fact]
    public void Dispose_DisposesBothSources()
    {
        var primary  = new StubGeo(null);
        var fallback = new StubGeo(null);

        new CompositeGeolocator(primary, fallback).Dispose();

        primary.Disposed.Should().BeTrue();
        fallback.Disposed.Should().BeTrue();
    }

    [Fact]
    public async Task LocateAsync_PrimaryComplete_SkipsFallback()
    {
        var primary  = new StubGeo(new GeoLocation("Berlin", "BE", 52.5, 13.4));
        var fallback = new StubGeo(new GeoLocation("X", null, null, null));
        var composite = new CompositeGeolocator(primary, fallback);

        var result = await composite.LocateAsync("1.2.3.4");

        result!.City.Should().Be("Berlin");
        fallback.Called.Should().BeFalse("primary дал полный результат");
    }

    [Fact]
    public async Task LocateAsync_PrimaryHasCoordsOnly_IsComplete()
    {
        var primary  = new StubGeo(new GeoLocation(null, null, 10.0, 20.0));
        var fallback = new StubGeo(new GeoLocation("FallbackCity", null, null, null));
        var composite = new CompositeGeolocator(primary, fallback);

        var result = await composite.LocateAsync("1.2.3.4");

        result!.Latitude.Should().Be(10.0);
        fallback.Called.Should().BeFalse();
    }

    [Fact]
    public async Task LocateAsync_PrimaryIncomplete_MergesFallback()
    {
        // A country-only primary result receives city and coordinate data from the fallback.
        var primary  = new StubGeo(new GeoLocation(null, null, null, null, Country: "DE"));
        var fallback = new StubGeo(new GeoLocation("Munich", "BY", 48.1, 11.6, Country: "XX"));
        var composite = new CompositeGeolocator(primary, fallback);

        var result = await composite.LocateAsync("1.2.3.4");

        fallback.Called.Should().BeTrue();
        result!.City.Should().Be("Munich");
        result.Latitude.Should().Be(48.1);
        result.Country.Should().Be("DE", "поля primary имеют приоритет при слиянии");
    }

    [Fact]
    public async Task LocateAsync_PrimaryNull_ReturnsFallback()
    {
        var composite = new CompositeGeolocator(
            new StubGeo(null), new StubGeo(new GeoLocation("Paris", null, 48.8, 2.3)));

        (await composite.LocateAsync("1.2.3.4"))!.City.Should().Be("Paris");
    }

    [Fact]
    public async Task LocateAsync_BothNull_ReturnsNull()
    {
        var composite = new CompositeGeolocator(new StubGeo(null), new StubGeo(null));

        (await composite.LocateAsync("1.2.3.4")).Should().BeNull();
    }

    [Fact]
    public void Locate_DelegatesToPrimary()
    {
        var primary  = new StubGeo(new GeoLocation("Rome", null, null, null));
        var fallback = new StubGeo(null);
        var composite = new CompositeGeolocator(primary, fallback);

        composite.Locate("1.2.3.4")!.City.Should().Be("Rome");
        fallback.Called.Should().BeFalse("синхронный Locate использует только primary");
    }
}
