using FluentAssertions;
using SubnetSearch.Classification;

namespace SubnetSearch.Tests;

public class ServerCoreBootstrapTests
{
    private static AsnNetworkProfile Prof(string? role, long reach) => new(role, reach);

    [Theory]
    [InlineData("tier1_transit", 0,    false, false)] // Carrier network.
    [InlineData("major_transit", 0,    false, false)]
    [InlineData("midsize_transit", 0,  false, false)]
    [InlineData("stub",           0,   false, true)]   // Non-transit networks pass.
    [InlineData("content_network", 0,  false, true)]
    [InlineData("access_provider", 0,  false, true)]
    public void PassesPrune_ByRole(string role, long reach, bool excluded, bool expected)
        => ServerCoreBootstrap.PassesPrune(Prof(role, reach), excluded).Should().Be(expected);

    [Fact]
    public void PassesPrune_NullRole_UsesReach()
    {
        ServerCoreBootstrap.PassesPrune(Prof(null, 5), false).Should().BeTrue();     // Small network.
        ServerCoreBootstrap.PassesPrune(Prof(null, 5000), false).Should().BeFalse(); // High reach indicates a carrier.
        ServerCoreBootstrap.PassesPrune(null, false).Should().BeTrue();              // Keep entries without a profile.
    }

    [Fact]
    public void PassesPrune_Excluded_AlwaysFalse()
        => ServerCoreBootstrap.PassesPrune(Prof("stub", 0), excluded: true).Should().BeFalse();

    [Fact]
    public void Build_BaseFromVpsh_PrunesCarriers_TypesVpsDedicated()
    {
        var vpsh = new Dictionary<uint, string>
        {
            [100] = "Small Host LLC",          // Stub networks pass.
            [200] = "\"Big Carrier\"",         // major_transit networks are removed.
            [300] = "No Profile Host",         // Entries without a profile pass.
        };
        var profiles = new Dictionary<uint, AsnNetworkProfile>
        {
            [100] = Prof("stub", 3),
            [200] = Prof("major_transit", 40000),
        };
        var excluded = new HashSet<uint>();

        var core = ServerCoreBootstrap.Build(vpsh, profiles, excluded, overlay: []);

        core.Select(e => e.Asn).Should().BeEquivalentTo(new uint[] { 100, 300 });
        var e100 = core.First(e => e.Asn == 100);
        e100.Name.Should().Be("Small Host LLC");
        e100.Types.Should().BeEquivalentTo(new[] { "vps", "dedicated" });
        core.First(e => e.Asn == 300).Name.Should().Be("No Profile Host");
    }

    [Fact]
    public void Build_Overlay_ReplacesRemovesAdds_AndBypassesPrune()
    {
        var vpsh = new Dictionary<uint, string> { [100] = "Host-A", [200] = "Host-B" };
        var profiles = new Dictionary<uint, AsnNetworkProfile>
        {
            [100] = Prof("stub", 1),
            [200] = Prof("stub", 1),
        };
        var overlay = new List<CoreEntry>
        {
            new(100, "AWS", new[] { "cloud" }),              // Replace the type set.
            new(200, "Removed", Array.Empty<string>()),      // removal
            new(999, "Carrier-Grade Host", new[] { "vps" }), // Add a curated entry after pruning.
        };

        var core = ServerCoreBootstrap.Build(vpsh, profiles, new HashSet<uint>(), overlay);

        core.First(e => e.Asn == 100).Types.Should().BeEquivalentTo(new[] { "cloud" });
        core.Should().NotContain(e => e.Asn == 200);        // The overlay removes this entry.
        core.First(e => e.Asn == 999).Types.Should().BeEquivalentTo(new[] { "vps" });
    }
}
