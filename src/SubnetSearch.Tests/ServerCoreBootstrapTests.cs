using FluentAssertions;
using SubnetSearch.Classification;

namespace SubnetSearch.Tests;

public class ServerCoreBootstrapTests
{
    private static AsnNetworkProfile Prof(string? role, long reach) => new(role, reach);

    [Theory]
    [InlineData("tier1_transit", 0,    false, false)] // карьер
    [InlineData("major_transit", 0,    false, false)]
    [InlineData("midsize_transit", 0,  false, false)]
    [InlineData("stub",           0,   false, true)]   // не транзит → проходит
    [InlineData("content_network", 0,  false, true)]
    [InlineData("access_provider", 0,  false, true)]
    public void PassesPrune_ByRole(string role, long reach, bool excluded, bool expected)
        => ServerCoreBootstrap.PassesPrune(Prof(role, reach), excluded).Should().Be(expected);

    [Fact]
    public void PassesPrune_NullRole_UsesReach()
    {
        ServerCoreBootstrap.PassesPrune(Prof(null, 5), false).Should().BeTrue();     // мелкий
        ServerCoreBootstrap.PassesPrune(Prof(null, 5000), false).Should().BeFalse(); // большой reach → карьер
        ServerCoreBootstrap.PassesPrune(null, false).Should().BeTrue();              // нет профиля → benefit of doubt
    }

    [Fact]
    public void PassesPrune_Excluded_AlwaysFalse()
        => ServerCoreBootstrap.PassesPrune(Prof("stub", 0), excluded: true).Should().BeFalse();

    [Fact]
    public void Build_BaseFromVpsh_PrunesCarriers_TypesVpsDedicated()
    {
        var vpsh = new Dictionary<uint, string>
        {
            [100] = "Small Host LLC",          // stub → проходит
            [200] = "\"Big Carrier\"",         // major_transit → прополка
            [300] = "No Profile Host",         // нет профиля → проходит
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
            new(100, "AWS", new[] { "cloud" }),              // замена типов
            new(200, "Removed", Array.Empty<string>()),      // удаление
            new(999, "Carrier-Grade Host", new[] { "vps" }), // add, минуя прополку
        };

        var core = ServerCoreBootstrap.Build(vpsh, profiles, new HashSet<uint>(), overlay);

        core.First(e => e.Asn == 100).Types.Should().BeEquivalentTo(new[] { "cloud" });
        core.Should().NotContain(e => e.Asn == 200);        // удалён оверлеем
        core.First(e => e.Asn == 999).Types.Should().BeEquivalentTo(new[] { "vps" });
    }
}
