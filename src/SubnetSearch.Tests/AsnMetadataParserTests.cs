using FluentAssertions;
using SubnetSearch.Classification;

namespace SubnetSearch.Tests;

public class AsnMetadataParserTests
{
    private static async Task<string> WriteTempAsJson(string body)
    {
        var path = Path.Combine(Path.GetTempPath(), $"asjson-{Guid.NewGuid():N}.json");
        await File.WriteAllTextAsync(path, body);
        return path;
    }

    [Fact]
    public async Task LoadNetworkProfilesAsync_ExtractsRoleAndReach()
    {
        var path = await WriteTempAsJson("""
        [
          {"asn":31027,"metadata":{"category":"hosting","networkRole":"major_transit"},
           "stats":{"connectivity":{"reach":41729}}},
          {"asn":215439,"metadata":{"category":"business","networkRole":"access_provider"},
           "stats":{"connectivity":{"reach":3}}},
          {"asn":999,"metadata":{"category":"hosting","networkRole":null},"stats":null}
        ]
        """);
        try
        {
            var map = await new AsnMetadataParser().LoadNetworkProfilesAsync(path);
            map[31027].NetworkRole.Should().Be("major_transit");
            map[31027].Reach.Should().Be(41729);
            map[215439].NetworkRole.Should().Be("access_provider");
            map[999].NetworkRole.Should().BeNull();
            map[999].Reach.Should().Be(0, "нет stats → reach=0");
        }
        finally { File.Delete(path); }
    }
}
