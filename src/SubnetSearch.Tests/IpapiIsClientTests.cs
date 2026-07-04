using FluentAssertions;
using SubnetSearch.Network.Reputation;

namespace SubnetSearch.Tests;

// Parsing tests for the api.ipapi.is response shapes.
// ASN queries (?q=AS123) return the ASN fields at the ROOT of the document ("asn" is a number).
// IP queries  (?q=1.2.3.4) return them nested under an "asn" OBJECT.
// abuser_score is a string like "0.0013 (Low)" — the numeric prefix must be extracted.
public class IpapiIsClientTests
{
    [Fact]
    public void Parse_AsnQueryShape_ReadsTypeAndScoreFromRoot()
    {
        const string json = """
        {
          "asn": 57976,
          "abuser_score": "0.0013 (Low)",
          "descr": "BLIZZARD - Blizzard Entertainment, Inc, US",
          "org": "Blizzard Entertainment, Inc",
          "type": "business",
          "rir": "RIPE"
        }
        """;

        var info = IpapiIsClient.ParseAsnInfo(json);

        info.Type.Should().Be("business");
        info.AbuserScore.Should().BeApproximately(0.0013, 0.00001);
    }

    [Fact]
    public void Parse_IpQueryShape_ReadsTypeAndScoreFromNestedAsnObject()
    {
        const string json = """
        {
          "ip": "1.1.1.1",
          "is_datacenter": false,
          "company": { "name": "APNIC", "abuser_score": "0.0234 (Elevated)", "type": "business" },
          "asn": {
            "asn": 13335,
            "abuser_score": "0.0153 (Elevated)",
            "org": "Cloudflare, Inc.",
            "type": "hosting"
          }
        }
        """;

        var info = IpapiIsClient.ParseAsnInfo(json);

        info.Type.Should().Be("hosting");
        info.AbuserScore.Should().BeApproximately(0.0153, 0.00001);
    }

    [Fact]
    public void Parse_NumericAbuserScore_StillParsed()
    {
        const string json = """{ "asn": 24940, "type": "hosting", "abuser_score": 0.05 }""";

        var info = IpapiIsClient.ParseAsnInfo(json);

        info.Type.Should().Be("hosting");
        info.AbuserScore.Should().BeApproximately(0.05, 0.00001);
    }

    [Fact]
    public void Parse_NoAsnData_ReturnsNulls()
    {
        const string json = """{ "error": "no results" }""";

        var info = IpapiIsClient.ParseAsnInfo(json);

        info.Type.Should().BeNull();
        info.AbuserScore.Should().BeNull();
    }

    [Fact]
    public void Parse_MissingTypeAndScore_ReturnsNulls()
    {
        const string json = """{ "asn": 12345, "org": "Somebody" }""";

        var info = IpapiIsClient.ParseAsnInfo(json);

        info.Type.Should().BeNull();
        info.AbuserScore.Should().BeNull();
    }
}
