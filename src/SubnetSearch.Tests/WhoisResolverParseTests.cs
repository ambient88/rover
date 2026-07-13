using FluentAssertions;
using SubnetSearch.Data;

namespace SubnetSearch.Tests;

public class WhoisResolverParseTests
{
    private const string ArinResponse = """
        OrgName:        Example Hosting Inc.
        Country:        US
        Updated:        2020-01-15
        website: https://example-hosting.com
        status: active
        OrgAbuseEmail:  abuse@example-hosting.com
        """;

    [Fact]
    public void Parse_Arin_ExtractsAllFields()
    {
        var r = WhoisResolver.ParseWhoisResponse("whois.arin.net", ArinResponse);

        r.Should().NotBeNull();
        r!.Organization.Should().Be("Example Hosting Inc.");
        r.Country.Should().Be("US");
        r.Rir.Should().Be("ARIN");
        r.Website.Should().Be("https://example-hosting.com/");
        r.AbuseEmail.Should().Be("abuse@example-hosting.com");
        r.Status.Should().Be("active");
        r.UpdatedDate.Should().Be(new DateTime(2020, 1, 15));
    }

    [Fact]
    public void Parse_Ripe_UsesRipeOrgFields()
    {
        const string ripe = """
            org-name:       ACME Networks BV
            country:        NL
            """;
        var r = WhoisResolver.ParseWhoisResponse("whois.ripe.net", ripe);

        r!.Organization.Should().Be("ACME Networks BV");
        r.Country.Should().Be("NL");
        r.Rir.Should().Be("RIPE");
    }

    [Fact]
    public void Parse_UnknownServer_NoOrgFieldsNoRir()
    {
        var r = WhoisResolver.ParseWhoisResponse("whois.unknown.example", "OrgName: Somebody\ncountry: DE");

        r!.Organization.Should().BeNull("for an unknown server, the set of org fields is not specified.");
        r.Rir.Should().BeNull();
        r.Country.Should().Be("DE");
    }

    [Fact]
    public void Parse_RegistryWebsite_IsIgnored()
    {
        const string resp = """
            OrgName: Some Org
            website: https://www.arin.net/resources
            """;
        var r = WhoisResolver.ParseWhoisResponse("whois.arin.net", resp);

        r!.Website.Should().BeNull("registry domains (arin.net, etc.) are filtered out.");
    }

    [Fact]
    public void Parse_Apnic_UsesDescrField_AndAbuseMailbox()
    {
        const string apnic = """
            descr:          Big Asia Hosting
            country:        SG
            abuse-mailbox:  abuse@bigasia.example
            """;
        var r = WhoisResolver.ParseWhoisResponse("whois.apnic.net", apnic);

        r!.Organization.Should().Be("Big Asia Hosting");
        r.Country.Should().Be("SG");
        r.Rir.Should().Be("APNIC");
        r.AbuseEmail.Should().Be("abuse@bigasia.example");
    }

    [Fact]
    public void Parse_Lacnic_UsesOwnerField()
    {
        const string lacnic = """
            owner:      Provedor Brasil Ltda
            country:    BR
            """;
        var r = WhoisResolver.ParseWhoisResponse("whois.lacnic.net", lacnic);

        r!.Organization.Should().Be("Provedor Brasil Ltda");
        r.Rir.Should().Be("LACNIC");
    }

    [Fact]
    public void Parse_WebsiteFromRemarks_IsExtracted()
    {
        const string resp = """
            OrgName: Some Host
            remarks: website https://some-host.example/about
            """;
        var r = WhoisResolver.ParseWhoisResponse("whois.arin.net", resp);

        r!.Website.Should().StartWith("https://some-host.example");
    }

    [Fact]
    public void Parse_ExtractsRegistrationAndUpdatedDates_AndStatus()
    {
        const string resp = """
            OrgName: X
            Registration Date: 2015-03-01
            Updated: 2021-07-15
            status: allocated
            """;
        var r = WhoisResolver.ParseWhoisResponse("whois.arin.net", resp);

        r!.RegistrationDate.Should().Be(new DateTime(2015, 3, 1));
        r.UpdatedDate.Should().Be(new DateTime(2021, 7, 15));
        r.Status.Should().Be("allocated");
    }

    [Fact]
    public void Parse_LongResponse_RawPreviewTruncated()
    {
        var big = "OrgName: X\n" + new string('y', 1000);
        var r = WhoisResolver.ParseWhoisResponse("whois.arin.net", big);

        r!.RawResponse!.Length.Should().BeLessThanOrEqualTo(503, "preview is truncated to 500 characters. + «...»");
    }
}
