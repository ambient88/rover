using FluentAssertions;
using SubnetSearch.Core.Utilities;

namespace SubnetSearch.Tests;

public class CsvLineTests
{
    [Fact]
    public void Parse_PlainFields()
        => CsvLine.Parse("a,b,c").Should().Equal("a", "b", "c");

    [Fact]
    public void Parse_QuotedFields_StripsQuotes()
        => CsvLine.Parse("\"a\",\"b\"").Should().Equal("a", "b");

    // The F7 case: a comma inside a quoted provider name must stay inside one field.
    [Fact]
    public void Parse_EmbeddedComma_KeptInsideField()
    {
        var fields = CsvLine.Parse(
            "64.5.32.0,64.5.63.255,\"ThePlanet.com Internet Services, Inc.\",http://theplanet.com");

        fields.Should().Equal(
            "64.5.32.0",
            "64.5.63.255",
            "ThePlanet.com Internet Services, Inc.",
            "http://theplanet.com");
    }

    [Fact]
    public void Parse_EscapedQuotes_BecomeLiteralQuote()
        => CsvLine.Parse("\"say \"\"hi\"\"\",x").Should().Equal("say \"hi\"", "x");

    [Fact]
    public void Parse_EmptyFields_Preserved()
        => CsvLine.Parse("a,,c").Should().Equal("a", "", "c");

    [Fact]
    public void Parse_TrailingEmptyField_Preserved()
        => CsvLine.Parse("a,b,").Should().Equal("a", "b", "");
}
