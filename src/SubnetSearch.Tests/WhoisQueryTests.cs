using FluentAssertions;
using SubnetSearch.Data;

namespace SubnetSearch.Tests;

public class WhoisQueryTests
{
    [Fact]
    public async Task ReadResponseAsync_ReturnsResponseWithinLimit()
    {
        const string response = "netname: EXAMPLE\ncountry: US\n";

        var result = await WhoisQuery.ReadResponseAsync(
            new StringReader(response), CancellationToken.None);

        result.Should().Be(response);
    }

    [Fact]
    public async Task ReadResponseAsync_RejectsOversizedResponse()
    {
        var response = new string('x', WhoisQuery.MaxResponseChars + 1);

        var action = () => WhoisQuery.ReadResponseAsync(
            new StringReader(response), CancellationToken.None);

        await action.Should().ThrowAsync<InvalidDataException>();
    }

    [Fact]
    public async Task ReadResponseAsync_ObservesCancellation()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var action = () => WhoisQuery.ReadResponseAsync(
            new StringReader("response"), cts.Token);

        await action.Should().ThrowAsync<OperationCanceledException>();
    }
}
