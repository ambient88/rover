using FluentAssertions;
using SubnetSearch.Network;

namespace SubnetSearch.Tests;

public class NetworkInterfaceHelperTests
{
    [Fact]
    public void GetPhysicalInterfaceName_DoesNotThrow()
    {
        var act = () => NetworkInterfaceHelper.GetPhysicalInterfaceName();
        act.Should().NotThrow();
    }

    [Fact]
    public void GetPhysicalIpAddress_DoesNotThrow()
    {
        var act = () => NetworkInterfaceHelper.GetPhysicalIpAddress();
        act.Should().NotThrow();
    }

    [Fact]
    public void Physical_IsCachedAcrossCalls()
    {
        NetworkInterfaceHelper.GetPhysicalInterfaceName()
            .Should().Be(NetworkInterfaceHelper.GetPhysicalInterfaceName());
        NetworkInterfaceHelper.GetPhysicalIpAddress()
            .Should().Be(NetworkInterfaceHelper.GetPhysicalIpAddress());
    }

    [Fact]
    public void CreateBypassVpnHttpClient_ReturnsNullOrClient()
    {
        var client = NetworkInterfaceHelper.CreateBypassVpnHttpClient(TimeSpan.FromSeconds(5));
        if (client != null)
        {
            client.Timeout.Should().Be(TimeSpan.FromSeconds(5));
            client.Dispose();
        }
    }
}
