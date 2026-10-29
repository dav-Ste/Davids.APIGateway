using System.Collections.Concurrent;
using System.Diagnostics.Metrics;
using System.Net;
using Davids.APIGateway.Infrastructure.Auth;
using Xunit;

namespace Davids.APIGateway.Tests;

[Trait("Category", "Integration")]
public sealed class GatewaySecurityMetricsTests
{
    [Fact]
    public async Task MissingBffCsrfHeaderOnLogoutEmitsCsrfSecurityMetric()
    {
        var events = new ConcurrentBag<(string Name, string Service, string Endpoint)>();
        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, meterListener) =>
        {
            if (instrument.Meter.Name == GatewaySecurityMetrics.MeterName)
            {
                meterListener.EnableMeasurementEvents(instrument);
            }
        };
        listener.SetMeasurementEventCallback<long>((instrument, _, tags, _) =>
        {
            string service = string.Empty, endpoint = string.Empty;
            foreach (var tag in tags)
            {
                if (tag.Key == "service") service = tag.Value?.ToString() ?? string.Empty;
                if (tag.Key == "endpoint") endpoint = tag.Value?.ToString() ?? string.Empty;
            }
            events.Add((instrument.Name, service, endpoint));
        });
        listener.Start();

        using var factory = GatewayTestSecurity.CreateGatewayFactory("http://127.0.0.1:9/");
        using var client = factory.CreateClient();

        using var request = new HttpRequestMessage(HttpMethod.Post, "/auth/logout");
        using var response = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);

        Assert.Contains(events, e =>
            e.Name == "davids.security.bff_csrf_rejected" &&
            e.Service == "davids-api-gateway" &&
            e.Endpoint == "/auth/logout");
    }
}
