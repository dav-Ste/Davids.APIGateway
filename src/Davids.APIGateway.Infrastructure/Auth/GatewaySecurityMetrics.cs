using System.Diagnostics.Metrics;

namespace Davids.APIGateway.Infrastructure.Auth;

public static class GatewaySecurityMetrics
{
    public const string MeterName = "Davids.Security.Audit";

    private static readonly Meter AuditMeter = new(MeterName, "1.0.0");

    private static readonly Counter<long> RateLimitRejectedCounter =
        AuditMeter.CreateCounter<long>("davids.security.rate_limit_rejected", unit: "{request}");

    private static readonly Counter<long> BffCsrfRejectedCounter =
        AuditMeter.CreateCounter<long>("davids.security.bff_csrf_rejected", unit: "{request}");

    public static void RecordRateLimitRejection(string policy)
    {
        RateLimitRejectedCounter.Add(
            1,
            new KeyValuePair<string, object>("service", "davids-api-gateway"),
            new KeyValuePair<string, object>("policy", policy ?? "default"));
    }

    public static void RecordBffCsrfRejection(string endpoint)
    {
        BffCsrfRejectedCounter.Add(
            1,
            new KeyValuePair<string, object>("service", "davids-api-gateway"),
            new KeyValuePair<string, object>("endpoint", endpoint ?? "unknown"));
    }
}
