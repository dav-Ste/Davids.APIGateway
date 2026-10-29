using System.Diagnostics;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace Davids.APIGateway.Infrastructure;

/// <summary>
/// Establishes the request correlation ID and forwards the current W3C server context
/// before YARP creates its outbound proxy span for the destination.
/// </summary>
public sealed class GatewayRequestContextMiddleware
{
    public const string CorrelationIdHeader = "X-Correlation-ID";

    private readonly RequestDelegate _next;
    private readonly ILogger<GatewayRequestContextMiddleware> _logger;

    public GatewayRequestContextMiddleware(
        RequestDelegate next,
        ILogger<GatewayRequestContextMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var correlationId = GetCorrelationId(context);
        context.TraceIdentifier = correlationId;
        context.Request.Headers[CorrelationIdHeader] = correlationId;

        var activity = Activity.Current;
        var traceParent = activity is { IdFormat: ActivityIdFormat.W3C } ? activity.Id : null;
        if (!string.IsNullOrEmpty(traceParent))
        {
            context.Request.Headers["traceparent"] = traceParent;
            if (!string.IsNullOrWhiteSpace(activity!.TraceStateString))
            {
                context.Request.Headers["tracestate"] = activity.TraceStateString;
            }
            else
            {
                context.Request.Headers.Remove("tracestate");
            }
        }

        context.Response.OnStarting(() =>
        {
            context.Response.Headers[CorrelationIdHeader] = correlationId;
            if (activity is { IdFormat: ActivityIdFormat.W3C })
            {
                context.Response.Headers["X-Trace-Id"] = activity.TraceId.ToString();
                context.Response.Headers["X-Span-Id"] = activity.SpanId.ToString();
            }

            return Task.CompletedTask;
        });

        using var scope = _logger.BeginScope(new Dictionary<string, object>
        {
            ["CorrelationId"] = correlationId
        });
        try
        {
            await _next(context);
        }
        catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested)
        {
            if (!context.Response.HasStarted)
            {
                context.Response.StatusCode = StatusCodes.Status499ClientClosedRequest;
            }
        }
    }

    private static string GetCorrelationId(HttpContext context)
    {
        var candidate = context.Request.Headers[CorrelationIdHeader].ToString();
        return IsValidCorrelationId(candidate) ? candidate : Guid.NewGuid().ToString("N");
    }

    private static bool IsValidCorrelationId(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 128)
        {
            return false;
        }

        foreach (var character in value)
        {
            if (!char.IsAsciiLetterOrDigit(character) && character is not '-' and not '_' and not '.' and not ':')
            {
                return false;
            }
        }

        return true;
    }
}
