using System.Net.Http.Headers;
using Davids.APIGateway.Infrastructure.Auth;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Yarp.ReverseProxy.Transforms;

namespace Davids.APIGateway.Infrastructure;

public static class ReverseProxyExtensions
{
    public const string VerifiedUserIdHeader = "X-Auth-User-Id";
    public const string VerifiedUserRoleHeader = "X-Auth-User-Role";
    public const string VerifiedTokenIdHeader = "X-Auth-Token-Id";
    public const string VerifiedSchemeHeader = "X-Auth-Scheme";

    private const string IdentityAddressKey = "ReverseProxy:Clusters:identity:Destinations:primary:Address";
    private const string AdminIdentityAddressKey = "ReverseProxy:Clusters:admin-identity:Destinations:primary:Address";
    private const string CustomersAddressKey = "ReverseProxy:Clusters:customers:Destinations:primary:Address";
    private const string FrontendAdminAddressKey = "ReverseProxy:Clusters:frontend-admin:Destinations:primary:Address";

    public static IServiceCollection AddGatewayReverseProxy(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        ValidateHttpAddress(configuration, IdentityAddressKey, "identity");
        ValidateHttpAddress(configuration, AdminIdentityAddressKey, "admin-identity");
        ValidateHttpAddress(configuration, CustomersAddressKey, "customers");
        ValidateHttpAddress(configuration, FrontendAdminAddressKey, "frontend-admin");

        services.AddReverseProxy()
            .LoadFromConfig(configuration.GetSection("ReverseProxy"))
            .AddTransforms(builderContext =>
            {
                var isFrontendCluster = string.Equals(
                    builderContext.Cluster?.ClusterId,
                    "frontend-admin",
                    StringComparison.OrdinalIgnoreCase);

                builderContext.AddRequestTransform(transformContext =>
                {
                    // Strip any client-supplied identity headers to prevent spoofing.
                    transformContext.ProxyRequest.Headers.Remove(VerifiedUserIdHeader);
                    transformContext.ProxyRequest.Headers.Remove(VerifiedUserRoleHeader);
                    transformContext.ProxyRequest.Headers.Remove(VerifiedTokenIdHeader);
                    transformContext.ProxyRequest.Headers.Remove(VerifiedSchemeHeader);

                    // Overwrite X-Forwarded-For with the verified gateway client IP (never append to untrusted client headers).
                    transformContext.ProxyRequest.Headers.Remove("X-Forwarded-For");
                    var remoteIp = transformContext.HttpContext.Connection.RemoteIpAddress;
                    if (remoteIp is not null)
                    {
                        var normalizedIp = remoteIp.IsIPv4MappedToIPv6
                            ? remoteIp.MapToIPv4().ToString()
                            : remoteIp.ToString();
                        transformContext.ProxyRequest.Headers.TryAddWithoutValidation("X-Forwarded-For", normalizedIp);
                    }

                    // Never forward gateway HttpOnly BFF session cookies to downstream hosts.
                    transformContext.ProxyRequest.Headers.Remove("Cookie");

                    if (isFrontendCluster)
                    {
                        transformContext.ProxyRequest.Headers.Remove("Authorization");
                        return ValueTask.CompletedTask;
                    }

                    var user = transformContext.HttpContext.User;
                    var activeIdentity =
                        user?.Identities.FirstOrDefault(i =>
                            i.IsAuthenticated &&
                            (string.Equals(i.AuthenticationType, GatewayAuthPolicies.AdminBearerScheme, StringComparison.Ordinal) ||
                             string.Equals(i.AuthenticationType, GatewayAuthPolicies.AdminBffCookieScheme, StringComparison.Ordinal)))
                        ?? user?.Identities.FirstOrDefault(i => i.IsAuthenticated);

                    if (activeIdentity is not null)
                    {
                        var isAdminIdentity =
                            string.Equals(activeIdentity.AuthenticationType, GatewayAuthPolicies.AdminBearerScheme, StringComparison.Ordinal) ||
                            string.Equals(activeIdentity.AuthenticationType, GatewayAuthPolicies.AdminBffCookieScheme, StringComparison.Ordinal);

                        if (isAdminIdentity &&
                            transformContext.ProxyRequest.Headers.Authorization is null &&
                            transformContext.HttpContext.Items.TryGetValue(GatewayAuthPolicies.VerifiedAdminRawTokenItemKey, out var rawObj) &&
                            rawObj is string rawAdminToken &&
                            !string.IsNullOrWhiteSpace(rawAdminToken))
                        {
                            transformContext.ProxyRequest.Headers.Authorization =
                                new AuthenticationHeaderValue("Bearer", rawAdminToken);
                        }

                        var subject = activeIdentity.FindFirst("sub")?.Value;
                        var role = activeIdentity.FindFirst("role")?.Value;
                        var tokenId = activeIdentity.FindFirst("jti")?.Value;
                        if (string.IsNullOrWhiteSpace(tokenId) &&
                            transformContext.HttpContext.Items.TryGetValue(GatewayAuthPolicies.VerifiedAdminTokenIdItemKey, out var jtiObj) &&
                            jtiObj is string bffJti)
                        {
                            tokenId = bffJti;
                        }

                        var scheme = activeIdentity.AuthenticationType;

                        if (!string.IsNullOrWhiteSpace(subject))
                        {
                            transformContext.ProxyRequest.Headers.TryAddWithoutValidation(VerifiedUserIdHeader, subject);
                        }

                        if (!string.IsNullOrWhiteSpace(role))
                        {
                            transformContext.ProxyRequest.Headers.TryAddWithoutValidation(VerifiedUserRoleHeader, role);
                        }

                        if (!string.IsNullOrWhiteSpace(tokenId))
                        {
                            transformContext.ProxyRequest.Headers.TryAddWithoutValidation(VerifiedTokenIdHeader, tokenId);
                        }

                        if (!string.IsNullOrWhiteSpace(scheme))
                        {
                            transformContext.ProxyRequest.Headers.TryAddWithoutValidation(VerifiedSchemeHeader, scheme);
                        }
                    }

                    return ValueTask.CompletedTask;
                });

                if (isFrontendCluster)
                {
                    builderContext.AddResponseTransform(responseContext =>
                    {
                        responseContext.HttpContext.Response.Headers.CacheControl = "no-store, no-cache, must-revalidate";
                        return ValueTask.CompletedTask;
                    });
                }
            });

        return services;
    }

    private static void ValidateHttpAddress(IConfiguration configuration, string key, string destinationName)
    {
        var address = configuration[key];
        if (!Uri.TryCreate(address, UriKind.Absolute, out var uri) ||
            (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
        {
            throw new InvalidOperationException($"A valid HTTP(S) {destinationName} destination is required at '{key}'.");
        }
    }

    public static IEndpointRouteBuilder MapGatewayReverseProxy(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapReverseProxy();
        return endpoints;
    }
}
