using System.Net.Http.Headers;
using System.Security.Claims;
using Davids.APIGateway.Infrastructure.Auth;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Yarp.ReverseProxy.Transforms;

namespace Davids.APIGateway.Infrastructure;

public static class ReverseProxyExtensions
{
    public const string VerifiedUserIdHeader = "X-Auth-User-Id";
    public const string VerifiedUserRoleHeader = "X-Auth-User-Role";
    public const string VerifiedUserEmailHeader = "X-Auth-User-Email";
    public const string VerifiedTokenIdHeader = "X-Auth-Token-Id";
    public const string VerifiedSchemeHeader = "X-Auth-Scheme";
    public const string VerifiedAuthorityHeader = "X-Auth-Authority";

    private static readonly string[] SpoofableAuthHeaders =
    [
        VerifiedUserIdHeader,
        VerifiedUserRoleHeader,
        VerifiedUserEmailHeader,
        VerifiedTokenIdHeader,
        VerifiedSchemeHeader,
        VerifiedAuthorityHeader,
        "X-Auth-UserId",
        "X-Auth-Role",
        "X-Auth-Email"
    ];

    private const string IdentityAddressKey = "ReverseProxy:Clusters:identity:Destinations:primary:Address";
    private const string AdminIdentityAddressKey = "ReverseProxy:Clusters:admin-identity:Destinations:primary:Address";
    private const string CustomersAddressKey = "ReverseProxy:Clusters:customers:Destinations:primary:Address";
    private const string FrontendAdminAddressKey = "ReverseProxy:Clusters:frontend-admin:Destinations:primary:Address";
    private const string FrontendWebAddressKey = "ReverseProxy:Clusters:frontend-web:Destinations:primary:Address";

    public static IServiceCollection AddGatewayReverseProxy(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        ValidateHttpAddress(configuration, IdentityAddressKey, "identity");
        ValidateHttpAddress(configuration, AdminIdentityAddressKey, "admin-identity");
        ValidateHttpAddress(configuration, CustomersAddressKey, "customers");
        ValidateHttpAddress(configuration, FrontendAdminAddressKey, "frontend-admin");
        if (!string.IsNullOrWhiteSpace(configuration[FrontendWebAddressKey]))
        {
            ValidateHttpAddress(configuration, FrontendWebAddressKey, "frontend-web");
        }

        services.AddReverseProxy()
            .LoadFromConfig(configuration.GetSection("ReverseProxy"))
            .AddTransforms(builderContext =>
            {
                var clusterId = builderContext.Cluster?.ClusterId;
                var isFrontendCluster =
                    string.Equals(clusterId, "frontend-admin", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(clusterId, "frontend-web", StringComparison.OrdinalIgnoreCase);

                builderContext.AddRequestTransform(transformContext =>
                {
                    // Strip any client-supplied identity headers to prevent spoofing.
                    foreach (var header in SpoofableAuthHeaders)
                    {
                        transformContext.ProxyRequest.Headers.Remove(header);
                    }

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

                    var activeIdentity = SelectActiveBackendIdentity(
                        transformContext.HttpContext.User,
                        transformContext.HttpContext.Request);

                    if (activeIdentity is not null)
                    {
                        var isWorkforceIdentity =
                            string.Equals(activeIdentity.AuthenticationType, GatewayAuthPolicies.AdminBearerScheme, StringComparison.Ordinal) ||
                            string.Equals(activeIdentity.AuthenticationType, GatewayAuthPolicies.AdminBffCookieScheme, StringComparison.Ordinal);

                        if (transformContext.ProxyRequest.Headers.Authorization is null)
                        {
                            var rawItemKey = isWorkforceIdentity
                                ? GatewayAuthPolicies.VerifiedAdminRawTokenItemKey
                                : GatewayAuthPolicies.VerifiedCustomerRawTokenItemKey;
                            if (transformContext.HttpContext.Items.TryGetValue(rawItemKey, out var rawObj) &&
                                rawObj is string rawToken &&
                                !string.IsNullOrWhiteSpace(rawToken))
                            {
                                transformContext.ProxyRequest.Headers.Authorization =
                                    new AuthenticationHeaderValue("Bearer", rawToken);
                            }
                        }

                        var subject = activeIdentity.FindFirst("sub")?.Value;
                        var role = activeIdentity.FindFirst("role")?.Value;
                        var email = activeIdentity.FindFirst("email")?.Value;
                        var tokenId = activeIdentity.FindFirst("jti")?.Value;
                        if (string.IsNullOrWhiteSpace(tokenId))
                        {
                            var jtiKey = isWorkforceIdentity
                                ? GatewayAuthPolicies.VerifiedAdminTokenIdItemKey
                                : GatewayAuthPolicies.VerifiedCustomerTokenIdItemKey;
                            if (transformContext.HttpContext.Items.TryGetValue(jtiKey, out var jtiObj) &&
                                jtiObj is string bffJti)
                            {
                                tokenId = bffJti;
                            }
                        }

                        var scheme = activeIdentity.AuthenticationType;
                        var authority = isWorkforceIdentity ? "employee" : "customer";

                        if (!string.IsNullOrWhiteSpace(subject))
                        {
                            transformContext.ProxyRequest.Headers.TryAddWithoutValidation(VerifiedUserIdHeader, subject);
                        }

                        if (!string.IsNullOrWhiteSpace(role))
                        {
                            transformContext.ProxyRequest.Headers.TryAddWithoutValidation(VerifiedUserRoleHeader, role);
                        }

                        if (!string.IsNullOrWhiteSpace(email))
                        {
                            transformContext.ProxyRequest.Headers.TryAddWithoutValidation(VerifiedUserEmailHeader, email);
                        }

                        if (!string.IsNullOrWhiteSpace(tokenId))
                        {
                            transformContext.ProxyRequest.Headers.TryAddWithoutValidation(VerifiedTokenIdHeader, tokenId);
                        }

                        if (!string.IsNullOrWhiteSpace(scheme))
                        {
                            transformContext.ProxyRequest.Headers.TryAddWithoutValidation(VerifiedSchemeHeader, scheme);
                        }

                        transformContext.ProxyRequest.Headers.TryAddWithoutValidation(VerifiedAuthorityHeader, authority);
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

    private static ClaimsIdentity? SelectActiveBackendIdentity(ClaimsPrincipal? user, HttpRequest request)
    {
        if (user is null)
        {
            return null;
        }

        var path = request.Path;
        var prefersCustomer =
            path.StartsWithSegments("/identity") ||
            path.StartsWithSegments("/customers/me") ||
            (path.Equals("/customers", StringComparison.OrdinalIgnoreCase) && HttpMethods.IsPost(request.Method)) ||
            GatewaySecurityExtensions.IsCustomerHost(request.Host.Host);

        if (prefersCustomer)
        {
            return GatewayIdentityPredicates.FindVerifiedCustomerIdentity(user)
                ?? user.Identities.FirstOrDefault(i => i.IsAuthenticated);
        }

        return user.Identities.FirstOrDefault(i =>
                   i.IsAuthenticated &&
                   (string.Equals(i.AuthenticationType, GatewayAuthPolicies.AdminBearerScheme, StringComparison.Ordinal) ||
                    string.Equals(i.AuthenticationType, GatewayAuthPolicies.AdminBffCookieScheme, StringComparison.Ordinal)))
               ?? user.Identities.FirstOrDefault(i => i.IsAuthenticated);
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
