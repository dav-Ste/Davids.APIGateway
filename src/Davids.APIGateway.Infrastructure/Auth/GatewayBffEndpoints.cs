using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Davids.APIGateway.Infrastructure.Auth;

public static class GatewayBffEndpoints
{
    public static IEndpointRouteBuilder MapGatewayBffEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/auth/login", (string? returnUrl, HttpContext context, ILoggerFactory loggerFactory) =>
        {
            context.Response.Headers.CacheControl = "no-store";
            var safeReturnUrl = NormalizeLocalReturnUrl(returnUrl);
            loggerFactory.CreateLogger("Davids.Security.Audit").LogInformation(
                "Audit: initiated administrator OIDC PKCE challenge from {ClientIp} (ReturnUrl={ReturnUrl}, CorrelationId={CorrelationId}).",
                GatewaySecurityExtensions.ResolveNormalizedIp(context),
                safeReturnUrl,
                context.TraceIdentifier);
            return Results.Challenge(
                new AuthenticationProperties { RedirectUri = safeReturnUrl },
                [GatewayAuthPolicies.AdminOidcScheme]);
        })
        .AllowAnonymous()
        .RequireRateLimiting(GatewayAuthPolicies.GatewayAdminAuthRateLimitPolicy);

        endpoints.MapGet("/auth/session", async (HttpContext context) =>
        {
            context.Response.Headers.CacheControl = "no-store";

            var cookieAuth = await context.AuthenticateAsync(GatewayAuthPolicies.AdminBffCookieScheme);
            ClaimsPrincipal? principal = null;
            string? authMethod = null;

            if (cookieAuth.Succeeded && cookieAuth.Principal is not null &&
                GatewayIdentityPredicates.IsVerifiedWorkforceReader(cookieAuth.Principal))
            {
                principal = cookieAuth.Principal;
                authMethod = "oidc-bff";
            }
            else
            {
                var bearerAuth = await context.AuthenticateAsync(GatewayAuthPolicies.AdminBearerScheme);
                if (bearerAuth.Succeeded && bearerAuth.Principal is not null &&
                    GatewayIdentityPredicates.IsVerifiedWorkforceReader(bearerAuth.Principal))
                {
                    principal = bearerAuth.Principal;
                    authMethod = "bearer";
                }
            }

            if (principal is null)
            {
                return Results.Json(new
                {
                    code = "unauthenticated",
                    reason = "No active administrator OIDC session."
                }, statusCode: StatusCodes.Status401Unauthorized);
            }

            return Results.Ok(new
            {
                authenticated = true,
                id = principal.FindFirstValue("sub"),
                email = principal.FindFirstValue("email"),
                fullName = principal.FindFirstValue("name"),
                role = principal.FindFirstValue("role") ?? "admin",
                authMethod
            });
        })
        .AllowAnonymous()
        .RequireRateLimiting(GatewayAuthPolicies.GatewayApiRateLimitPolicy);

        endpoints.MapPost("/auth/logout", async (
            HttpContext context,
            GatewayAdminOidcSettings adminOidc,
            IConfigurationFallbackCluster clusterFallback,
            IHttpClientFactory httpClientFactory,
            ILoggerFactory loggerFactory,
            CancellationToken cancellationToken) =>
        {
            context.Response.Headers.CacheControl = "no-store";

            if (!GatewayAdminOidcSettings.HasValidCsrfContext(context))
            {
                GatewaySecurityMetrics.RecordBffCsrfRejection("/auth/logout");
                loggerFactory.CreateLogger("Davids.Security.Audit").LogWarning(
                    "Audit: rejected /auth/logout failing CSRF check from {ClientIp} (SecurityAuditEvent={SecurityAuditEvent}, CorrelationId={CorrelationId}).",
                    GatewaySecurityExtensions.ResolveNormalizedIp(context),
                    "BffCsrfRejected",
                    context.TraceIdentifier);
                return Results.Json(new
                {
                    code = "csrf_rejected",
                    reason = "Missing or invalid CSRF verification header for administrator BFF logout."
                }, statusCode: StatusCodes.Status403Forbidden);
            }

            var authResult = await context.AuthenticateAsync(GatewayAuthPolicies.AdminBffCookieScheme);
            var adminId = authResult.Principal?.FindFirstValue("sub") ?? "unknown";
            if (authResult.Succeeded && authResult.Properties is not null)
            {
                var accessToken = authResult.Properties.GetTokenValue("access_token");
                var refreshToken = authResult.Properties.GetTokenValue("refresh_token");
                var revocationEndpoint = adminOidc.ResolveRevocationEndpoint(clusterFallback);
                var client = httpClientFactory.CreateClient(GatewayAuthPolicies.BackchannelHttpClientName);
                var logger = loggerFactory.CreateLogger("Davids.APIGateway.AdminBffLogout");

                await TryRevokeTokenAsync(
                    client,
                    revocationEndpoint,
                    adminOidc.BffClientId,
                    adminOidc.BffClientSecret,
                    refreshToken,
                    "refresh_token",
                    logger,
                    cancellationToken);
                await TryRevokeTokenAsync(
                    client,
                    revocationEndpoint,
                    adminOidc.BffClientId,
                    adminOidc.BffClientSecret,
                    accessToken,
                    "access_token",
                    logger,
                    cancellationToken);
            }

            await context.SignOutAsync(GatewayAuthPolicies.AdminBffCookieScheme);
            loggerFactory.CreateLogger("Davids.Security.Audit").LogInformation(
                "Audit: signed out administrator BFF session for {AdminId} from {ClientIp} (CorrelationId={CorrelationId}).",
                adminId,
                GatewaySecurityExtensions.ResolveNormalizedIp(context),
                context.TraceIdentifier);
            return Results.NoContent();
        })
        .AllowAnonymous()
        .RequireRateLimiting(GatewayAuthPolicies.GatewayAdminAuthRateLimitPolicy);

        // Customer Web Portal OIDC BFF endpoints (isolated davids_customer_bff cookie)
        endpoints.MapGet("/customer-auth/login", (string? returnUrl, HttpContext context, ILoggerFactory loggerFactory) =>
        {
            context.Response.Headers.CacheControl = "no-store";
            var safeReturnUrl = NormalizeCustomerReturnUrl(returnUrl, context.Request);
            loggerFactory.CreateLogger("Davids.Security.Audit").LogInformation(
                "Audit: initiated customer OIDC PKCE challenge from {ClientIp} (ReturnUrl={ReturnUrl}, CorrelationId={CorrelationId}).",
                GatewaySecurityExtensions.ResolveNormalizedIp(context),
                safeReturnUrl,
                context.TraceIdentifier);
            return Results.Challenge(
                new AuthenticationProperties { RedirectUri = safeReturnUrl },
                [GatewayAuthPolicies.CustomerOidcScheme]);
        })
        .AllowAnonymous()
        .RequireRateLimiting(GatewayAuthPolicies.GatewayCustomerAuthRateLimitPolicy);

        endpoints.MapGet("/customer-auth/session", async (HttpContext context) =>
        {
            context.Response.Headers.CacheControl = "no-store";

            var cookieAuth = await context.AuthenticateAsync(GatewayAuthPolicies.CustomerBffCookieScheme);
            ClaimsPrincipal? principal = null;
            string? authMethod = null;

            if (cookieAuth.Succeeded && cookieAuth.Principal is not null &&
                GatewayIdentityPredicates.IsVerifiedCustomer(cookieAuth.Principal))
            {
                principal = cookieAuth.Principal;
                authMethod = "oidc-bff";
            }
            else
            {
                var bearerAuth = await context.AuthenticateAsync(GatewayAuthPolicies.CustomerBearerScheme);
                if (bearerAuth.Succeeded && bearerAuth.Principal is not null &&
                    GatewayIdentityPredicates.IsVerifiedCustomer(bearerAuth.Principal))
                {
                    principal = bearerAuth.Principal;
                    authMethod = "bearer";
                }
            }

            if (principal is null)
            {
                return Results.Json(new
                {
                    code = "unauthenticated",
                    reason = "No active customer OIDC session."
                }, statusCode: StatusCodes.Status401Unauthorized);
            }

            return Results.Ok(new
            {
                authenticated = true,
                id = principal.FindFirstValue("sub"),
                email = principal.FindFirstValue("email"),
                role = "user",
                authMethod
            });
        })
        .AllowAnonymous()
        .RequireRateLimiting(GatewayAuthPolicies.GatewayApiRateLimitPolicy);

        endpoints.MapPost("/customer-auth/logout", async (
            HttpContext context,
            GatewayCustomerOidcSettings customerOidc,
            IConfigurationFallbackCluster clusterFallback,
            IHttpClientFactory httpClientFactory,
            ILoggerFactory loggerFactory,
            CancellationToken cancellationToken) =>
        {
            context.Response.Headers.CacheControl = "no-store";

            if (!GatewayCustomerOidcSettings.HasValidCsrfContext(context))
            {
                GatewaySecurityMetrics.RecordBffCsrfRejection("/customer-auth/logout");
                loggerFactory.CreateLogger("Davids.Security.Audit").LogWarning(
                    "Audit: rejected /customer-auth/logout failing CSRF check from {ClientIp} (SecurityAuditEvent={SecurityAuditEvent}, CorrelationId={CorrelationId}).",
                    GatewaySecurityExtensions.ResolveNormalizedIp(context),
                    "CustomerBffCsrfRejected",
                    context.TraceIdentifier);
                return Results.Json(new
                {
                    code = "csrf_rejected",
                    reason = "Missing or invalid CSRF verification header for customer BFF logout."
                }, statusCode: StatusCodes.Status403Forbidden);
            }

            var authResult = await context.AuthenticateAsync(GatewayAuthPolicies.CustomerBffCookieScheme);
            var customerId = authResult.Principal?.FindFirstValue("sub") ?? "unknown";
            if (authResult.Succeeded && authResult.Properties is not null)
            {
                var accessToken = authResult.Properties.GetTokenValue("access_token");
                var refreshToken = authResult.Properties.GetTokenValue("refresh_token");
                var revocationEndpoint = customerOidc.ResolveRevocationEndpoint(clusterFallback);
                var client = httpClientFactory.CreateClient(GatewayAuthPolicies.CustomerBackchannelHttpClientName);
                var logger = loggerFactory.CreateLogger("Davids.APIGateway.CustomerBffLogout");

                await TryRevokeTokenAsync(
                    client,
                    revocationEndpoint,
                    customerOidc.BffClientId,
                    clientSecret: null,
                    refreshToken,
                    "refresh_token",
                    logger,
                    cancellationToken);
                await TryRevokeTokenAsync(
                    client,
                    revocationEndpoint,
                    customerOidc.BffClientId,
                    clientSecret: null,
                    accessToken,
                    "access_token",
                    logger,
                    cancellationToken);
            }

            await context.SignOutAsync(GatewayAuthPolicies.CustomerBffCookieScheme);
            loggerFactory.CreateLogger("Davids.Security.Audit").LogInformation(
                "Audit: signed out customer BFF session for {CustomerId} from {ClientIp} (CorrelationId={CorrelationId}).",
                customerId,
                GatewaySecurityExtensions.ResolveNormalizedIp(context),
                context.TraceIdentifier);
            return Results.NoContent();
        })
        .AllowAnonymous()
        .RequireRateLimiting(GatewayAuthPolicies.GatewayCustomerAuthRateLimitPolicy);

        return endpoints;
    }

    public static string NormalizeLocalReturnUrl(string? returnUrl)
    {
        if (string.IsNullOrWhiteSpace(returnUrl))
        {
            return "/";
        }

        var trimmed = returnUrl.Trim();
        if (!trimmed.StartsWith('/') || trimmed.StartsWith("//", StringComparison.Ordinal) || trimmed.StartsWith("/\\", StringComparison.Ordinal))
        {
            return "/";
        }

        if (trimmed.StartsWith("/login", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("/auth/", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("/customer-auth/", StringComparison.OrdinalIgnoreCase))
        {
            return "/";
        }

        return trimmed;
    }

    public static string NormalizeCustomerReturnUrl(string? returnUrl, HttpRequest request)
    {
        var defaultTarget = GatewaySecurityExtensions.IsCustomerHost(request.Host.Host) ? "/" : "/portal";
        if (string.IsNullOrWhiteSpace(returnUrl))
        {
            return defaultTarget;
        }

        var trimmed = returnUrl.Trim();
        if (!trimmed.StartsWith('/') || trimmed.StartsWith("//", StringComparison.Ordinal) || trimmed.StartsWith("/\\", StringComparison.Ordinal))
        {
            return defaultTarget;
        }

        if (trimmed.StartsWith("/login", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("/portal/login", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("/auth/", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("/customer-auth/", StringComparison.OrdinalIgnoreCase))
        {
            return defaultTarget;
        }

        return trimmed;
    }

    private static async Task TryRevokeTokenAsync(
        HttpClient client,
        string revocationEndpoint,
        string clientId,
        string? clientSecret,
        string? token,
        string tokenTypeHint,
        ILogger logger,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            return;
        }

        try
        {
            var form = new Dictionary<string, string>
            {
                ["client_id"] = clientId,
                ["token"] = token,
                ["token_type_hint"] = tokenTypeHint
            };
            if (!string.IsNullOrWhiteSpace(clientSecret))
            {
                form["client_secret"] = clientSecret;
            }

            using var response = await client.PostAsync(
                revocationEndpoint,
                new FormUrlEncodedContent(form),
                cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "Back-channel OIDC {TokenTypeHint} revocation failed during BFF logout.", tokenTypeHint);
        }
    }
}
