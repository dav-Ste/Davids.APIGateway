using Davids.APIGateway.Infrastructure;
using Davids.APIGateway.Infrastructure.Auth;
using Davids.ServiceDefaults;
using Microsoft.AspNetCore.DataProtection;

var builder = WebApplication.CreateBuilder(args);
await builder.Configuration.LoadVaultAsync();
builder.AddServiceDefaults("davids-api-gateway");
builder.Services.AddTrustedForwardedHeaders(
    builder.Configuration,
    builder.Environment,
    trustLoopbackInNonProduction: false);
builder.Services.AddGatewaySecurity(builder.Configuration, builder.Environment);
builder.Services.AddDataProtection()
    .ConfigureDavidsDataProtection(
        builder.Configuration,
        builder.Environment,
        applicationName: "davids-api-gateway",
        externalRepositoryFactory: sp =>
        {
            var store = sp.GetService<IGatewayDataProtectionStore>();
            return store is null ? null : new GatewayDataProtectionXmlRepository(store);
        },
        externalStoreConfigured: builder.Configuration.GetValue<bool>("Redis:Enabled"));
builder.Services.AddGatewayReverseProxy(builder.Configuration);

var app = builder.Build();
app.UseTrustedForwardedHeaders();
app.UseMiddleware<GatewayRequestContextMiddleware>();
app.Use((context, next) =>
{
    var headers = context.Response.Headers;
    headers["X-Content-Type-Options"] = "nosniff";
    headers["Referrer-Policy"] = "strict-origin-when-cross-origin";
    headers["X-Frame-Options"] = "DENY";
    headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()";
    var isCustomerAuthorize = context.Request.Path.StartsWithSegments(
        "/identity/connect/authorize",
        StringComparison.OrdinalIgnoreCase);
    var formAction = isCustomerAuthorize
        ? (app.Environment.IsDevelopment() ? "'self' https: http:" : "'self' https:")
        : "'self'";
    headers["Content-Security-Policy"] =
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
        "connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'self'; " +
        $"frame-ancestors 'none'; form-action {formAction}";

    var method = context.Request.Method;
    var isAllowedMethod =
        HttpMethods.IsGet(method) ||
        HttpMethods.IsHead(method) ||
        HttpMethods.IsPost(method) ||
        HttpMethods.IsPut(method) ||
        HttpMethods.IsDelete(method) ||
        HttpMethods.IsOptions(method);
    if (!isAllowedMethod)
    {
        headers["Allow"] = "GET, HEAD, POST, PUT, DELETE, OPTIONS";
        context.Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
        return Task.CompletedTask;
    }

    return next();
});
app.UseAuthentication();
app.UseAuthorization();
app.UseRateLimiter();

app.MapDefaultEndpoints();
app.MapGatewayBffEndpoints();
app.MapGet("/gateway-info", () => Results.Ok(new
{
    service = "Davids API Gateway",
    routes = new[]
    {
        "/auth/login",
        "/auth/session",
        "/auth/logout",
        "/signin-oidc",
        "/identity/{**remainder}",
        "/admin-identity/{**remainder}",
        "/customers/{**remainder}",
        "/login",
        "/{**remainder}"
    },
    authentication = "Self-Hosted .NET OIDC: CustomerBearer RS256 JWKS + AdminBearer RS256 JWKS + Confidential PKCE AdminBffCookie",
    authorization = new[]
    {
        "Anonymous (explicit public OIDC protocol & /login routes)",
        "customer-authenticated",
        "authenticated",
        "resource-owner-or-admin",
        "customers-admin",
        "admin-frontend"
    },
    routing = "YARP validates RS256 OIDC JWTs via JWKS discovery and terminates the Authorization Code + PKCE BFF session for Davids.Frontend.Admin, stripping cookies and injecting verified Bearer tokens to downstream clusters."
})).AllowAnonymous();
app.MapGatewayReverseProxy();
app.Run();

public partial class Program { }
