using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Json;
using System.Threading.RateLimiting;
using Davids.APIGateway.Infrastructure.Auth;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using StackExchange.Redis;

namespace Davids.APIGateway.Infrastructure;

public sealed class GatewayAuthorizationResultHandler : IAuthorizationMiddlewareResultHandler
{
    public async Task HandleAsync(
        RequestDelegate next,
        HttpContext context,
        AuthorizationPolicy policy,
        PolicyAuthorizationResult authorizeResult)
    {
        if (authorizeResult.Succeeded)
        {
            await next(context);
            return;
        }

        if (context.Response.HasStarted)
        {
            return;
        }

        if (context.Items.ContainsKey(GatewayAuthPolicies.CsrfRejectedItemKey))
        {
            GatewaySecurityMetrics.RecordBffCsrfRejection("proxy");
            context.RequestServices
                .GetRequiredService<Microsoft.Extensions.Logging.ILoggerFactory>()
                .CreateLogger("Davids.Security.Audit")
                .LogWarning(
                    "Audit: rejected cookie-authenticated administrator request failing CSRF check from {ClientIp} on {Path} (SecurityAuditEvent={SecurityAuditEvent}, CorrelationId={CorrelationId}).",
                    GatewaySecurityExtensions.ResolveNormalizedIp(context),
                    context.Request.Path.Value,
                    "BffCsrfRejected",
                    context.TraceIdentifier);
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            context.Response.Headers.CacheControl = "no-store";
            await context.Response.WriteAsJsonAsync(new
            {
                code = "csrf_rejected",
                reason = "Missing or invalid CSRF verification header for cookie-authenticated administrator request."
            }, context.RequestAborted);
            return;
        }

        if (authorizeResult.Forbidden)
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            context.Response.Headers.CacheControl = "no-store";
            await context.Response.WriteAsJsonAsync(new
            {
                code = "forbidden",
                reason = "Your account is not permitted to perform this action."
            }, context.RequestAborted);
            return;
        }

        if (IsBrowserAdminFrontendNavigation(context.Request))
        {
            context.Response.StatusCode = StatusCodes.Status302Found;
            context.Response.Headers.Location = "/login";
            context.Response.Headers.CacheControl = "no-store";
            return;
        }

        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        context.Response.Headers.WWWAuthenticate = "Bearer";
        context.Response.Headers.CacheControl = "no-store";
        await context.Response.WriteAsJsonAsync(new
        {
            code = "unauthenticated",
            reason = "A valid RS256 Bearer access token or active OIDC BFF session is required."
        }, context.RequestAborted);
    }

    private static bool IsBrowserAdminFrontendNavigation(HttpRequest request)
    {
        if (!HttpMethods.IsGet(request.Method) && !HttpMethods.IsHead(request.Method))
        {
            return false;
        }

        if (request.Path.StartsWithSegments("/identity") ||
            request.Path.StartsWithSegments("/admin-identity") ||
            request.Path.StartsWithSegments("/customers") ||
            request.Path.StartsWithSegments("/auth"))
        {
            return false;
        }

        var accept = request.Headers.Accept.ToString();
        return accept.Contains("text/html", StringComparison.OrdinalIgnoreCase);
    }
}

public static class GatewaySecurityExtensions
{
    public static IServiceCollection AddGatewaySecurity(
        this IServiceCollection services,
        IConfiguration configuration,
        IHostEnvironment environment)
    {
        var customerOidc = configuration.GetSection("CustomerOidc").Get<GatewayOidcAuthoritySettings>()
            ?? new GatewayOidcAuthoritySettings();
        var customerStaticKey = customerOidc.ValidateAndResolveStaticPublicKey("CustomerOidc");

        var adminOidc = configuration.GetSection("AdminOidc").Get<GatewayAdminOidcSettings>()
            ?? new GatewayAdminOidcSettings();
        var adminStaticKey = adminOidc.ValidateAdminSettings(customerOidc.PublicKeyPem);

        var adminClusterAddress =
            configuration["ReverseProxy:Clusters:admin-identity:Destinations:primary:Address"]
            ?? "http://localhost:5014/";
        var clusterFallback = new IConfigurationFallbackCluster(adminClusterAddress);

        services.AddSingleton(customerOidc);
        services.AddSingleton(adminOidc);
        services.AddSingleton(clusterFallback);
        services.AddDataProtection();
        AddGatewayRateLimiting(services, configuration);
        services.AddHttpClient(GatewayAuthPolicies.BackchannelHttpClientName, client =>
        {
            client.Timeout = TimeSpan.FromSeconds(30);
        });

        if (configuration.GetValue<bool>("Redis:Enabled"))
        {
            var connection = configuration.GetConnectionString("cache")
                ?? throw new InvalidOperationException("Redis is enabled at the API Gateway, but ConnectionStrings:cache is missing.");
            services.AddSingleton<IConnectionMultiplexer>(_ =>
            {
                var options = ConfigurationOptions.Parse(connection);
                options.AbortOnConnectFail = false;
                options.ConnectTimeout = 5000;
                options.AsyncTimeout = 5000;
                return ConnectionMultiplexer.Connect(options);
            });
            services.AddSingleton<IGatewayTokenRevocation, RedisGatewayTokenRevocation>();
            services.AddSingleton<IGatewayDataProtectionStore, RedisGatewayDataProtectionStore>();
        }
        else
        {
            services.AddSingleton<IGatewayTokenRevocation, NoGatewayTokenRevocation>();
        }

        var requireHttpsMetadata =
            environment.IsProduction() ||
            !(environment.IsDevelopment() ||
              environment.IsEnvironment("Testing") ||
              configuration.GetValue<bool>("Http:AllowInsecureDevelopment"));

        var cookieSecurePolicy = environment.IsProduction()
            ? CookieSecurePolicy.Always
            : CookieSecurePolicy.SameAsRequest;

        services.AddAuthentication(GatewayAuthPolicies.CustomerBearerScheme)
            .AddJwtBearer(GatewayAuthPolicies.CustomerBearerScheme, options =>
            {
                options.MapInboundClaims = false;
                options.RequireHttpsMetadata = requireHttpsMetadata;
                if (!string.IsNullOrWhiteSpace(customerOidc.MetadataAddress))
                {
                    options.MetadataAddress = customerOidc.MetadataAddress;
                }

                options.TokenValidationParameters = new TokenValidationParameters
                {
                    AuthenticationType = GatewayAuthPolicies.CustomerBearerScheme,
                    ValidateIssuer = !string.IsNullOrWhiteSpace(customerOidc.EffectiveIssuer),
                    ValidIssuer = customerOidc.EffectiveIssuer,
                    ValidateAudience = true,
                    ValidAudience = customerOidc.Audience,
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = customerStaticKey,
                    ValidateLifetime = true,
                    RequireExpirationTime = true,
                    RequireSignedTokens = true,
                    ValidAlgorithms = [SecurityAlgorithms.RsaSha256],
                    ClockSkew = TimeSpan.FromSeconds(customerOidc.ClockSkewSeconds),
                    NameClaimType = "sub",
                    RoleClaimType = "role"
                };
                options.Events = new JwtBearerEvents
                {
                    OnTokenValidated = async context =>
                    {
                        var subject = context.Principal?.FindFirst("sub")?.Value;
                        var tokenId = context.Principal?.FindFirst("jti")?.Value;
                        var role = context.Principal?.FindFirst("role")?.Value;
                        if (!Guid.TryParse(subject, out var subjectId) || subjectId == Guid.Empty ||
                            string.IsNullOrWhiteSpace(tokenId) ||
                            !string.Equals(role, "user", StringComparison.Ordinal))
                        {
                            context.Fail("CustomerBearer accepts valid RS256 customer ('user') tokens only.");
                            return;
                        }

                        var revocation = context.HttpContext.RequestServices.GetRequiredService<IGatewayTokenRevocation>();
                        if (await revocation.IsRevokedAsync(tokenId, context.HttpContext.RequestAborted))
                        {
                            context.Fail("Customer access token has been revoked.");
                        }
                    }
                };
            })
            .AddJwtBearer(GatewayAuthPolicies.AdminBearerScheme, options =>
            {
                options.MapInboundClaims = false;
                options.RequireHttpsMetadata = requireHttpsMetadata;
                if (!string.IsNullOrWhiteSpace(adminOidc.MetadataAddress))
                {
                    options.MetadataAddress = adminOidc.MetadataAddress;
                }

                options.TokenValidationParameters = new TokenValidationParameters
                {
                    AuthenticationType = GatewayAuthPolicies.AdminBearerScheme,
                    ValidateIssuer = !string.IsNullOrWhiteSpace(adminOidc.EffectiveIssuer),
                    ValidIssuer = adminOidc.EffectiveIssuer,
                    ValidateAudience = true,
                    ValidAudience = adminOidc.Audience,
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = adminStaticKey,
                    ValidateLifetime = true,
                    RequireExpirationTime = true,
                    RequireSignedTokens = true,
                    ValidAlgorithms = [SecurityAlgorithms.RsaSha256],
                    ClockSkew = TimeSpan.FromSeconds(adminOidc.ClockSkewSeconds),
                    NameClaimType = "sub",
                    RoleClaimType = "role"
                };
                options.Events = new JwtBearerEvents
                {
                    OnMessageReceived = context =>
                    {
                        var authHeader = context.Request.Headers.Authorization.ToString();
                        if (authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                        {
                            var headerToken = authHeader["Bearer ".Length..].Trim();
                            if (!string.IsNullOrEmpty(headerToken))
                            {
                                context.Token = headerToken;
                                context.HttpContext.Items[GatewayAuthPolicies.VerifiedAdminRawTokenItemKey] = headerToken;
                            }
                        }

                        return Task.CompletedTask;
                    },
                    OnTokenValidated = async context =>
                    {
                        var subject = context.Principal?.FindFirst("sub")?.Value;
                        var tokenId = context.Principal?.FindFirst("jti")?.Value;
                        var role = context.Principal?.FindFirst("role")?.Value;
                        if (!Guid.TryParse(subject, out var subjectId) || subjectId == Guid.Empty ||
                            string.IsNullOrWhiteSpace(tokenId) ||
                            !string.Equals(role, "admin", StringComparison.Ordinal))
                        {
                            context.HttpContext.Items.Remove(GatewayAuthPolicies.VerifiedAdminRawTokenItemKey);
                            context.Fail("AdminBearer accepts valid RS256 administrator ('admin') tokens only.");
                            return;
                        }

                        var revocation = context.HttpContext.RequestServices.GetRequiredService<IGatewayTokenRevocation>();
                        if (await revocation.IsAdminRevokedAsync(tokenId, context.HttpContext.RequestAborted))
                        {
                            context.HttpContext.Items.Remove(GatewayAuthPolicies.VerifiedAdminRawTokenItemKey);
                            context.Fail("Administrator access token has been revoked.");
                            return;
                        }

                        context.HttpContext.Items[GatewayAuthPolicies.VerifiedAdminTokenIdItemKey] = tokenId;
                    },
                    OnAuthenticationFailed = context =>
                    {
                        context.HttpContext.Items.Remove(GatewayAuthPolicies.VerifiedAdminRawTokenItemKey);
                        context.HttpContext.Items.Remove(GatewayAuthPolicies.VerifiedAdminTokenIdItemKey);
                        return Task.CompletedTask;
                    }
                };
            })
            .AddCookie(GatewayAuthPolicies.AdminBffCookieScheme, options =>
            {
                options.Cookie.Name = GatewayAuthPolicies.AdminBffCookieName;
                options.Cookie.HttpOnly = true;
                options.Cookie.SameSite = SameSiteMode.Lax;
                options.Cookie.SecurePolicy = cookieSecurePolicy;
                options.Cookie.Path = "/";
                options.ExpireTimeSpan = TimeSpan.FromHours(Math.Max(1, adminOidc.SessionHours));
                options.SlidingExpiration = false;

                options.Events = new CookieAuthenticationEvents
                {
                    OnValidatePrincipal = async context =>
                    {
                        var subject = context.Principal?.FindFirstValue("sub");
                        var role = context.Principal?.FindFirstValue("role");
                        if (!Guid.TryParse(subject, out var adminId) || adminId == Guid.Empty ||
                            !string.Equals(role, "admin", StringComparison.Ordinal))
                        {
                            context.RejectPrincipal();
                            return;
                        }

                        var method = context.HttpContext.Request.Method;
                        var isSafeMethod = HttpMethods.IsGet(method) ||
                                           HttpMethods.IsHead(method) ||
                                           HttpMethods.IsOptions(method);
                        if (!isSafeMethod && !GatewayAdminOidcSettings.HasValidCsrfContext(context.HttpContext))
                        {
                            context.HttpContext.Items[GatewayAuthPolicies.CsrfRejectedItemKey] = true;
                            context.RejectPrincipal();
                            return;
                        }

                        var accessToken = context.Properties.GetTokenValue("access_token");
                        var refreshToken = context.Properties.GetTokenValue("refresh_token");
                        var expiresAtRaw = context.Properties.GetTokenValue("expires_at");

                        if (string.IsNullOrWhiteSpace(accessToken))
                        {
                            context.RejectPrincipal();
                            return;
                        }

                        if (DateTimeOffset.TryParse(expiresAtRaw, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var expiresAt) &&
                            expiresAt <= DateTimeOffset.UtcNow.AddSeconds(60))
                        {
                            if (string.IsNullOrWhiteSpace(refreshToken))
                            {
                                context.RejectPrincipal();
                                return;
                            }

                            var refreshed = await TryRefreshAdminTokensAsync(
                                context.HttpContext,
                                adminOidc,
                                clusterFallback,
                                refreshToken);
                            if (refreshed is null)
                            {
                                context.RejectPrincipal();
                                return;
                            }

                            accessToken = refreshed.Value.AccessToken;
                            var updatedTokens = new List<AuthenticationToken>
                            {
                                new() { Name = "access_token", Value = refreshed.Value.AccessToken },
                                new() { Name = "refresh_token", Value = refreshed.Value.RefreshToken },
                                new() { Name = "expires_at", Value = refreshed.Value.ExpiresAt.ToString("o", CultureInfo.InvariantCulture) }
                            };
                            if (!string.IsNullOrWhiteSpace(refreshed.Value.IdToken))
                            {
                                updatedTokens.Add(new AuthenticationToken { Name = "id_token", Value = refreshed.Value.IdToken });
                            }

                            context.Properties.StoreTokens(updatedTokens);
                            context.ShouldRenew = true;
                        }

                        var handler = new JwtSecurityTokenHandler();
                        if (!handler.CanReadToken(accessToken))
                        {
                            context.RejectPrincipal();
                            return;
                        }

                        var jwt = handler.ReadJwtToken(accessToken);
                        if (string.IsNullOrWhiteSpace(jwt.Id))
                        {
                            context.RejectPrincipal();
                            return;
                        }

                        var revocation = context.HttpContext.RequestServices.GetRequiredService<IGatewayTokenRevocation>();
                        if (await revocation.IsAdminRevokedAsync(jwt.Id, context.HttpContext.RequestAborted))
                        {
                            context.RejectPrincipal();
                            await context.HttpContext.SignOutAsync(GatewayAuthPolicies.AdminBffCookieScheme);
                            return;
                        }

                        context.HttpContext.Items[GatewayAuthPolicies.VerifiedAdminRawTokenItemKey] = accessToken;
                        context.HttpContext.Items[GatewayAuthPolicies.VerifiedAdminTokenIdItemKey] = jwt.Id;
                    }
                };
            })
            .AddOpenIdConnect(GatewayAuthPolicies.AdminOidcScheme, options =>
            {
                options.SignInScheme = GatewayAuthPolicies.AdminBffCookieScheme;
                options.RequireHttpsMetadata = requireHttpsMetadata;
                options.ClientId = adminOidc.BffClientId;
                options.ClientSecret = adminOidc.BffClientSecret;
                options.ResponseType = OpenIdConnectResponseType.Code;
                // Use standard OAuth 2.1 query redirect (302 Found -> /signin-oidc?code=...&state=...)
                // rather than ASP.NET Core's default form_post HTML page, whose inline onload JS is blocked by CSP script-src 'self'.
                options.ResponseMode = OpenIdConnectResponseMode.Query;
                options.UsePkce = true;
                options.SaveTokens = true;
                options.GetClaimsFromUserInfoEndpoint = false;
                options.MapInboundClaims = false;
                options.CallbackPath = "/signin-oidc";
                options.SignedOutCallbackPath = "/signout-callback-oidc";

                options.CorrelationCookie.Name = GatewayAuthPolicies.AdminOidcCorrelationCookiePrefix;
                options.CorrelationCookie.HttpOnly = true;
                options.CorrelationCookie.SameSite = SameSiteMode.Lax;
                options.CorrelationCookie.SecurePolicy = cookieSecurePolicy;

                options.NonceCookie.Name = GatewayAuthPolicies.AdminOidcNonceCookiePrefix;
                options.NonceCookie.HttpOnly = true;
                options.NonceCookie.SameSite = SameSiteMode.Lax;
                options.NonceCookie.SecurePolicy = cookieSecurePolicy;

                options.Scope.Clear();
                options.Scope.Add("openid");
                options.Scope.Add("email");
                options.Scope.Add("profile");
                options.Scope.Add("roles");
                options.Scope.Add("offline_access");
                options.Scope.Add(adminOidc.Audience);

                if (!string.IsNullOrWhiteSpace(adminOidc.MetadataAddress))
                {
                    options.MetadataAddress = adminOidc.MetadataAddress;
                }
                else
                {
                    var fallbackIssuer = adminOidc.EffectiveIssuer ?? "https://admin-identity.davids.local/";
                    options.Configuration = new OpenIdConnectConfiguration
                    {
                        Issuer = fallbackIssuer,
                        AuthorizationEndpoint = adminOidc.PublicAuthorizeEndpoint,
                        TokenEndpoint = adminOidc.ResolveTokenEndpoint(clusterFallback)
                    };
                    if (adminStaticKey is not null)
                    {
                        options.Configuration.SigningKeys.Add(adminStaticKey);
                    }
                }

                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = !string.IsNullOrWhiteSpace(adminOidc.EffectiveIssuer),
                    ValidIssuer = adminOidc.EffectiveIssuer,
                    ValidateAudience = true,
                    ValidAudience = adminOidc.BffClientId,
                    ValidateLifetime = true,
                    ValidAlgorithms = [SecurityAlgorithms.RsaSha256],
                    NameClaimType = "sub",
                    RoleClaimType = "role"
                };

                options.Events = new OpenIdConnectEvents
                {
                    OnRedirectToIdentityProvider = context =>
                    {
                        if (!string.IsNullOrWhiteSpace(adminOidc.PublicAuthorizeEndpoint))
                        {
                            context.ProtocolMessage.IssuerAddress =
                                adminOidc.PublicAuthorizeEndpoint.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                                adminOidc.PublicAuthorizeEndpoint.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
                                    ? adminOidc.PublicAuthorizeEndpoint
                                    : $"{context.Request.Scheme}://{context.Request.Host}{adminOidc.PublicAuthorizeEndpoint}";
                        }

                        return Task.CompletedTask;
                    },
                    OnTokenValidated = context =>
                    {
                        var auditLogger = context.HttpContext.RequestServices
                            .GetRequiredService<Microsoft.Extensions.Logging.ILoggerFactory>()
                            .CreateLogger("Davids.Security.Audit");
                        var clientIp = ResolveNormalizedIp(context.HttpContext);
                        var correlationId = context.HttpContext.TraceIdentifier;
                        var sub = context.Principal?.FindFirstValue("sub");
                        var role = context.Principal?.FindFirstValue("role");
                        if (!Guid.TryParse(sub, out var adminId) || adminId == Guid.Empty ||
                            !string.Equals(role, "admin", StringComparison.Ordinal))
                        {
                            auditLogger.LogWarning(
                                "Audit: rejected BFF OIDC callback without valid admin identity from {ClientIp} (CorrelationId={CorrelationId}).",
                                clientIp,
                                correlationId);
                            context.Fail("OIDC ID token did not carry a valid administrator identity.");
                            return Task.CompletedTask;
                        }

                        var normalizedClaims = context.Principal!.Claims.ToList();
                        var bffIdentity = new ClaimsIdentity(
                            normalizedClaims,
                            GatewayAuthPolicies.AdminBffCookieScheme,
                            "sub",
                            "role");
                        context.Principal = new ClaimsPrincipal(bffIdentity);
                        auditLogger.LogInformation(
                            "Audit: established administrator BFF OIDC session for {AdminId} from {ClientIp} (CorrelationId={CorrelationId}).",
                            adminId,
                            clientIp,
                            correlationId);
                        return Task.CompletedTask;
                    },
                    OnRemoteFailure = context =>
                    {
                        var auditLogger = context.HttpContext.RequestServices
                            .GetRequiredService<Microsoft.Extensions.Logging.ILoggerFactory>()
                            .CreateLogger("Davids.Security.Audit");
                        auditLogger.LogWarning(
                            context.Failure,
                            "Audit: administrator BFF OIDC callback failed from {ClientIp} (CorrelationId={CorrelationId}).",
                            ResolveNormalizedIp(context.HttpContext),
                            context.HttpContext.TraceIdentifier);
                        context.Response.Redirect("/login?error=oidc_failed");
                        context.HandleResponse();
                        return Task.CompletedTask;
                    }
                };
            });

        services.AddSingleton<IAuthorizationHandler, AdminOnlyAuthorizationHandler>();
        services.AddSingleton<IAuthorizationHandler, CustomerOnlyAuthorizationHandler>();
        services.AddSingleton<IAuthorizationHandler, ResourceOwnerOrAdminHandler>();
        services.AddSingleton<IAuthorizationMiddlewareResultHandler, GatewayAuthorizationResultHandler>();

        services.AddAuthorization(options =>
        {
            options.FallbackPolicy = new AuthorizationPolicyBuilder(
                    GatewayAuthPolicies.CustomerBearerScheme,
                    GatewayAuthPolicies.AdminBearerScheme,
                    GatewayAuthPolicies.AdminBffCookieScheme)
                .RequireAuthenticatedUser()
                .Build();

            options.AddPolicy(GatewayAuthPolicies.Authenticated, policy =>
                policy.AddAuthenticationSchemes(
                        GatewayAuthPolicies.CustomerBearerScheme,
                        GatewayAuthPolicies.AdminBearerScheme,
                        GatewayAuthPolicies.AdminBffCookieScheme)
                    .RequireAuthenticatedUser());

            options.AddPolicy(GatewayAuthPolicies.CustomerAuthenticated, policy =>
                policy.AddAuthenticationSchemes(
                        GatewayAuthPolicies.CustomerBearerScheme,
                        GatewayAuthPolicies.AdminBearerScheme,
                        GatewayAuthPolicies.AdminBffCookieScheme)
                    .RequireAuthenticatedUser()
                    .AddRequirements(new CustomerOnlyRequirement()));

            options.AddPolicy(GatewayAuthPolicies.CustomersAdmin, policy =>
                policy.AddAuthenticationSchemes(
                        GatewayAuthPolicies.AdminBearerScheme,
                        GatewayAuthPolicies.AdminBffCookieScheme,
                        GatewayAuthPolicies.CustomerBearerScheme)
                    .RequireAuthenticatedUser()
                    .AddRequirements(new AdminOnlyRequirement()));

            options.AddPolicy(GatewayAuthPolicies.AdminFrontend, policy =>
                policy.AddAuthenticationSchemes(
                        GatewayAuthPolicies.AdminBearerScheme,
                        GatewayAuthPolicies.AdminBffCookieScheme,
                        GatewayAuthPolicies.CustomerBearerScheme)
                    .RequireAuthenticatedUser()
                    .AddRequirements(new AdminOnlyRequirement()));

            options.AddPolicy(GatewayAuthPolicies.ResourceOwnerOrAdmin, policy =>
                policy.AddAuthenticationSchemes(
                        GatewayAuthPolicies.CustomerBearerScheme,
                        GatewayAuthPolicies.AdminBearerScheme,
                        GatewayAuthPolicies.AdminBffCookieScheme)
                    .RequireAuthenticatedUser()
                    .AddRequirements(new ResourceOwnerOrAdminRequirement()));
        });

        return services;
    }

    private readonly record struct RefreshedTokenSet(
        string AccessToken,
        string RefreshToken,
        string? IdToken,
        DateTimeOffset ExpiresAt);

    private static async Task<RefreshedTokenSet?> TryRefreshAdminTokensAsync(
        HttpContext httpContext,
        GatewayAdminOidcSettings adminOidc,
        IConfigurationFallbackCluster clusterFallback,
        string refreshToken)
    {
        try
        {
            var factory = httpContext.RequestServices.GetRequiredService<IHttpClientFactory>();
            var client = factory.CreateClient(GatewayAuthPolicies.BackchannelHttpClientName);
            using var response = await client.PostAsync(
                adminOidc.ResolveTokenEndpoint(clusterFallback),
                new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["grant_type"] = "refresh_token",
                    ["client_id"] = adminOidc.BffClientId,
                    ["client_secret"] = adminOidc.BffClientSecret,
                    ["refresh_token"] = refreshToken
                }),
                httpContext.RequestAborted);

            if (!response.IsSuccessStatusCode)
            {
                return null;
            }

            using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync(httpContext.RequestAborted));
            var root = doc.RootElement;
            var newAccess = root.GetProperty("access_token").GetString();
            var newRefresh = root.TryGetProperty("refresh_token", out var rt) ? rt.GetString() : refreshToken;
            var newId = root.TryGetProperty("id_token", out var idt) ? idt.GetString() : null;
            var expiresIn = root.TryGetProperty("expires_in", out var exp) ? exp.GetInt32() : 900;

            if (string.IsNullOrWhiteSpace(newAccess) || string.IsNullOrWhiteSpace(newRefresh))
            {
                return null;
            }

            return new RefreshedTokenSet(
                newAccess,
                newRefresh,
                newId,
                DateTimeOffset.UtcNow.AddSeconds(Math.Max(60, expiresIn)));
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return null;
        }
    }

    private static void AddGatewayRateLimiting(IServiceCollection services, IConfiguration configuration)
    {
        var windowSeconds = Math.Max(1, configuration.GetValue("RateLimiting:WindowSeconds", 60));
        var adminAuthLimit = Math.Max(1, configuration.GetValue("RateLimiting:AdminAuthPermitLimit", 10));
        var customerAuthLimit = Math.Max(1, configuration.GetValue("RateLimiting:CustomerAuthPermitLimit", 30));
        var apiLimit = Math.Max(1, configuration.GetValue("RateLimiting:ApiPermitLimit", 120));
        var window = TimeSpan.FromSeconds(windowSeconds);

        static string ResolveClientKey(HttpContext context, string scope)
        {
            var ip = context.Connection.RemoteIpAddress;
            var normalizedIp = ip is null
                ? "unknown"
                : (ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4().ToString() : ip.ToString());
            return $"{scope}:{normalizedIp}";
        }

        services.AddRateLimiter(options =>
        {
            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            options.OnRejected = async (rejectedContext, cancellationToken) =>
            {
                GatewaySecurityMetrics.RecordRateLimitRejection("gateway");
                rejectedContext.HttpContext.RequestServices
                    .GetRequiredService<Microsoft.Extensions.Logging.ILoggerFactory>()
                    .CreateLogger("Davids.Security.Audit")
                    .LogWarning(
                        "Audit: gateway rate-limit rejected request from {ClientIp} on {Path} (SecurityAuditEvent={SecurityAuditEvent}, CorrelationId={CorrelationId}).",
                        ResolveNormalizedIp(rejectedContext.HttpContext),
                        rejectedContext.HttpContext.Request.Path.Value,
                        "RateLimitRejected",
                        rejectedContext.HttpContext.TraceIdentifier);

                rejectedContext.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;
                rejectedContext.HttpContext.Response.Headers.CacheControl = "no-store";
                if (rejectedContext.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter))
                {
                    var seconds = Math.Max(1, (int)Math.Ceiling(retryAfter.TotalSeconds));
                    rejectedContext.HttpContext.Response.Headers.RetryAfter =
                        seconds.ToString(CultureInfo.InvariantCulture);
                }

                await rejectedContext.HttpContext.Response.WriteAsJsonAsync(new
                {
                    code = "rate_limit_exceeded",
                    reason = "Too many requests. Please try again later."
                }, cancellationToken);
            };

            options.AddPolicy(GatewayAuthPolicies.GatewayAdminAuthRateLimitPolicy, context =>
                RateLimitPartition.GetFixedWindowLimiter(
                    ResolveClientKey(context, GatewayAuthPolicies.GatewayAdminAuthRateLimitPolicy),
                    _ => new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = adminAuthLimit,
                        Window = window,
                        QueueLimit = 0
                    }));

            options.AddPolicy(GatewayAuthPolicies.GatewayCustomerAuthRateLimitPolicy, context =>
                RateLimitPartition.GetFixedWindowLimiter(
                    ResolveClientKey(context, GatewayAuthPolicies.GatewayCustomerAuthRateLimitPolicy),
                    _ => new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = customerAuthLimit,
                        Window = window,
                        QueueLimit = 0
                    }));

            options.AddPolicy(GatewayAuthPolicies.GatewayApiRateLimitPolicy, context =>
                RateLimitPartition.GetFixedWindowLimiter(
                    ResolveClientKey(context, GatewayAuthPolicies.GatewayApiRateLimitPolicy),
                    _ => new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = apiLimit,
                        Window = window,
                        QueueLimit = 0
                    }));
        });
    }

    internal static string ResolveNormalizedIp(HttpContext context)
    {
        var ip = context.Connection.RemoteIpAddress;
        return ip is null
            ? "unknown"
            : (ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4().ToString() : ip.ToString());
    }
}
