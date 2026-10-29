using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Davids.APIGateway.Infrastructure.Auth;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.IdentityModel.Tokens;

namespace Davids.APIGateway.Tests;

internal static class GatewayTestSecurity
{
    public const string CustomerIssuer = "https://identity.davids.test/";
    public const string CustomerAudience = "davids-services";

    public const string AdminIssuer = "https://admin-identity.davids.test/";
    public const string AdminAudience = "davids-admin";
    public const string BffClientId = "davids-admin-bff";
    public const string BffClientSecret = "gateway-test-admin-bff-secret-at-least-24-chars!";

    public static readonly RSA CustomerRsa = RSA.Create(2048);
    public static readonly RSA AdminRsa = RSA.Create(2048);

    public static readonly string CustomerPublicKeyPem = CustomerRsa.ExportSubjectPublicKeyInfoPem();
    public static readonly string AdminPublicKeyPem = AdminRsa.ExportSubjectPublicKeyInfoPem();

    public static readonly RsaSecurityKey CustomerPrivateKey = CreateSigningKey(CustomerRsa);
    public static readonly RsaSecurityKey AdminPrivateKey = CreateSigningKey(AdminRsa);

    public static WebApplicationFactory<Program> CreateGatewayFactory(
        string backendDestination,
        string frontendDestination = "http://127.0.0.1:9/",
        IGatewayTokenRevocation revocation = null,
        string identityDestination = null,
        string adminIdentityDestination = null,
        string customersDestination = null,
        string adminAuthority = null,
        Action<IServiceCollection> configureServices = null)
    {
        return new WebApplicationFactory<Program>().WithWebHostBuilder(webHost =>
        {
            webHost.UseEnvironment("Testing");
            webHost.UseSetting("CustomerOidc:Issuer", CustomerIssuer);
            webHost.UseSetting("CustomerOidc:Audience", CustomerAudience);
            webHost.UseSetting("CustomerOidc:PublicKeyPem", CustomerPublicKeyPem);

            if (!string.IsNullOrWhiteSpace(adminAuthority))
            {
                webHost.UseSetting("AdminOidc:Authority", adminAuthority);
                webHost.UseSetting("AdminOidc:Issuer", adminAuthority.TrimEnd('/') + "/");
            }
            else
            {
                webHost.UseSetting("AdminOidc:Issuer", AdminIssuer);
                webHost.UseSetting("AdminOidc:PublicKeyPem", AdminPublicKeyPem);
            }

            webHost.UseSetting("AdminOidc:Audience", AdminAudience);
            webHost.UseSetting("AdminOidc:BffClientId", BffClientId);
            webHost.UseSetting("AdminOidc:BffClientSecret", BffClientSecret);
            webHost.UseSetting("Redis:Enabled", "false");
            webHost.UseSetting("Vault:Enabled", "false");

            webHost.UseSetting(
                "ReverseProxy:Clusters:identity:Destinations:primary:Address",
                identityDestination ?? backendDestination);
            webHost.UseSetting(
                "ReverseProxy:Clusters:admin-identity:Destinations:primary:Address",
                adminIdentityDestination ?? backendDestination);
            webHost.UseSetting(
                "ReverseProxy:Clusters:customers:Destinations:primary:Address",
                customersDestination ?? backendDestination);
            webHost.UseSetting(
                "ReverseProxy:Clusters:frontend-admin:Destinations:primary:Address",
                frontendDestination);

            webHost.ConfigureServices(services =>
            {
                if (revocation is not null)
                {
                    services.RemoveAll<IGatewayTokenRevocation>();
                    services.AddSingleton(revocation);
                }

                configureServices?.Invoke(services);
            });
        });
    }

    public static string CreateTokenForRole(Guid subject, string role = "user", string tokenId = null)
        => string.Equals(role, "admin", StringComparison.Ordinal)
            ? CreateAdminToken(subject, role, tokenId)
            : CreateCustomerToken(subject, role, tokenId);

    public static string CreateCustomerToken(
        Guid subject,
        string role = "user",
        string tokenId = null,
        RsaSecurityKey signingKey = null,
        string issuer = CustomerIssuer,
        string audience = CustomerAudience,
        DateTime? notBeforeUtc = null,
        DateTime? expiresUtc = null,
        bool includeTokenId = true,
        bool includeSubject = true)
    {
        return WriteToken(
            subject,
            role,
            tokenId,
            signingKey ?? CustomerPrivateKey,
            issuer,
            audience,
            notBeforeUtc,
            expiresUtc,
            includeTokenId,
            includeSubject);
    }

    public static string CreateAdminToken(
        Guid subject,
        string role = "admin",
        string tokenId = null,
        RsaSecurityKey signingKey = null,
        string issuer = AdminIssuer,
        string audience = AdminAudience,
        DateTime? notBeforeUtc = null,
        DateTime? expiresUtc = null,
        bool includeTokenId = true,
        bool includeSubject = true)
    {
        return WriteToken(
            subject,
            role,
            tokenId,
            signingKey ?? AdminPrivateKey,
            issuer,
            audience,
            notBeforeUtc,
            expiresUtc,
            includeTokenId,
            includeSubject);
    }

    public static string CreateAdminIdToken(
        Guid subject,
        string nonce,
        string issuer,
        string clientId = BffClientId,
        string email = "admin@davids.local",
        string fullName = "Root Admin")
    {
        var now = DateTime.UtcNow;
        var claims = new List<Claim>
        {
            new("sub", subject.ToString("N")),
            new("email", email),
            new("name", fullName),
            new("role", "admin"),
            new("iat", DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64)
        };
        if (!string.IsNullOrWhiteSpace(nonce))
        {
            claims.Add(new Claim("nonce", nonce));
        }

        var jwt = new JwtSecurityToken(
            issuer: issuer,
            audience: clientId,
            claims: claims,
            notBefore: now.AddSeconds(-5),
            expires: now.AddMinutes(15),
            signingCredentials: new SigningCredentials(AdminPrivateKey, SecurityAlgorithms.RsaSha256));

        return new JwtSecurityTokenHandler().WriteToken(jwt);
    }

    private static string WriteToken(
        Guid subject,
        string role,
        string tokenId,
        RsaSecurityKey signingKey,
        string issuer,
        string audience,
        DateTime? notBeforeUtc,
        DateTime? expiresUtc,
        bool includeTokenId,
        bool includeSubject)
    {
        var now = DateTime.UtcNow;
        var claims = new List<Claim>();
        if (includeSubject)
        {
            claims.Add(new Claim("sub", subject.ToString("N")));
        }

        if (!string.IsNullOrWhiteSpace(role))
        {
            claims.Add(new Claim("role", role));
        }

        if (includeTokenId)
        {
            claims.Add(new Claim("jti", tokenId ?? Guid.NewGuid().ToString("N")));
        }

        var token = new JwtSecurityToken(
            issuer: issuer,
            audience: audience,
            claims: claims,
            notBefore: notBeforeUtc ?? now.AddMinutes(-1),
            expires: expiresUtc ?? now.AddMinutes(30),
            signingCredentials: new SigningCredentials(signingKey, SecurityAlgorithms.RsaSha256));

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private static RsaSecurityKey CreateSigningKey(RSA rsa)
    {
        var kid = Base64UrlEncoder.Encode(SHA256.HashData(rsa.ExportSubjectPublicKeyInfo()))[..16];
        return new RsaSecurityKey(rsa.ExportParameters(includePrivateParameters: true)) { KeyId = kid };
    }
}
