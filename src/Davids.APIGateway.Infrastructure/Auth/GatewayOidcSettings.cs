using System.Security.Cryptography;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;

namespace Davids.APIGateway.Infrastructure.Auth;

public class GatewayOidcAuthoritySettings
{
    public string? Authority { get; set; }
    public string? Issuer { get; set; }
    public string Audience { get; set; } = "davids-services";
    public string? PublicKeyPem { get; set; }
    public int ClockSkewSeconds { get; set; } = 30;

    public string? MetadataAddress
        => string.IsNullOrWhiteSpace(Authority)
            ? null
            : Authority.TrimEnd('/') + "/.well-known/openid-configuration";

    public string? EffectiveIssuer
    {
        get
        {
            var candidate = !string.IsNullOrWhiteSpace(Issuer) ? Issuer : Authority;
            return string.IsNullOrWhiteSpace(candidate) ? null : candidate.TrimEnd('/') + "/";
        }
    }

    public RsaSecurityKey? ValidateAndResolveStaticPublicKey(string sectionName)
    {
        if (string.IsNullOrWhiteSpace(Audience) || ClockSkewSeconds < 0 || ClockSkewSeconds > 300)
        {
            throw new InvalidOperationException($"Invalid {sectionName} validation configuration at API Gateway.");
        }

        var hasAuthority = !string.IsNullOrWhiteSpace(Authority);
        var hasPublicKey = !string.IsNullOrWhiteSpace(PublicKeyPem);
        if (!hasAuthority && !hasPublicKey)
        {
            throw new InvalidOperationException(
                $"{sectionName}:Authority (OIDC discovery URL) or {sectionName}:PublicKeyPem (RSA public key) is required.");
        }

        if (hasAuthority &&
            (!Uri.TryCreate(Authority, UriKind.Absolute, out var authorityUri) ||
             (authorityUri.Scheme != Uri.UriSchemeHttp && authorityUri.Scheme != Uri.UriSchemeHttps)))
        {
            throw new InvalidOperationException($"{sectionName}:Authority must be an absolute HTTP(S) URI.");
        }

        if (!hasPublicKey)
        {
            return null;
        }

        var trimmed = PublicKeyPem!.Trim();
        if (trimmed.Contains("PRIVATE KEY", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                $"{sectionName}:PublicKeyPem must be an RSA PUBLIC key only; Davids.APIGateway never holds signing private keys.");
        }

        using var rsa = RSA.Create();
        try
        {
            rsa.ImportFromPem(trimmed);
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException)
        {
            throw new InvalidOperationException($"{sectionName}:PublicKeyPem is not a valid PEM RSA public key.", ex);
        }

        if (rsa.KeySize < 2048)
        {
            throw new InvalidOperationException($"{sectionName}:PublicKeyPem must be at least 2048 bits.");
        }

        var parameters = rsa.ExportParameters(includePrivateParameters: false);
        var kid = Base64UrlEncoder.Encode(SHA256.HashData(rsa.ExportSubjectPublicKeyInfo()))[..16];
        return new RsaSecurityKey(parameters) { KeyId = kid };
    }
}

public sealed class GatewayAdminOidcSettings : GatewayOidcAuthoritySettings
{
    public GatewayAdminOidcSettings()
    {
        Audience = "davids-admin";
    }

    public string BffClientId { get; set; } = "davids-admin-bff";
    public string BffClientSecret { get; set; } = string.Empty;
    public string PublicAuthorizeEndpoint { get; set; } = "/admin-identity/connect/authorize";
    public int SessionHours { get; set; } = 8;

    public RsaSecurityKey? ValidateAdminSettings(string? customerPublicKeyPem)
    {
        var key = ValidateAndResolveStaticPublicKey("AdminOidc");
        if (string.IsNullOrWhiteSpace(BffClientId))
        {
            throw new InvalidOperationException("AdminOidc:BffClientId is required.");
        }

        if (string.IsNullOrWhiteSpace(BffClientSecret) || BffClientSecret.Length < 24)
        {
            throw new InvalidOperationException(
                "AdminOidc:BffClientSecret must be at least 24 characters (configure via user-secrets or Vault).");
        }

        if (!string.IsNullOrWhiteSpace(PublicKeyPem) &&
            !string.IsNullOrWhiteSpace(customerPublicKeyPem) &&
            string.Equals(PublicKeyPem.Trim(), customerPublicKeyPem.Trim(), StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "AdminOidc:PublicKeyPem must be distinct from CustomerOidc:PublicKeyPem.");
        }

        if (!string.IsNullOrWhiteSpace(EffectiveIssuer) &&
            string.Equals(EffectiveIssuer, "https://identity.davids.local/", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "AdminOidc:Issuer must be distinct from CustomerOidc:Issuer.");
        }

        return key;
    }

    public string ResolveTokenEndpoint(IConfigurationFallbackCluster clusterFallback)
    {
        var baseUrl = !string.IsNullOrWhiteSpace(Authority) ? Authority : clusterFallback.AdminIdentityClusterAddress;
        return baseUrl.TrimEnd('/') + "/connect/token";
    }

    public string ResolveRevocationEndpoint(IConfigurationFallbackCluster clusterFallback)
    {
        var baseUrl = !string.IsNullOrWhiteSpace(Authority) ? Authority : clusterFallback.AdminIdentityClusterAddress;
        return baseUrl.TrimEnd('/') + "/connect/revocation";
    }

    public static bool HasValidCsrfContext(HttpContext context)
    {
        if (!string.Equals(
                context.Request.Headers[GatewayAuthPolicies.AdminCsrfHeaderName].ToString(),
                GatewayAuthPolicies.AdminCsrfHeaderValue,
                StringComparison.Ordinal))
        {
            return false;
        }

        var origin = context.Request.Headers.Origin.ToString();
        if (!string.IsNullOrWhiteSpace(origin))
        {
            var expectedOrigin = $"{context.Request.Scheme}://{context.Request.Host}";
            if (!string.Equals(origin, expectedOrigin, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
        }

        return true;
    }
}

public sealed record IConfigurationFallbackCluster(string AdminIdentityClusterAddress);
