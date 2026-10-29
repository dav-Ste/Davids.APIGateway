namespace Davids.APIGateway.Infrastructure.Auth;

public static class GatewayAuthPolicies
{
    public const string CustomerBearerScheme = "CustomerBearer";
    public const string AdminBearerScheme = "AdminBearer";
    public const string AdminBffCookieScheme = "AdminBffCookie";
    public const string AdminOidcScheme = "AdminOidc";

    public const string Authenticated = "authenticated";
    public const string CustomerAuthenticated = "customer-authenticated";
    public const string CustomersAdmin = "customers-admin";
    public const string AdminFrontend = "admin-frontend";
    public const string ResourceOwnerOrAdmin = "resource-owner-or-admin";

    public const string AdminBffCookieName = "davids_admin_bff";
    public const string AdminOidcCorrelationCookiePrefix = "davids_oidc_corr.";
    public const string AdminOidcNonceCookiePrefix = "davids_oidc_nonce.";

    public const string AdminCsrfHeaderName = "X-Requested-With";
    public const string AdminCsrfHeaderValue = "DavidsAdmin";
    public const string VerifiedAdminRawTokenItemKey = "Davids.VerifiedAdminRawToken";
    public const string VerifiedAdminTokenIdItemKey = "Davids.VerifiedAdminTokenId";
    public const string CsrfRejectedItemKey = "Davids.CsrfRejected";
    public const string BackchannelHttpClientName = "AdminOidcBackchannel";

    public const string GatewayAdminAuthRateLimitPolicy = "gateway-admin-auth";
    public const string GatewayCustomerAuthRateLimitPolicy = "gateway-customer-auth";
    public const string GatewayApiRateLimitPolicy = "gateway-api";
}
