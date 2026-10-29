using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace Davids.APIGateway.Infrastructure.Auth;

public sealed class AdminOnlyRequirement : IAuthorizationRequirement;

public sealed class CustomerOnlyRequirement : IAuthorizationRequirement;

public sealed class ResourceOwnerOrAdminRequirement : IAuthorizationRequirement;

public static class GatewayIdentityPredicates
{
    public static bool IsVerifiedAdmin(System.Security.Claims.ClaimsPrincipal user)
        => user.Identities.Any(identity =>
            identity.IsAuthenticated &&
            (string.Equals(identity.AuthenticationType, GatewayAuthPolicies.AdminBearerScheme, StringComparison.Ordinal) ||
             string.Equals(identity.AuthenticationType, GatewayAuthPolicies.AdminBffCookieScheme, StringComparison.Ordinal)) &&
            identity.HasClaim("role", "admin"));
}

public sealed class AdminOnlyAuthorizationHandler : AuthorizationHandler<AdminOnlyRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        AdminOnlyRequirement requirement)
    {
        if (GatewayIdentityPredicates.IsVerifiedAdmin(context.User))
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }
}

public sealed class CustomerOnlyAuthorizationHandler : AuthorizationHandler<CustomerOnlyRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        CustomerOnlyRequirement requirement)
    {
        var hasCustomerIdentity = context.User.Identities.Any(identity =>
            identity.IsAuthenticated &&
            string.Equals(identity.AuthenticationType, GatewayAuthPolicies.CustomerBearerScheme, StringComparison.Ordinal) &&
            identity.HasClaim("role", "user"));

        if (hasCustomerIdentity)
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }
}

public sealed class ResourceOwnerOrAdminHandler : AuthorizationHandler<ResourceOwnerOrAdminRequirement>
{
    private static readonly string[] RouteOwnerKeys = ["userId", "customerId"];

    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        ResourceOwnerOrAdminRequirement requirement)
    {
        var isAdmin = GatewayIdentityPredicates.IsVerifiedAdmin(context.User);

        var httpContext = context.Resource switch
        {
            HttpContext direct => direct,
            IHttpContextAccessor accessor => accessor.HttpContext,
            _ => null
        };

        // Customer Identity (/identity/users/{userId}) is strictly customer-owned; admins only inspect /customers/{customerId}.
        if (isAdmin && (httpContext is null || !httpContext.Request.Path.StartsWithSegments("/identity")))
        {
            context.Succeed(requirement);
            return Task.CompletedTask;
        }

        if (httpContext is null)
        {
            return Task.CompletedTask;
        }

        var customerIdentity = context.User.Identities.FirstOrDefault(identity =>
            identity.IsAuthenticated &&
            string.Equals(identity.AuthenticationType, GatewayAuthPolicies.CustomerBearerScheme, StringComparison.Ordinal) &&
            identity.HasClaim("role", "user"));

        var subjectClaim = customerIdentity?.FindFirst("sub")?.Value;
        if (!Guid.TryParse(subjectClaim, out var subjectId) || subjectId == Guid.Empty)
        {
            return Task.CompletedTask;
        }

        foreach (var key in RouteOwnerKeys)
        {
            var rawValue = httpContext.GetRouteValue(key)?.ToString();
            if (string.IsNullOrWhiteSpace(rawValue))
            {
                continue;
            }

            if (Guid.TryParse(rawValue, out var targetId) && targetId == subjectId)
            {
                context.Succeed(requirement);
            }

            return Task.CompletedTask;
        }

        return Task.CompletedTask;
    }
}
