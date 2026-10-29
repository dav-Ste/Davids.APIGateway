using Microsoft.Extensions.Logging;
using StackExchange.Redis;

namespace Davids.APIGateway.Infrastructure.Auth;

public interface IGatewayTokenRevocation
{
    Task<bool> IsRevokedAsync(string tokenId, CancellationToken cancellationToken = default);
    Task<bool> IsAdminRevokedAsync(string tokenId, CancellationToken cancellationToken = default)
        => IsRevokedAsync(tokenId, cancellationToken);
}

public sealed class NoGatewayTokenRevocation : IGatewayTokenRevocation
{
    public Task<bool> IsRevokedAsync(string tokenId, CancellationToken cancellationToken = default)
        => Task.FromResult(string.IsNullOrWhiteSpace(tokenId));

    public Task<bool> IsAdminRevokedAsync(string tokenId, CancellationToken cancellationToken = default)
        => Task.FromResult(string.IsNullOrWhiteSpace(tokenId));
}

public sealed class RedisGatewayTokenRevocation(
    IConnectionMultiplexer redis,
    ILogger<RedisGatewayTokenRevocation> logger) : IGatewayTokenRevocation
{
    private const string CustomerPrefix = "davids:identity:revoked:";
    private const string AdminPrefix = "davids:admin-identity:revoked:";

    public Task<bool> IsRevokedAsync(string tokenId, CancellationToken cancellationToken = default)
        => CheckPrefixAsync(CustomerPrefix, tokenId);

    public Task<bool> IsAdminRevokedAsync(string tokenId, CancellationToken cancellationToken = default)
        => CheckPrefixAsync(AdminPrefix, tokenId);

    private async Task<bool> CheckPrefixAsync(string prefix, string tokenId)
    {
        if (string.IsNullOrWhiteSpace(tokenId))
        {
            return true;
        }

        try
        {
            return await redis.GetDatabase().KeyExistsAsync(prefix + tokenId);
        }
        catch (RedisException exception)
        {
            logger.LogWarning(
                exception,
                "Redis unavailable at API Gateway; continuing to downstream service validation.");
            return false;
        }
    }
}
