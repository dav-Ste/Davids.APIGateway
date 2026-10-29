using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.Extensions.Logging;
using StackExchange.Redis;

namespace Davids.APIGateway.Infrastructure.Auth;

public interface IGatewayDataProtectionStore
{
    IReadOnlyCollection<string> ReadAllXmlElements();
    void StoreXmlElement(string? friendlyName, string xml);
}

public sealed class RedisGatewayDataProtectionStore(
    IConnectionMultiplexer multiplexer,
    ILogger<RedisGatewayDataProtectionStore> logger) : IGatewayDataProtectionStore
{
    public const string RedisHashKey = "davids:gateway:dataprotection:keys";

    public IReadOnlyCollection<string> ReadAllXmlElements()
    {
        var values = multiplexer.GetDatabase().HashValues(RedisHashKey);
        var elements = new List<string>(values.Length);
        foreach (var value in values)
        {
            if (value.HasValue)
            {
                elements.Add(value.ToString());
            }
        }

        logger.LogDebug("Loaded {KeyCount} Data Protection key ring elements from Redis.", elements.Count);
        return elements;
    }

    public void StoreXmlElement(string? friendlyName, string xml)
    {
        var fieldName = string.IsNullOrWhiteSpace(friendlyName)
            ? "key-" + Guid.NewGuid().ToString("N")
            : friendlyName;
        multiplexer.GetDatabase().HashSet(RedisHashKey, fieldName, xml);
        logger.LogInformation("Persisted encrypted Gateway Data Protection key '{FriendlyName}' to Redis.", fieldName);
    }
}

public sealed class GatewayDataProtectionXmlRepository(IGatewayDataProtectionStore store) : IXmlRepository
{
    public IReadOnlyCollection<XElement> GetAllElements()
    {
        var raw = store.ReadAllXmlElements();
        var parsed = new List<XElement>(raw.Count);
        foreach (var xml in raw)
        {
            if (!string.IsNullOrWhiteSpace(xml))
            {
                parsed.Add(XElement.Parse(xml));
            }
        }

        return parsed.AsReadOnly();
    }

    public void StoreElement(XElement element, string? friendlyName)
    {
        ArgumentNullException.ThrowIfNull(element);
        store.StoreXmlElement(friendlyName, element.ToString(SaveOptions.DisableFormatting));
    }
}
