using System.Text.Json;
using Microsoft.Extensions.Configuration;

namespace Davids.APIGateway.Infrastructure;

public static class VaultConfiguration
{
    // Davids.APIGateway validates RS256 tokens via public JWKS discovery and never loads signing keys from Vault.
    // Only the confidential OIDC BFF client secret, Redis connection string, and log-sink API keys are permitted.
    private static readonly HashSet<string> AllowedKeys = new(StringComparer.OrdinalIgnoreCase)
    {
        "AdminOidc:BffClientSecret",
        "DataProtection:MasterKey",
        "ConnectionStrings:cache",
        "LoggingSinks:Seq:ApiKey",
        "LoggingSinks:Elasticsearch:ApiKey"
    };

    public static async Task LoadVaultAsync(
        this ConfigurationManager configuration,
        CancellationToken cancellationToken = default)
    {
        if (!configuration.GetValue<bool>("Vault:Enabled"))
        {
            return;
        }

        var address = configuration["Vault:Address"]
            ?? throw new InvalidOperationException("Vault:Address is required when Vault is enabled.");
        var token = configuration["Vault:Token"];
        var tokenFile = configuration["Vault:TokenFile"];
        if (!string.IsNullOrWhiteSpace(tokenFile))
        {
            token = (await File.ReadAllTextAsync(tokenFile, cancellationToken)).Trim();
        }

        if (string.IsNullOrWhiteSpace(token))
        {
            throw new InvalidOperationException("Vault token or Vault Agent token file is required.");
        }

        var path = configuration["Vault:KvPath"] ?? "secret/data/davids/gateway";

        using var client = new HttpClient
        {
            BaseAddress = new Uri(address.TrimEnd('/') + "/"),
            Timeout = TimeSpan.FromSeconds(15)
        };
        client.DefaultRequestHeaders.Add("X-Vault-Token", token);

        using var response = await client.GetAsync("v1/" + path.TrimStart('/'), cancellationToken);
        response.EnsureSuccessStatusCode();
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken));
        var values = Flatten(document.RootElement.GetProperty("data").GetProperty("data"));
        var unsupported = values.Keys.FirstOrDefault(key => !AllowedKeys.Contains(key));
        if (unsupported is not null)
        {
            throw new InvalidOperationException($"Unsupported API Gateway Vault setting: {unsupported}");
        }

        configuration.AddInMemoryCollection(values);
    }

    public static Dictionary<string, string> Flatten(JsonElement root)
    {
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        void Visit(JsonElement element, string prefix)
        {
            if (element.ValueKind == JsonValueKind.Object)
            {
                foreach (var property in element.EnumerateObject())
                {
                    Visit(property.Value, string.IsNullOrEmpty(prefix) ? property.Name : prefix + ":" + property.Name);
                }
            }
            else if (element.ValueKind == JsonValueKind.String)
            {
                values[prefix] = element.GetString();
            }
            else
            {
                throw new InvalidOperationException("Vault settings must contain string leaves.");
            }
        }

        Visit(root, string.Empty);
        return values;
    }
}
