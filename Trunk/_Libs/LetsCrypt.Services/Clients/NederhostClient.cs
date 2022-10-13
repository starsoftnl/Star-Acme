using System.Text.Json;

namespace LetsCrypt.Services.Clients;

[HttpClientRegistration]
[ServiceAlias(typeof(IDnsHostingClient))]
internal class NederhostClient : IDnsHostingClient
{
    private readonly HttpClient HttpClient;
    private readonly ILogger<NederhostClient> Logger;
    private readonly IOptionsMonitor<NederhostOptions> OptionsMonitor;
    private readonly JsonSerializerOptions JsonOptions;

    public NederhostClient(HttpClient httpClient, ILogger<NederhostClient> logger, IOptionsMonitor<NederhostOptions> optionsMonitor)
    {
        Logger = logger;
        HttpClient = httpClient;
        OptionsMonitor = optionsMonitor;

        HttpClient.BaseAddress = new Uri(OptionsMonitor.CurrentValue.Url ?? "https://api.nederhost.nl/dns/v1/");
        HttpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", optionsMonitor.CurrentValue.ApiKey);

        JsonOptions = new JsonSerializerOptions();
        JsonOptions.DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingDefault;
        JsonOptions.PropertyNameCaseInsensitive = true;
        JsonOptions.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
    }

    public string ProviderName
        => "Nederhost";

    public async Task<DnsRecords> GetRecordsAsync(string zone, CancellationToken cancellationToken)
    {
        var result = await HttpClient.GetFromJsonAsync<DnsRecords>($"zones/{zone}/records", cancellationToken);
        if( result == null ) throw new Exception("Nederhost query returned null");

        return result;
    }

    public async Task SetRecordAsync(string zone, string name, string type, DnsValue[] values, CancellationToken cancellationToken)
    {
        try
        {
            var result = await HttpClient.PostAsJsonAsync($"zones/{zone}/records/{name}/{type}", values, JsonOptions, cancellationToken);
            result.EnsureSuccessStatusCode();
        }
        catch( Exception ex )
        {
            Logger.Error(ex, "Error setting Nederhost DNS record");
            throw;
        }
    }

    public async Task DeleteRecordAsync(string zone, string name, string type, CancellationToken cancellationToken)
    {
        try
        {
            var result = await HttpClient.DeleteAsync($"zones/{zone}/records/{name}/{type}", cancellationToken);
            result.EnsureSuccessStatusCode();
        }
        catch (Exception ex)
        {
            Logger.Error(ex, "Error deleting Nederhost DNS record");
            throw;
        }
    }
}
