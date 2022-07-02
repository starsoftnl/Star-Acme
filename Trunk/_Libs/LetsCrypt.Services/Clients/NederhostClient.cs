using System.Text.Json;

namespace LetsCrypt.Services.Clients;

[HttpClientRegistration]
internal class NederhostClient
{
    private readonly HttpClient HttpClient;
    private readonly IOptionsMonitor<NederhostOptions> OptionsMonitor;
    private readonly JsonSerializerOptions JsonOptions;

    public NederhostClient(HttpClient httpClient, IOptionsMonitor<NederhostOptions> optionsMonitor)
    {
        HttpClient = httpClient;
        OptionsMonitor = optionsMonitor;

        HttpClient.BaseAddress = new Uri(optionsMonitor.CurrentValue.Url ?? "https://api.nederhost.nl/dns/v1/");
        HttpClient.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", optionsMonitor.CurrentValue.ApiKey);

        JsonOptions = new JsonSerializerOptions();
        JsonOptions.DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingDefault;
        JsonOptions.PropertyNameCaseInsensitive = true;
        JsonOptions.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
    }

    public async Task<DnsRecords> GetRecordsAsync( string zone, CancellationToken cancellationToken)
        => await HttpClient.GetFromJsonAsync<DnsRecords>($"zones/{zone}/records", cancellationToken) ?? throw new Exception("Nederhost query returned null");

    public async Task SetRecordAsync(string zone, string name, string type, DnsValue[] values, CancellationToken cancellationToken)
        => await HttpClient.PostAsJsonAsync($"zones/{zone}/records/{name}/{type}", values, JsonOptions, cancellationToken);

    public async Task DeleteRecordAsync(string zone, string name, string type, CancellationToken cancellationToken)
        => await HttpClient.DeleteAsync($"zones/{zone}/records/{name}/{type}", cancellationToken);
}
