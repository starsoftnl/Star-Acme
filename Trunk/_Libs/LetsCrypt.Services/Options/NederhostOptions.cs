namespace LetsCrypt.Services.Options;

[OptionsRegistration("Nederhost")]
internal class NederhostOptions
{
    public string Url { get; set; } = "https://api.nederhost.nl/dns/v1";

    public string ApiKey { get; set; } = "";
}
