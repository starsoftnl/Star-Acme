namespace LetsCrypt.Services.Options;

[OptionsRegistration("Acme")]
internal class AcmeOptions
{
    public string? Url { get; set; }

    public string[] EMailAddresses { get; set; } 
        = Array.Empty<string>();
}
