namespace LetsCrypt.Services.Models;

internal class CertificateTargetHomeAssistant : CertificateTargetBase
{
    public string SharedFolder { get; set; } = "\\ssl";

    public string Username { get; set; } = "HomeAssistant";

    public string Password { get; set; } = "";

    public string PrivateKeyPath { get; set; } = "\\ssl\\privkey.pem";

    public string FullChainPath { get; set; } = "\\ssl\\fullchain.pem";
}
