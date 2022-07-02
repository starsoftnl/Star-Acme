namespace LetsCrypt.Services.Models;

internal class CertificateTargetBase
{
    public bool Enabled { get; set; } = true;
    public string StoreName { get; set; } = "My";
}
