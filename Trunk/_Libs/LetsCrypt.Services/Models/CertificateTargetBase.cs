namespace LetsCrypt.Services.Models;

internal class CertificateTargetBase
{
    public int Phase { get; set; } = 0;
    public bool Enabled { get; set; } = true;
    public string StoreName { get; set; } = "My";
}
