namespace LetsCrypt.Services.Models;

internal class CertificateTargetUnifi : CertificateTargetBase
{
    public string KeyToolPath { get; set; } = "C:\\Program Files\\Java\\jre1.8.0_261\\bin\\keytool.exe";

    public string UnifiPath { get; set; } = "C:\\Ubiquiti UniFi";
}
