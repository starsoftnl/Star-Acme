namespace LetsCrypt.Services.Options;

[OptionsRegistration("Certificates")]
internal class CertificatesOptions : Dictionary<string,CertificateOptions>
{
}
