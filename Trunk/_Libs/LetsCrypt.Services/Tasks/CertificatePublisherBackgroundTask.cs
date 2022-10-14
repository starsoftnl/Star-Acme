using LetsCrypt.Services.Services;

namespace LetsCrypt.Services.Tasks;

// https://lachlanbarclay.net/2022/01/updating-iis-certificates-with-powershell
// https://www.alitajran.com/install-exchange-certificate-with-powershell/
// https://serverfault.com/questions/444286/configure-custom-ssl-certificate-for-rdp-on-windows-server-2012-and-later-in-r
// https://www.google.com/search?q=get+thumbprint+from+pfx+c%23&oq=get+thumbprint+from+pfx+c%23&aqs=edge..69i57j0i546l4.12086j0j1&sourceid=chrome&ie=UTF-8
// https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509certificate2?view=net-6.0

internal class CertificatePublisherBackgroundTask : WorkerBackgroundTask
{
    private readonly CertificateService CertificateService;
    private readonly DeploymentService DeploymentService;
    private readonly IOptionsMonitor<CertificatesOptions> CertificateOptions;
    private readonly ILetsCryptMailService MailService;

    public CertificatePublisherBackgroundTask(
        ILetsCryptMailService mailService,
        CertificateService certificateService,
        DeploymentService deploymentService,
        IOptionsMonitor<CertificatesOptions> certificateOptions)
    {
        CertificateService = certificateService;
        DeploymentService = deploymentService;
        CertificateOptions = certificateOptions;
        MailService = mailService;

        certificateOptions.OnChange((o, n) =>Run());
    }

    protected override async Task<TimeSpan?> RunTaskAsync(DateTimeOffset now, CancellationToken cancellationToken)
    {
        DateTimeOffset? next = await DeploymentService.RunAsync(now, cancellationToken);
        return next - DateTimeOffset.Now;
    }
}
