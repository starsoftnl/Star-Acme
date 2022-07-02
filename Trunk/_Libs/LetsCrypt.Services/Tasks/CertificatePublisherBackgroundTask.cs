using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

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
    private readonly IOptionsMonitor<CertificateOptions> CertificateOptions;

    public CertificatePublisherBackgroundTask(
        CertificateService certificateService,
        DeploymentService deploymentService,
        IOptionsMonitor<CertificateOptions> certificateOptions)
    {
        CertificateService = certificateService;
        DeploymentService = deploymentService;
        CertificateOptions = certificateOptions;
    }

    protected override async Task<TimeSpan?> RunTaskAsync(DateTimeOffset now, CancellationToken cancellationToken)
    {
        DateTimeOffset? next = null;

        foreach (var order in CertificateOptions.CurrentValue)
        {
            try
            {
                var pfx = await CertificateService.LoadCertificateAsync(order.Id, cancellationToken);
                var certificate = pfx == null ? null : new X509Certificate2(pfx, order.PfxPassword);

                LoggerContext.Set("Order", order.Id);
                LoggerContext.Set("Thumbprint", certificate?.Thumbprint);

                if (certificate != null && DateTimeOffset.Now > certificate.NotAfter - TimeSpan.FromDays(30))
                {
                    Logger.Information($"Existing certificate only has 30 days left. Removing it now");
                    CertificateService.DeleteOrder(order.Id);
                    CertificateService.DeleteCertificate(order.Id);
                    certificate = null;
                }

                if (certificate != null)
                {
                    if (next == null || certificate.NotAfter - TimeSpan.FromDays(30) < next.Value)
                        next = certificate.NotAfter - TimeSpan.FromDays(30);
                    Logger.Information($"Existing certificate is still valid. Recheck at {next}");
                    continue;
                }

                if (!await CertificateService.UpdateOrCreateCertificate(order, cancellationToken))
                {
                    if (next == null || next > now + TimeSpan.FromSeconds(10))
                        next = now + TimeSpan.FromSeconds(10);
                    continue;
                }

                pfx = await CertificateService.LoadCertificateAsync(order.Id, cancellationToken);
                certificate = pfx == null ? null : new X509Certificate2(pfx, order.PfxPassword);

                LoggerContext.Set("Thumbprint", certificate?.Thumbprint);

                if (certificate == null)
                {
                    if (next == null || next > now + TimeSpan.FromDays(1))
                        next = now + TimeSpan.FromDays(1);
                    continue;
                }

                if (next == null || certificate.NotAfter - TimeSpan.FromDays(30) < next.Value)
                    next = certificate.NotAfter - TimeSpan.FromDays(30);

                Logger.Information($"Got new certificate. Recheck at {next}");
            }
            catch ( Exception ex )
            {
                Logger.Error(ex, "Certificate Update Failed");

                if (next == null || next > now + TimeSpan.FromDays(1))
                    next = now + TimeSpan.FromDays(1);
            }
        }

        return await DeploymentService.DeployCertificatesAsync( now, next, cancellationToken ) - DateTimeOffset.Now;
    }
}
