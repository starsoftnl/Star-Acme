using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace LetsCrypt.Services.Services;

internal class DeploymentServiceWMSVC : DeploymentServiceBase
{
    public DeploymentServiceWMSVC(
        ILogger<DeploymentServiceWMSVC> logger,
        ILetsCryptMailService mailService,
        IOptionsMonitor<CertificatesOptions> certificateOptions,
        CertificateService certificateService)
        : base(logger, mailService, certificateOptions, certificateService)
    {
    }

    protected override void GetPhaseCount(out int min, out int max)
    {
        min = Target.WMSVC?.Phase ?? 0;
        max = Target.WMSVC?.Phase ?? 0;
    }

    protected override async Task<DateTimeOffset?> DeployCertificateAsync(CancellationToken cancellationToken)
    {
        if (Target.WMSVC?.Enabled != true || Target.WMSVC.Phase != Phase) return null;

        var next = await UpdateCertificateAsync(cancellationToken);

        await DeployCertificateAsync(Target.WMSVC, cancellationToken);

        return next;
    }

    private async Task DeployCertificateAsync(DeploymentTargetWMSVC wmsvc, CancellationToken cancellationToken)
    {
        if( !await CopyCertificateAsync(cancellationToken) ) return;

        LoggerContext.Set("StoreName", wmsvc.StoreName);
        LoggerContext.Set("Method", "WMSVC");

        await ImportCertificateAsync(wmsvc.StoreName, cancellationToken);

        var thumbprint = await GetThumbprintAsync(cancellationToken);

        Logger.Information("Bind certificate");

        var binary = string.Join(",", Enumerable.Range(0, thumbprint.Length / 2).Select(i => $"0x{thumbprint.Substring(i * 2, 2)}"));

        var script = new StringBuilder();
        script.AppendLine($"Set-ExecutionPolicy -ExecutionPolicy Unrestricted");
        script.AppendLine($"Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\WebManagement\\Server' -Name 'SslCertificateHash' -Value ([byte[]]({binary}))");
        script.AppendLine($"Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\WebManagement\\Server' -Name 'SelfSignedCertificateHash' -Value ([byte[]]({binary}))");
        await RunRemoteScriptAsync(script.ToString(), cancellationToken);

        await RestartServiceAsync("Web Management Service", cancellationToken);
    }
}
