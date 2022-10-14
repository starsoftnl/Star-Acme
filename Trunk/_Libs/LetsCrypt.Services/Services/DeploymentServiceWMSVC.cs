using System.Net;
using System.Security.Cryptography.X509Certificates;

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
        var pfx = await CopyCertificateAsync(cancellationToken);
        if (pfx == null) return;

        LoggerContext.Set("StoreName", wmsvc.StoreName);
        LoggerContext.Set("Method", "WMSVC");

        await ImportCertificateAsync(wmsvc.StoreName, cancellationToken);

        var filePathLocal = GetLocalCertificatePath();
        var certificate = new X509Certificate2(pfx, PfxPassword);
        var thumbprint = certificate.Thumbprint;

        Logger.Information("Bind certificate");

        await RemoteAsync(async remote =>
        {
            string[] result;
            result = await remote.ExecuteAsync(shell => shell
                .AddCommand("Set-ExecutionPolicy")
                .AddArgument("Unrestricted"));

            result = await remote.ExecuteAsync(shell => shell
                .AddCommand("Stop-Service")
                .AddArgument("WMSVC"));

            var binary = string.Join(",", Enumerable.Range(0, certificate.Thumbprint.Length / 2).Select(i => $"0x{certificate.Thumbprint.Substring(i * 2, 2)}"));

            result = await remote.ExecuteAsync(shell => shell
                .AddScript($"Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\WebManagement\\Server' -Name 'SslCertificateHash' -Value ([byte[]]({binary}))"));

            result = await remote.ExecuteAsync(shell => shell
                .AddScript($"Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\WebManagement\\Server' -Name 'SelfSignedCertificateHash' -Value ([byte[]]({binary}))"));

            result = await remote.ExecuteAsync(shell => shell
                .AddCommand("Start-Service")
                .AddArgument("WMSVC"));

        });
    }
}
