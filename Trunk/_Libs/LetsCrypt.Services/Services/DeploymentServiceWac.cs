using System.Net;
using System.Security.Cryptography.X509Certificates;

namespace LetsCrypt.Services.Services;

internal class DeploymentServiceWac : DeploymentServiceBase
{
    public DeploymentServiceWac(
        ILogger<DeploymentServiceWac> logger,
        ILetsCryptMailService mailService,
        IOptionsMonitor<CertificatesOptions> certificateOptions,
        CertificateService certificateService)
        : base(logger, mailService, certificateOptions, certificateService)
    {
    }

    protected override void GetPhaseCount(out int min, out int max)
    {
        min = Target.Wac?.Phase ?? 0;
        max = Target.Wac?.Phase ?? 0;
    }

    protected override async Task<DateTimeOffset?> DeployCertificateAsync(CancellationToken cancellationToken)
    {
        if (Target.Wac?.Enabled != true || Target.Wac.Phase != Phase) return null;

        var next = await UpdateCertificateAsync(cancellationToken);

        await DeployCertificateAsync(Target.Wac, cancellationToken);

        return next;
    }

    private async Task DeployCertificateAsync(DeploymentTargetWac wac, CancellationToken cancellationToken)
    {
        if (!await CopyCertificateAsync(cancellationToken)) return;

        LoggerContext.Set("StoreName", wac.StoreName);
        LoggerContext.Set("Method", "WAC");

        await ImportCertificateAsync(wac.StoreName, cancellationToken);

        var thumbprint = await GetThumbprintAsync(cancellationToken);

        Logger.Information("Bind certificate");

        await RemoteAsync(async remote =>
        {
            string[] result;
            result = await remote.ExecuteAsync(shell => shell
                .AddCommand("Set-ExecutionPolicy")
                .AddArgument("Unrestricted"));

            result = await remote.ExecuteAsync(shell => shell
                .AddCommand("Stop-Service")
                .AddArgument("ServerManagementGateway"));

            result = await remote.ExecuteAsync(shell => shell
                .AddScript($"netsh http delete sslcert ipport=0.0.0.0:{wac.Port}"));

            result = await remote.ExecuteAsync(shell => shell
                .AddScript($"netsh http delete urlacl url=https://+:{wac.Port}/"));

            result = await remote.ExecuteAsync(shell => shell
                .AddScript($"netsh http add urlacl url=https://+:{wac.Port}/ user='NT Authority\\Network Service'"));

            result = await remote.ExecuteAsync(shell => shell
                .AddScript($"netsh http add sslcert ipport=0.0.0.0:{wac.Port} certhash='{thumbprint}' appid='{{9A81E8DC-5AFD-46B6-A728-93218D11C0B9}}'"));

            result = await remote.ExecuteAsync(shell => shell
                .AddCommand("Start-Service")
                .AddArgument("ServerManagementGateway"));
        });
    }
}
