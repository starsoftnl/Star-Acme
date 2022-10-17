using Org.BouncyCastle.Asn1.Pkcs;
using System.Net;
using System.Security.Cryptography.X509Certificates;

namespace LetsCrypt.Services.Services;

internal class DeploymentServiceHttpSys : DeploymentServiceBase
{
    public DeploymentServiceHttpSys(
        ILogger<DeploymentServiceHttpSys> logger,
        ILetsCryptMailService mailService,
        IOptionsMonitor<CertificatesOptions> certificateOptions,
        CertificateService certificateService)
        : base(logger, mailService, certificateOptions, certificateService)
    {
    }

    protected override void GetPhaseCount(out int min, out int max)
    {
        if (Target.HttpSys != null && Target.HttpSys.Length > 0)
        {
            min = Target.HttpSys.Min(h => h.Phase);
            max = Target.HttpSys.Max(h => h.Phase);
        }
        else max = min = 0;
    }

    protected override async Task<DateTimeOffset?> DeployCertificateAsync(CancellationToken cancellationToken)
    {
        DateTimeOffset? next = null;

        foreach (var http in Target.HttpSys)
            if (http?.Enabled == true && http.Phase == Phase)
            {
                next ??= await UpdateCertificateAsync(cancellationToken);
                await DeployCertificateAsync(http, cancellationToken);
            }

        return next;
    }

    private async Task DeployCertificateAsync(DeploymentTargetHttpSys http, CancellationToken cancellationToken)
    {
        if (!await CopyCertificateAsync(cancellationToken))
            return;

        LoggerContext.Set("StoreName", http.StoreName);
        LoggerContext.Set("Method", "HttpSys");

        await ImportCertificateAsync(http.StoreName, cancellationToken);

        var thumbprint = await GetThumbprintAsync(cancellationToken);

        await RemoteAsync(async remote =>
        {
            string[] result;
            result = await remote.ExecuteAsync(shell => shell
                .AddCommand("Set-ExecutionPolicy")
                .AddArgument("Unrestricted"));

            foreach (var binding in http.Bindings)
            {
                LoggerContext.Set("Binding", binding);
                Logger.Information("Bind certificate");

                result = await remote.ExecuteAsync(shell =>
                {
                    if (IPAddress.TryParse(binding.Split(":")[0], out var address))
                        shell.AddScript($"netsh http delete sslcert ipport='{binding}'");
                    else shell.AddScript($"netsh http delete sslcert hostnameport='{binding}'");
                });

                result = await remote.ExecuteAsync(shell =>
                {
                    if (IPAddress.TryParse(binding.Split(":")[0], out var address))
                        shell.AddScript($"netsh http add sslcert ipport='{binding}' certhash={thumbprint} certstorename={http.StoreName} appid='{ApplicationId}'");
                    else shell.AddScript($"netsh http add sslcert hostnameport='{binding}' certhash={thumbprint} certstorename={http.StoreName} appid='{ApplicationId}'");
                });
            }
        });
    }
}
