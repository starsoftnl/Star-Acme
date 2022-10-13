using System.Net;
using System.Security.Cryptography.X509Certificates;

namespace LetsCrypt.Services.Services;

internal class DeploymentServiceHttpSys : DeploymentServiceBase
{
    public DeploymentServiceHttpSys(
        ILogger<DeploymentServiceHttpSys> logger,
        ILetsCryptMailService mailService,
        IOptionsMonitor<DeployOptions> deployOptions,
        CertificateService certificateService)
        : base(logger, mailService, deployOptions, certificateService)
    {
    }

    protected override async Task DeployCertificateAsync(CancellationToken cancellationToken)
    {
        foreach (var http in Target.HttpSys)
            if( http?.Enabled == true )
                await DeployCertificateAsync(http, cancellationToken);
    }

    private async Task DeployCertificateAsync(CertificateTargetHttpSys http, CancellationToken cancellationToken)
    {
        var pfx = await CopyCertificateAsync(cancellationToken);
        if (pfx == null) return;

        LoggerContext.Set("StoreName", http.StoreName);
        LoggerContext.Set("Method", "HttpSys");

        await ImportCertificateAsync(http.StoreName, cancellationToken);

        var filePathLocal = GetLocalCertificatePath();
        var certificate = new X509Certificate2(pfx, PfxPassword);
        var thumbprint = certificate.Thumbprint;

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
