using Org.BouncyCastle.Asn1.Pkcs;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;

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

        var script = new StringBuilder();
        script.AppendLine($"Set-ExecutionPolicy -ExecutionPolicy Unrestricted");

        foreach (var binding in http.Bindings)
        {
            LoggerContext.Set("Binding", binding);
            Logger.Information("Bind certificate");

            if (IPAddress.TryParse(binding.Split(":")[0], out var address))
            {
                script.AppendLine($"netsh http delete sslcert ipport='{binding}'");
                script.AppendLine($"netsh http add sslcert ipport='{binding}' certhash={thumbprint} certstorename={http.StoreName} appid='{ApplicationId}'");
            }
            else
            {
                script.AppendLine($"netsh http delete sslcert hostnameport='{binding}'");
                script.AppendLine($"netsh http add sslcert hostnameport='{binding}' certhash={thumbprint} certstorename={http.StoreName} appid='{ApplicationId}'");
            }                            
        }

        await RunRemoteScriptAsync(script.ToString(), cancellationToken);
    }
}
