using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace LetsCrypt.Services.Services;

internal class DeploymentServiceIIS : DeploymentServiceBase
{
    public DeploymentServiceIIS(
        ILogger<DeploymentServiceIIS> logger,
        ILetsCryptMailService mailService,
        IOptionsMonitor<CertificatesOptions> certificateOptions,
        CertificateService certificateService)
        : base(logger, mailService, certificateOptions, certificateService)
    {
    }

    protected override void GetPhaseCount(out int min, out int max)
    {
        if (Target.IIS != null && Target.IIS.Length > 0)
        {
            min = Target.IIS.Min(h => h.Phase);
            max = Target.IIS.Max(h => h.Phase);
        }
        else max = min = 0;
    }

    protected override async Task<DateTimeOffset?> DeployCertificateAsync(CancellationToken cancellationToken)
    {
        DateTimeOffset? next = null;

        foreach (var iis in Target.IIS)
            if (iis?.Enabled == true && iis.Phase == Phase)
            {
                next ??= await UpdateCertificateAsync(cancellationToken);
                await DeployCertificateAsync(iis, cancellationToken);
            }

        return next;
    }

    // Requires
    // [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    // Install-Module –Name IISAdministration -RequiredVersion 1.1.0.0
    // Install-Module –Name IISAdministration -Force
    private async Task DeployCertificateAsync(DeploymentTargetIIS iis, CancellationToken cancellationToken)
    {
        if( !await CopyCertificateAsync(cancellationToken) ) return;

        LoggerContext.Set("StoreName", iis.StoreName);
        LoggerContext.Set("Method", "IIS");
        LoggerContext.Set("Website", iis.Website);

        await ImportCertificateAsync(iis.StoreName, cancellationToken);

        var thumbprint = await GetThumbprintAsync(cancellationToken);

        var script = new StringBuilder();
        script.AppendLine($"Set-ExecutionPolicy -ExecutionPolicy Unrestricted");
        script.AppendLine($"Import-Module -Name 'WebAdministration'");

        foreach (var binding in iis.Bindings)
        {
            LoggerContext.Set("Binding", binding);
            Logger.Information("Bind certificate");

            script.AppendLine($"Remove-IISSiteBinding -Name '{iis.Website}' -BindingInformation '{binding.Trim('?')}' -Protocol https -Confirm:$false");
            script.Append($"New-IISSiteBinding -Name '{iis.Website}' -BindingInformation '{binding.Trim('?')}' -Protocol https -Force -CertStoreLocation 'Cert:\\LocalMachine\\{iis.StoreName}' -CertificateThumbPrint '{thumbprint}'");
            if (binding.Split(":").Length == 3 && !string.IsNullOrEmpty(binding.Split(":")[2]) && !binding.EndsWith("?"))
                script.Append(" -SslFlag Sni");
            script.AppendLine();
        }

        await RunRemoteScriptAsync(script.ToString(), cancellationToken);

        if( iis.RestartService )
            await RestartServiceAsync("World Wide Web Publishing Service", cancellationToken);
    }
}
