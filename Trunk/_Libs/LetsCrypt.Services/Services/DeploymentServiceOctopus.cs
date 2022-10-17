using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace LetsCrypt.Services.Services;

internal class DeploymentServiceOctopus : DeploymentServiceBase
{
    public DeploymentServiceOctopus(
        ILogger<DeploymentServiceOctopus> logger,
        ILetsCryptMailService mailService,
        IOptionsMonitor<CertificatesOptions> certificateOptions,
        CertificateService certificateService)
        : base(logger, mailService, certificateOptions, certificateService)
    {
    }

    protected override void GetPhaseCount(out int min, out int max)
    {
        min = Target.Octopus?.Phase ?? 0;
        max = Target.Octopus?.Phase ?? 0;
    }

    protected override async Task<DateTimeOffset?> DeployCertificateAsync(CancellationToken cancellationToken)
    {
        if (Target.Octopus?.Enabled != true || Target.Octopus.Phase != Phase) return null;

        var next = await UpdateCertificateAsync(cancellationToken);

        await DeployCertificateAsync(Target.Octopus, cancellationToken);

        return next;
    }

    private async Task DeployCertificateAsync(DeploymentTargetOctopus octopus, CancellationToken cancellationToken)
    {
        if (!await CopyCertificateAsync(cancellationToken)) 
            return;

        LoggerContext.Set("StoreName", octopus.StoreName);
        LoggerContext.Set("Method", "Octopus");

        await ImportCertificateAsync(octopus.StoreName, cancellationToken);

        var filePathLocal = GetLocalCertificatePath();
        var thumbprint = await GetThumbprintAsync(cancellationToken);
        var octopusPath = octopus.OctopusPath ?? @"C:\Program Files\Octopus Deploy\Octopus";

        LoggerContext.Set("IPAddress", octopus.IpAddress);
        LoggerContext.Set("Port", octopus.Port);
        Logger.Information("Bind certificate");

        var items = new List<string>();
        items.Add($"--thumbprint='{thumbprint}'");
        items.Add($"--certificate-store='{octopus.StoreName}'");

        if (!string.IsNullOrEmpty(octopus.Instance))
            items.Add($"--instance='{octopus.Instance}'");

        if (!string.IsNullOrEmpty(octopus.IpAddress))
            items.Add($"--ip-address='{octopus.IpAddress}'");

        if (octopus.Port != null)
            items.Add($"--port={octopus.Port}");

        var script = new StringBuilder();
        script.AppendLine($"Set-ExecutionPolicy -ExecutionPolicy Unrestricted");
        script.AppendLine($"Set-Location -Path '{octopusPath}'");
        script.AppendLine($"Stop-Service -Name 'OctopusDeploy' -Force");
        script.AppendLine($".\\octopus.server.exe ssl-certificate {string.Join(" ", items)}");
        script.AppendLine($"Start-Service -Name 'OctopusDeploy'");

        await RunRemoteScriptAsync(script.ToString(), cancellationToken);
    }
}
