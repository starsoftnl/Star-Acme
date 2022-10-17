using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace LetsCrypt.Services.Services;

internal class DeploymentServiceExchange : DeploymentServiceBase
{
    public DeploymentServiceExchange(
        ILogger<DeploymentServiceHttpSys> logger,
        ILetsCryptMailService mailService,
        IOptionsMonitor<CertificatesOptions> certificateOptions,
        CertificateService certificateService)
        : base(logger, mailService, certificateOptions, certificateService)
    {
    }

    protected override void GetPhaseCount(out int min, out int max)
    {
        min = Target.Exchange?.Phase ?? 0;
        max = Target.Exchange?.Phase ?? 0;
    }

    protected override async Task<DateTimeOffset?> DeployCertificateAsync(CancellationToken cancellationToken)
    {
        if (Target.Exchange?.Enabled != true || Target.Exchange.Phase != Phase) return null;

        var next = await UpdateCertificateAsync(cancellationToken);

        await DeployCertificateAsync(Target.Exchange, cancellationToken);

        return next;
    }

    private async Task DeployCertificateAsync(DeploymentTargetExchange exchange, CancellationToken cancellationToken)
    {
        if (!await CopyCertificateAsync(cancellationToken))
            return;

        LoggerContext.Set("StoreName", exchange.StoreName);
        LoggerContext.Set("Method", "Exchange");

        await ImportCertificateAsync(exchange.StoreName, cancellationToken);

        var pfx = await CertificateService.LoadCertificateAsync(OrderId, cancellationToken);
        if (pfx == null) return;

        var filePathLocal = GetLocalCertificatePath();
        var certificate = new X509Certificate2(pfx, PfxPassword);
        var thumbprint = certificate.Thumbprint;

        Logger.Information("Bind certificate");

        var script = new StringBuilder();
        script.AppendLine($"Set-ExecutionPolicy -ExecutionPolicy Unrestricted");
        if (!string.IsNullOrEmpty(Username) && !string.IsNullOrEmpty(Password))
        {
            script.AppendLine($"$password = ConvertTo-SecureString '{Password}' -AsPlainText -Force");
            script.AppendLine($"$UserCredential = New-Object System.Management.Automation.PSCredential ('{Username}', $password)");
            script.AppendLine($"$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://{ComputerName}.STARSOFT.NL/PowerShell/ -Authentication Kerberos -Credential $UserCredential");
        } else script.AppendLine($"$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://{ComputerName}.STARSOFT.NL/PowerShell/ -Authentication Negotiate");
        script.AppendLine($"Import-PSSession $Session -DisableNameChecking");
        script.AppendLine($"Enable-ExchangeCertificate -Thumbprint '{thumbprint}' -Services 'IIS'");
        script.AppendLine($"iisreset");
        script.AppendLine($"Remove-PSSession -computername {ComputerName}.STARSOFT.NL");
        await RunRemoteScriptAsync(script.ToString(), cancellationToken);
    }
}
