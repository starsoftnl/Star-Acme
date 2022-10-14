using System.Security.Cryptography.X509Certificates;

namespace LetsCrypt.Services.Services;

internal class DeploymentServiceSqlServer : DeploymentServiceBase
{
    public DeploymentServiceSqlServer(
        ILogger<DeploymentServiceSqlServer> logger,
        ILetsCryptMailService mailService,
        IOptionsMonitor<CertificatesOptions> certificateOptions,
        CertificateService certificateService)
        : base(logger, mailService, certificateOptions, certificateService)
    {
    }

    protected override void GetPhaseCount(out int min, out int max)
    {
        min = Target.SqlServer?.Phase ?? 0;
        max = Target.SqlServer?.Phase ?? 0;
    }

    protected override async Task<DateTimeOffset?> DeployCertificateAsync(CancellationToken cancellationToken)
    {
        if (Target.SqlServer?.Enabled != true || Target.SqlServer.Phase != Phase) return null;

        var next = await UpdateCertificateAsync(cancellationToken);

        await DeployCertificateAsync(Target.SqlServer, cancellationToken);

        return next;
    }

    private async Task DeployCertificateAsync(DeploymentTargetSqlServer sql, CancellationToken cancellationToken)
    {
        var pfx = await CopyCertificateAsync(cancellationToken);
        if (pfx == null) return;

        LoggerContext.Set("StoreName", sql.StoreName);
        LoggerContext.Set("Method", "SqlServer");

        await ImportCertificateAsync(sql.StoreName, cancellationToken);

        var filePathLocal = GetLocalCertificatePath();
        var certificate = new X509Certificate2(pfx, PfxPassword);
        var thumbprint = certificate.Thumbprint;

        Logger.Information("Bind certificate");

        await AddAccessRightsToCertificateAsync( sql.StoreName, thumbprint, "NT Service\\MSSQLSERVER", cancellationToken);
        
        // Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL15.MSSQLSERVER\MSSQLServer\SuperSocketNetLib
        var instance = $"{sql.InstanceName ?? "MSSQLServer"}";
        await SetRegistryKeyAsync($"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Microsoft SQL Server\\MSSQL15.{instance}\\{instance}\\SuperSocketNetLib", "Certificate", thumbprint);
    }
}
