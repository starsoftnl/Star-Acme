namespace LetsCrypt.Services.Services;

[Singleton]
internal class DeploymentService
{
    private readonly ILogger Logger;
    private readonly IEnumerable<IDeploymentService> DeploymentServices;
    private readonly IOptionsMonitor<CertificateOptions> CertificateOptions;

    public DeploymentService( 
        ILogger<DeploymentService> logger,
        IEnumerable<IDeploymentService> deploymentServices,
        IOptionsMonitor<CertificateOptions> certificateOptions)
    {
        Logger = logger;
        DeploymentServices = deploymentServices;
        CertificateOptions = certificateOptions;
    }

    public async Task<DateTimeOffset?> DeployCertificatesAsync(DateTimeOffset now, DateTimeOffset? next, CancellationToken cancellationToken)
    {
        foreach (var order in CertificateOptions.CurrentValue)
        {
            try
            {
                foreach (var deployment in DeploymentServices)
                    await deployment.DeployCertificateAsync(order, cancellationToken);
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "Certificate Deploy Failed");

                if (next == null || next > now + TimeSpan.FromDays(1))
                    next = now + TimeSpan.FromDays(1);
            }
        }

        return next;
    }
}
