namespace LetsCrypt.Services.Services;

[Singleton]
internal class DeploymentService
{
    private readonly ILogger Logger;
    private readonly ILetsCryptMailService MailService;
    private readonly IEnumerable<IDeploymentService> DeploymentServices;
    private readonly IOptionsMonitor<CertificateOptions> CertificateOptions;

    public DeploymentService(
        ILogger<DeploymentService> logger,
        ILetsCryptMailService mailService,
        IEnumerable<IDeploymentService> deploymentServices,
        IOptionsMonitor<CertificateOptions> certificateOptions)
    {
        Logger = logger;
        MailService = mailService;
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

                Logger.Information("Certificate Deploy Completed");
            }
            catch (Exception ex)
            {
                var message = $"Certificate deploy failed for order {order.Id}";

                Logger.Error(ex, message);

                await MailService.SendEmailNotificationAsync(ex, message, cancellationToken);

                if (next == null || next > now + TimeSpan.FromDays(1))
                    next = now + TimeSpan.FromDays(1);
            }
        }

        return next;
    }
}
