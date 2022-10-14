using ACMESharp.Protocol.Resources;

namespace LetsCrypt.Services.Services;

[Singleton]
internal class DeploymentService
{
    private readonly ILogger Logger;
    private readonly ILetsCryptMailService MailService;
    private readonly IEnumerable<IDeploymentService> DeploymentServices;
    private readonly IOptionsMonitor<CertificateOptions> CertificateOptions;
    private readonly IOptionsMonitor<DeploymentOptions> DeploymentOptions;

    public DeploymentService(
        ILogger<DeploymentService> logger,
        ILetsCryptMailService mailService,
        IEnumerable<IDeploymentService> deploymentServices,
        IOptionsMonitor<CertificateOptions> certificateOptions,
        IOptionsMonitor<DeploymentOptions> deploymentOptions)
    {
        Logger = logger;
        MailService = mailService;
        DeploymentServices = deploymentServices;
        CertificateOptions = certificateOptions;
        DeploymentOptions = deploymentOptions;
    }

    private DateTimeOffset Now { get; set; }

    private DateTimeOffset? Next { get; set; }

    public async Task<DateTimeOffset?> RunAsync(DateTimeOffset now, DateTimeOffset? next, CancellationToken cancellationToken)
    {
        Now = now;
        Next = next;

        foreach (var deployment in DeploymentOptions.CurrentValue)
            await RunDeploymentAsync(deployment, cancellationToken);

        return Next;
    }

    private async Task RunDeploymentAsync(CertificateDeploy deployment, CancellationToken cancellationToken)
    {
        try
        {
            LoggerContext.Set("Deployment", deployment.Name ?? deployment.Certificate);

            foreach (var target in deployment.Targets)
                await RunDeploymentTargetAsync(deployment, target, cancellationToken);
        }
        catch (Exception ex)
        {
            var message = $"Certificate deploy failed for {deployment.Name ?? deployment.Certificate}";

            Logger.Error(ex, message);

            await MailService.SendEmailNotificationAsync(ex, message, cancellationToken);

            if (Next == null || Next > Now + TimeSpan.FromDays(1))
                Next = Now + TimeSpan.FromDays(1);
        }
    }

    private async Task RunDeploymentTargetAsync(CertificateDeploy deployment, CertificateTarget target, CancellationToken cancellationToken)
    {
        try
        {
            LoggerContext.Set("ComputerName", target.ComputerName);

            var phases = DeploymentServices.Select(s => s.GetPhaseCount(target)).Where(s => s != null).Max();

            for (int phase = 0; phase < phases; phase++)
                foreach (var service in DeploymentServices)
                    await service.DeployCertificateAsync(deployment, target, phase, cancellationToken);
        }
        catch( Exception ex )
        {
            var message = $"Certificate {deployment.Name ?? deployment.Certificate} deploy to {target.ComputerName} failed";

            Logger.Error(ex, message);

            await MailService.SendEmailNotificationAsync(ex, message, cancellationToken);

            if (Next == null || Next > Now + TimeSpan.FromDays(1))
                Next = Now + TimeSpan.FromDays(1);
        }
    }
}
