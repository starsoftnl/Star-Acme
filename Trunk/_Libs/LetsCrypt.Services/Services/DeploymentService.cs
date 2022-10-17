using ACMESharp.Protocol.Resources;
using Org.BouncyCastle.Asn1.X509;
using static System.Net.Mime.MediaTypeNames;

namespace LetsCrypt.Services.Services;

[Singleton]
internal class DeploymentService
{
    private readonly ILogger Logger;
    private readonly ILetsCryptMailService MailService;
    private readonly IEnumerable<IDeploymentService> DeploymentServices;
    private readonly IOptionsMonitor<DeploymentsOptions> DeploymentOptions;
    private readonly Dictionary<string, DateTimeOffset?> DeploymentDateTime = new();

    public DeploymentService(
        ILogger<DeploymentService> logger,
        ILetsCryptMailService mailService,
        IEnumerable<IDeploymentService> deploymentServices,
        IOptionsMonitor<DeploymentsOptions> deploymentOptions)
    {
        Logger = logger;
        MailService = mailService;
        DeploymentServices = deploymentServices;
        DeploymentOptions = deploymentOptions;
    }

    private DateTimeOffset Now { get; set; }

    public async Task<DateTimeOffset?> RunAsync(DateTimeOffset now, CancellationToken cancellationToken)
    {
        Now = now;
    
        foreach (var deployment in DeploymentOptions.CurrentValue)
            await RunDeploymentAsync(deployment.Key, deployment.Value, cancellationToken);

        var next = DeploymentDateTime.Values.Where(d => d != null).ToList();
        var delay =  next.Count == 0 ? null : next.Min();

        Logger.Information($"Deployment completed. Next run at {delay:dd-MM-yyyy HH:mm:ss}");

        return delay;
    }

    private async Task RunDeploymentAsync(string name, DeploymentOptions deployment, CancellationToken cancellationToken)
    {
        LoggerContext.Set("Deployment", name);

        foreach (var target in deployment.Targets)
            await RunDeploymentTargetAsync(name, deployment, target.Key, target.Value, cancellationToken);
    }

    private async Task RunDeploymentTargetAsync(string name, DeploymentOptions deployment, string computer, DeploymentTarget target, CancellationToken cancellationToken)
    {
        var key = $"{name}|{computer}";

        try
        {
            if (DeploymentDateTime.TryGetValue(key, out var nextrun) )
                if(nextrun == null || nextrun.Value > Now) return;
            DeploymentDateTime[key] = null;

            LoggerContext.Set("ComputerName", computer);

            GetPhaseCount(target, out int minphase, out int maxphase);

            for (int phase = minphase; phase <= maxphase; phase++)
            {
                LoggerContext.Set("Phase", phase);

                foreach (var service in DeploymentServices)
                {
                    LoggerContext.Set("Service", service.GetType().Name);

                    var next = await service.RunAsync(Now, deployment, computer, target, phase, cancellationToken);

                    if (next != null)
                       if (DeploymentDateTime[key] == null || next.Value < DeploymentDateTime[key]!.Value)
                            DeploymentDateTime[key] = next;
                }
            }
        }
        catch( Exception ex )
        {
            var message = $"Certificate {deployment.Name ?? deployment.Certificate} deploy to {computer} failed";

            Logger.Error(ex, message);

            await MailService.SendEmailNotificationAsync(ex, message, cancellationToken);

            DeploymentDateTime[key] = Now + TimeSpan.FromHours(1);
        }
    }

    private void GetPhaseCount(DeploymentTarget target, out int min, out int max)
    {
        min = 0;
        max = 0;

        foreach (var deployment in DeploymentServices)
        {
            deployment.GetPhaseCount(target, out var dmin, out var dmax);
            min = Math.Min(min, dmin);
            max = Math.Max(max, dmax);
        }
    }
}
