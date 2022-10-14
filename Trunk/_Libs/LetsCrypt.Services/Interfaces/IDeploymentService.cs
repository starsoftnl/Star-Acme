namespace LetsCrypt.Services;

internal interface IDeploymentService
{
    void GetPhaseCount(DeploymentTarget target, out int min, out int max);

    Task<DateTimeOffset?> RunAsync(DateTimeOffset now, DeploymentOptions deployment, string computerName, DeploymentTarget target, int phase, CancellationToken cancellationToken);
}
