namespace LetsCrypt.Services.Models;

internal class DeploymentTargetWac : DeploymentTargetBase
{
    public int Port { get; set; } = 443;
}
