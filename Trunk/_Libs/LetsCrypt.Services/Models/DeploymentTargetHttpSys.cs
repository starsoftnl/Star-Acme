namespace LetsCrypt.Services.Models;

internal class DeploymentTargetHttpSys : DeploymentTargetBase
{
    public string[] Bindings { get; set; } = Array.Empty<string>();
}
