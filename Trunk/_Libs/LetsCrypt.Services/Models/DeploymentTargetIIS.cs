namespace LetsCrypt.Services.Models;

internal class DeploymentTargetIIS : DeploymentTargetBase
{
    public bool RestartService { get; set; }
    public string Website { get; set; } = "Default Web Site";
    public string[] Bindings { get; set; } = Array.Empty<string>();
}
