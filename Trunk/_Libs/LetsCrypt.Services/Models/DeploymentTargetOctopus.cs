namespace LetsCrypt.Services.Models;

internal class DeploymentTargetOctopus : DeploymentTargetBase
{
    public string? OctopusPath { get; set; }
    public string? Instance { get; set; }
    public string? IpAddress { get; set; }
    public int? Port { get; set; }
}
