using System.Management.Automation;

namespace LetsCrypt.Services.Models;

internal class DeploymentTarget
{
    public string? Certificate { get; set; }

    public string? Username { get; set; }

    public string? Password { get; set; }

    public string? UncPath { get; set; }

    public string? LocalPath { get; set; }

    public DeploymentTargetAuthentication[] Authentications { get; set; }
       = Array.Empty<DeploymentTargetAuthentication>();

    public DeploymentTargetIIS[] IIS { get; set; }
        = Array.Empty<DeploymentTargetIIS>();

    public DeploymentTargetHttpSys[] HttpSys { get; set; }
        = Array.Empty<DeploymentTargetHttpSys>();

    public DeploymentTargetOctopus? Octopus { get; set; }

    public DeploymentTargetExchange? Exchange { get; set; }

    public DeploymentTargetWac? Wac { get; set; }

    public DeploymentTargetUnifi? Unifi { get; set; }

    public DeploymentTargetHomeAssistant? HomeAssistant { get; set; }

    public DeploymentTargetWMSVC? WMSVC { get; set; }

    public DeploymentTargetRdp? Rdp { get; set; }

    public DeploymentTargetSqlServer? SqlServer { get; set; }

    public DeploymentTargetWindowsService[] WindowsServices { get; set; }
        = Array.Empty<DeploymentTargetWindowsService>();
}
