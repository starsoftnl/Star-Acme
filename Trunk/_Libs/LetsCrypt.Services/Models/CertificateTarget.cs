﻿using System.Management.Automation;

namespace LetsCrypt.Services.Models;

internal class CertificateTarget
{
    public string ComputerName { get; set; } = default!;

    public string? Certificate { get; set; }

    public string? Username { get; set; }

    public string? Password { get; set; }

    public string? UncPath { get; set; }

    public string? LocalPath { get; set; }

    public CertificateTargetAuthentication[] Authentications { get; set; }
       = Array.Empty<CertificateTargetAuthentication>();

    public CertificateTargetIIS[] IIS { get; set; }
        = Array.Empty<CertificateTargetIIS>();

    public CertificateTargetHttpSys[] HttpSys { get; set; }
        = Array.Empty<CertificateTargetHttpSys>();

    public CertificateTargetOctopus? Octopus { get; set; }

    public CertificateTargetExchange? Exchange { get; set; }

    public CertificateTargetWac? Wac { get; set; }

    public CertificateTargetUnifi? Unifi { get; set; }

    public CertificateTargetHomeAssistant? HomeAssistant { get; set; }

    public CertificateTargetWMSVC? WMSVC { get; set; }

    public CertificateTargetRdp? Rdp { get; set; }

    public CertificateTargetSqlServer? SqlServer { get; set; }

    public CertificateTargetWindowsService[] WindowsServices { get; set; }
        = Array.Empty<CertificateTargetWindowsService>();
}
