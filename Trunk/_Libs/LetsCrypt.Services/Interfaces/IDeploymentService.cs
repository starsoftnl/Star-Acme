namespace LetsCrypt.Services;

internal interface IDeploymentService
{
    int? GetPhaseCount(CertificateTarget target);

    Task DeployCertificateAsync(CertificateDeploy deployment, CertificateTarget target, int phase, CancellationToken cancellationToken);
}
