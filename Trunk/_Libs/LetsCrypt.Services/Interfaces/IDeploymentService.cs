namespace LetsCrypt.Services;

internal interface IDeploymentService
{
    Task DeployCertificateAsync(CertificateOrder order, CancellationToken cancellationToken);
}
