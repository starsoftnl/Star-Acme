using PKISharp.SimplePKI;

namespace LetsCrypt.Services;

internal static class PkiKeyPairExtensions
{
    public static string ToBase64( this PkiKeyPair keyPair )
    {
        using (var ms = new MemoryStream())
        {
            keyPair.Save(ms);
            return Convert.ToBase64String(ms.ToArray());
        }
    }

    public static PkiKeyPair FromBase64( string base64 )
    {
        using (var ms = new MemoryStream(Convert.FromBase64String(base64)))
            return PkiKeyPair.Load(ms);
    }
}
