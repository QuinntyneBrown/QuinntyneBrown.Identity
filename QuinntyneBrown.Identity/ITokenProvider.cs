using System.Security.Claims;

namespace QuinntyneBrown.Identity
{
    public interface ITokenProvider
    {
        string Get(string username, IEnumerable<Claim> customClaims = null, int? expirationInMinutes = null);
        ClaimsPrincipal GetPrincipalFromExpiredToken(string token);        
    }
}