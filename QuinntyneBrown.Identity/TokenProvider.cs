using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace QuinntyneBrown.Identity
{
    public class TokenProvider : ITokenProvider
    {
        private AuthenticationOptions _authenticationOptions;
        public TokenProvider(IOptions<AuthenticationOptions> optionsAccessor)
        {
            _authenticationOptions = optionsAccessor.Value;
        }

        public string Get(string uniqueName, IEnumerable<Claim> customClaims = null, int? expirationInMinutes = null)
        {
            var now = DateTime.UtcNow;
            var nowDateTimeOffset = new DateTimeOffset(now);

            var claims = new List<Claim>()
                {
                    new Claim(JwtRegisteredClaimNames.UniqueName, uniqueName),
                    new Claim(JwtRegisteredClaimNames.Sub, uniqueName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new Claim(JwtRegisteredClaimNames.Iat, nowDateTimeOffset.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
                };

            if (customClaims != null)
                claims.AddRange(customClaims);

            var jwt = new JwtSecurityToken(
                issuer: _authenticationOptions.JwtIssuer,
                audience: _authenticationOptions.JwtAudience,
                claims: claims,
                notBefore: now,
                expires: now.AddMinutes(expirationInMinutes ??= _authenticationOptions.ExpirationMinutes),
                signingCredentials: new SigningCredentials(new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_authenticationOptions.JwtKey)), SecurityAlgorithms.HmacSha256));

            return new JwtSecurityTokenHandler().WriteToken(jwt);
        }

        public ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
        {
            var tokenValidationParameters = TokenValidationParametersFactory.Create(_authenticationOptions.JwtKey, _authenticationOptions.JwtIssuer, _authenticationOptions.JwtAudience);

            var tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken securityToken;
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out securityToken);
            var jwtSecurityToken = securityToken as JwtSecurityToken;
            if (jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                throw new SecurityTokenException("Invalid token");

            return principal;
        }
    }
}