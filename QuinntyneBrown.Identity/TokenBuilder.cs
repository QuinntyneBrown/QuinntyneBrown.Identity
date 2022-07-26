﻿using System.Security.Claims;

namespace QuinntyneBrown.Identity
{
    public class TokenBuilder : ITokenBuilder
    {
        private readonly ITokenProvider _tokenProivder;

        private string _username = string.Empty;
        
        private List<Claim> _claims = new ();
        
        public TokenBuilder(ITokenProvider tokenProvider)
        {
            _tokenProivder = tokenProvider ?? throw new ArgumentNullException(nameof(tokenProvider));
        }

        public TokenBuilder AddUsername(string username)
        {
            _username = username;
            return this;
        }

        public TokenBuilder FromClaimsPrincipal(ClaimsPrincipal claimsPrincipal)
        {
            _username = claimsPrincipal.Identity.Name;

            if (string.IsNullOrEmpty(_username))
            {
                _username = claimsPrincipal.FindFirst("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name")?.Value;

            }

            _claims = claimsPrincipal.Claims.ToList();

            return this;
        }

        public TokenBuilder RemoveClaim(Claim claim)
        {
            _claims.Remove(_claims.SingleOrDefault(x => x.Type == claim.Type));

            return this;
        }

        public TokenBuilder AddClaim(Claim claim)
        {
            _claims.Add(claim);

            return this;
        }

        public TokenBuilder AddOrUpdateClaim(Claim claim)
        {
            RemoveClaim(claim);

            _claims.Add(claim);

            return this;
        }

        public string Build()
        {
            return _tokenProivder.Get(_username, _claims);
        }
    }
}
