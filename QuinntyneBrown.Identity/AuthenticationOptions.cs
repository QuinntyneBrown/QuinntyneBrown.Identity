namespace QuinntyneBrown.Identity
{
    public class AuthenticationOptions
    {
        public int ExpirationMinutes { get; set; }
        public string JwtKey { get; set; } = string.Empty;
        public string JwtIssuer { get; set; } = string.Empty;
        public string JwtAudience { get; set; } = string.Empty;        
    }
}
