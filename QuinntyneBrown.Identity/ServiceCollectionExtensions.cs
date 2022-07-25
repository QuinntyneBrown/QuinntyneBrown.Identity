using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Primitives;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;

namespace QuinntyneBrown.Identity
{
    public static class ServiceCollectionExtensions
    {
        private static string GenerateSecret()
        {
            var tripleDESCryptoServiceProvider = TripleDES.Create();
            tripleDESCryptoServiceProvider.GenerateKey();
            return Convert.ToBase64String(tripleDESCryptoServiceProvider.Key);
        }

        public static IServiceCollection AddIdentity(this IServiceCollection services, Action<AuthenticationOptions>? options = null)
        {
            Action<AuthenticationOptions> defaultOptions = o =>
            {
                o.ExpirationMinutes = 30;
                o.JwtKey = GenerateSecret();
                o.JwtAudience = nameof(QuinntyneBrown);
                o.JwtIssuer = nameof(QuinntyneBrown);
            };

            services.Configure(options ??= defaultOptions);

            var authenticationOptions = new AuthenticationOptions();

            (options ??= defaultOptions).Invoke(authenticationOptions);

            services.AddSingleton<IPasswordHasher, PasswordHasher>();
            services.AddSingleton<ITokenProvider, TokenProvider>();
            services.AddTransient<ITokenBuilder, TokenBuilder>();

            var jwtSecurityTokenHandler = new JwtSecurityTokenHandler
            {
                InboundClaimTypeMap = new Dictionary<string, string>()
            };

            services.AddAuthentication(x =>
            {
                x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
                .AddJwtBearer(options =>
            {
                options.RequireHttpsMetadata = false;
                options.SaveToken = true;
                options.SecurityTokenValidators.Clear();
                options.SecurityTokenValidators.Add(jwtSecurityTokenHandler);
                options.TokenValidationParameters = TokenValidationParametersFactory.Create(authenticationOptions.JwtKey, authenticationOptions.JwtIssuer, authenticationOptions.JwtAudience);
                options.Events = new JwtBearerEvents
                {
                    OnMessageReceived = context =>
                    {
                        context.Request.Query.TryGetValue("access_token", out StringValues token);

                        if (!string.IsNullOrEmpty(token))
                        {
                            context.Token = token;
                        };

                        return Task.CompletedTask;
                    }
                };
            });

            return services;
        }
    }
}
