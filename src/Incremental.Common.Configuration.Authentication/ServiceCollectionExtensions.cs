using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace Incremental.Common.Configuration.Authentication
{
    public static class ServiceCollectionExtensions
    {
        public static IServiceCollection AddDefaultAuthentication(this IServiceCollection services, IConfiguration configuration)
        {
            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
            }).AddJwtBearer(options =>
            {
                options.SaveToken = true;
                options.RequireHttpsMetadata = true;
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = false,
                    ValidateLifetime = false,
                    ValidIssuer = configuration["JWT_TOKEN_ISSUER"],
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["JWT_TOKEN_SECURITY_KEY"]))
                };
            });

            return services;
        }

        public static IServiceCollection AddDefaultAuthorization(this IServiceCollection services)
        {
            services.AddAuthorization(options =>
            {
                options.AddPolicy(IncrementalPolicies.Scope.Core, policy =>
                    policy.RequireClaim(
                        IncrementalClaims.Scope(IncrementalScopes.Core).Type,
                        IncrementalClaims.Scope(IncrementalScopes.Core).Value)
                );
                
                options.AddPolicy(IncrementalPolicies.Scope.Extension, policy =>
                    policy.RequireClaim(
                        IncrementalClaims.Scope(IncrementalScopes.Extension).Type,
                        IncrementalClaims.Scope(IncrementalScopes.Extension).Value)
                );
            });

            return services;
        }
    }
}