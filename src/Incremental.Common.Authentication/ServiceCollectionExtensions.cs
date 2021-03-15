using System;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace Incremental.Common.Authentication
{
    /// <summary>
    /// Extensions.
    /// </summary>
    public static class ServiceCollectionExtensions
    {
        public static IServiceCollection AddCommonCors(this IServiceCollection services)
        {
            return services.AddCors();
        }
        
        public static IServiceCollection AddCommonAuthentication(this IServiceCollection services, IConfiguration configuration,
            string? hub = default)
        {
            JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();

            services.AddDefaultAuthentication(configuration, hub);

            services.AddDefaultAuthorization();

            return services;
        }

        /// <summary>
        /// Configures default authentication resources.
        /// </summary>
        /// <param name="services"></param>
        /// <param name="configuration"></param>
        /// <param name="hubPath"></param>
        /// <returns><see cref="IServiceCollection"/></returns>
        private static IServiceCollection AddDefaultAuthentication(this IServiceCollection services, IConfiguration configuration,
            string? hubPath = default)
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
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["JWT_TOKEN_SECURITY_KEY"]))
                };
                if (!string.IsNullOrWhiteSpace(hubPath))
                {
                    options.Events = new JwtBearerEvents
                    {
                        OnMessageReceived = context =>
                        {
                            var accessToken = context.Request.Query["access_token"];

                            // If the request is for our hub...
                            var path = context.HttpContext.Request.Path;
                            if (!string.IsNullOrEmpty(accessToken) && path.StartsWithSegments(hubPath))
                            {
                                // Read the token out of the query string
                                context.Token = accessToken;
                            }

                            return Task.CompletedTask;
                        }
                    };
                }
            });

            return services;
        }

        /// <summary>
        /// Configures default authorization resources.
        /// </summary>
        /// <param name="services"></param>
        /// <returns></returns>
        private static IServiceCollection AddDefaultAuthorization(this IServiceCollection services)
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