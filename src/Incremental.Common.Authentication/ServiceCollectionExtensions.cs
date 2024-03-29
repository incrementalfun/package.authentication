﻿using System;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Threading.Tasks;
using Azure.Identity;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace Incremental.Common.Authentication;

/// <summary>
/// Authentication extensions.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers Data Protection mechanisms in a Azure Blob Storage mixed with Azure Key Vault.
    /// <remarks>
    /// Must specify AZURE_BLOB_STORAGE_URI and AZURE_KEY_VAULT_URI in configuration.
    /// </remarks>
    /// </summary>
    /// <param name="services"></param>
    /// <param name="configuration"></param>
    /// <returns></returns>
    public static IServiceCollection AddCommonDataProtection(this IServiceCollection services, IConfiguration configuration)
    {
        var environment = $"{Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") ?? "Production"}";

        if (environment == "Production")
        {
            services.AddDataProtection()
                .PersistKeysToAzureBlobStorage(new Uri(configuration["AZURE_BLOB_STORAGE_URI"]), new DefaultAzureCredential())
                .ProtectKeysWithAzureKeyVault(new Uri(configuration["AZURE_KEY_VAULT_URI"]), new DefaultAzureCredential());
        }

        return services;
    }
    
    /// <summary>
    /// Registers Data Protection mechanisms in a DataProtectionKeyContext.
    /// </summary>
    /// <param name="services"></param>
    /// <param name="configuration"></param>
    /// <typeparam name="TContext"></typeparam>
    /// <returns></returns>
    public static IServiceCollection AddCommonDataProtection<TContext>(this IServiceCollection services, IConfiguration configuration) 
        where TContext : DbContext, IDataProtectionKeyContext
    {
        var environment = $"{Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") ?? "Production"}";

        if (environment == "Production")
        {
            services.AddDataProtection()
                .PersistKeysToDbContext<TContext>();
        }

        return services;
    }

    /// <summary>
    /// Add common authentication services and configurations.
    /// </summary>
    /// <param name="services"></param>
    /// <param name="configuration"></param>
    /// <param name="jwtOptionsAction"></param>
    /// <param name="hub"></param>
    /// <returns></returns>
    public static IServiceCollection AddCommonAuthentication(this IServiceCollection services, IConfiguration configuration,
        Action<JwtBearerOptions>? jwtOptionsAction = default, string? hub = default)
    {
        JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();

        services.AddDefaultAuthentication(configuration, jwtOptionsAction, hub);

        services.AddDefaultAuthorization();

        return services;
    }

    private static IServiceCollection AddDefaultAuthentication(this IServiceCollection services, IConfiguration configuration,
        Action<JwtBearerOptions>? jwtOptionsAction = default, string? hubPath = default)
    {
        var defaultOptions = new Action<JwtBearerOptions>(options =>
        {
            options.SaveToken = true;
            options.RequireHttpsMetadata = true;
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = false,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                RequireAudience = true,
                RequireExpirationTime = true,
                RequireSignedTokens = true,
                ValidIssuer = configuration["JWT_TOKEN_ISSUER"],
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["JWT_TOKEN_SECURITY_KEY"]))
            };
            
            options.Events = GenerateJwtBearerEvents(hubPath);
        });
        
        services.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
        }).AddJwtBearer(options =>
        {
            defaultOptions.Invoke(options);
            jwtOptionsAction?.Invoke(options);
        });

        return services;
    }

    private static JwtBearerEvents GenerateJwtBearerEvents(string? hubPath)
    {
        var events = new JwtBearerEvents
        {
            OnAuthenticationFailed = context =>
            {
                if (context.Exception.GetType() == typeof(SecurityTokenExpiredException))
                {
                    context.Response.Headers.Add("Token-Expired", "true");
                }
                return Task.CompletedTask;
            }
        };

        if (!string.IsNullOrWhiteSpace(hubPath))
        {
            events.OnMessageReceived = context =>
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
            };
        }

        return events;
    }

    /// <summary>
    /// Configures default authorization resources.
    /// </summary>
    /// <param name="services"></param>
    /// <returns></returns>
    private static IServiceCollection AddDefaultAuthorization(this IServiceCollection services)
    {
        // services.AddAuthorization(options =>
        // {
        //     options.AddPolicy(IncrementalPolicies.Scope.Core, policy =>
        //         policy.RequireClaim(
        //             IncrementalClaims.Scope(Scopes.Core).Type,
        //             IncrementalClaims.Scope(Scopes.Core).Value)
        //     );
        //
        //     options.AddPolicy(IncrementalPolicies.Scope.Extension, policy =>
        //         policy.RequireClaim(
        //             IncrementalClaims.Scope(Scopes.Extension).Type,
        //             IncrementalClaims.Scope(Scopes.Extension).Value)
        //     );
        //     
        //     options.AddPolicy(IncrementalPolicies.Scope.Extension, policy =>
        //         policy.RequireClaim(
        //             IncrementalClaims.Scope(Scopes.Service).Type,
        //             IncrementalClaims.Scope(Scopes.Service).Value)
        //     );
        // });

        return services;
    }
}