using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Incremental.Common.Authentication.Configuration;

/// <summary>
/// Authorization extensions.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Configures default authorization resources.
    /// </summary>
    /// <param name="services"></param>
    /// <returns></returns>
    private static IServiceCollection AddDefaultAuthorization(this IServiceCollection services)
    {
        services.AddAuthorization(options =>
        {
            options.AddPolicy(Policies.Scope.Core, policy =>
                policy.RequireClaim(
                    Claims.Scope(Scopes.Core).Type,
                    Claims.Scope(Scopes.Core).Value)
            );
            
            options.AddPolicy(Policies.Scope.Extension, policy =>
                policy.RequireClaim(
                    Claims.Scope(Scopes.Extension).Type,
                    Claims.Scope(Scopes.Extension).Value)
            );
                
            options.AddPolicy(Policies.Scope.Extension, policy =>
                policy.RequireClaim(
                    Claims.Scope(Scopes.Service).Type,
                    Claims.Scope(Scopes.Service).Value)
            );
        });

        return services;
    }
}