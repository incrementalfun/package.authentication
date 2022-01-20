using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Incremental.Common.Authentication.Jwt;

/// <summary>
/// Common JWT Service extensions.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers an instance of <see cref="TokenService{TUser,TContext}"/>.
    /// </summary>
    /// <param name="services"></param>
    /// <typeparam name="TUser"></typeparam>
    /// <typeparam name="TContext"></typeparam>
    /// <returns></returns>
    public static IServiceCollection AddJwtTokenService<TUser, TContext>(this IServiceCollection services) where TUser : IdentityUser where TContext : IdentityDbContext<TUser>
    {
        services.AddScoped<ITokenService, TokenService<TUser, TContext>>();

        services.AddOptions<TokenServiceOptions>(TokenServiceOptions.TokenService);

        services.AddSingleton<IPostConfigureOptions<TokenServiceOptions>, TokenServiceOptionsPostConfigureOptions>();
        
        return services;
    }
}