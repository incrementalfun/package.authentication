using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

namespace Incremental.Common.Authentication.Jwt;

/// <summary>
/// Common JWT Service extensions.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers an instance of <see cref="TokenService{TUser}"/>.
    /// </summary>
    /// <param name="services"></param>
    /// <typeparam name="TUser"></typeparam>
    /// <returns></returns>
    public static IServiceCollection AddJwtTokenService<TUser>(this IServiceCollection services) where TUser : IdentityUser
    {
        return services.AddScoped<ITokenService, TokenService<TUser>>();
    }
}