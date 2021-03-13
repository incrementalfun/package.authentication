using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;

namespace Incremental.Common.Authentication
{
    /// <summary>
    /// Application builder extensions for authentication.
    /// </summary>
    public static class ApplicationBuilderExtensions
    {
        public static IApplicationBuilder UseCommonCors(this IApplicationBuilder app, IConfiguration configuration)
        {
            app.UseCors(options =>
            {
                options.WithOrigins(configuration["SPA_BASE_URI"])
                    .AllowAnyMethod()
                    .AllowAnyHeader()
                    .AllowCredentials()
                    .WithExposedHeaders("x-pagination");
            });

            return app;
        }

        public static IApplicationBuilder UseCommonAuthentication(this IApplicationBuilder app)
        {
            app.UseAuthentication();

            app.UseAuthorization();

            return app;
        }
    }
}