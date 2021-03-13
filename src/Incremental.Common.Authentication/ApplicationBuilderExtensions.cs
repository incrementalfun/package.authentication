using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;

namespace Incremental.Common.Authentication
{
    public static class ApplicationBuilderExtensions
    {
        public static IApplicationBuilder UseCommonCors(IApplicationBuilder app, IConfiguration configuration)
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
    }
}