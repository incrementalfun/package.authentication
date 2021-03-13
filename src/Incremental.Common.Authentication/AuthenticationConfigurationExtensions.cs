using System;
using System.Collections.Generic;
using Microsoft.Extensions.Configuration;

namespace Incremental.Common.Authentication
{
    /// <summary>
    /// Common authentication configuration extensions.
    /// </summary>
    public static class AuthenticationConfigurationExtensions
    {
        /// <summary>
        /// Adds default authentication configuration to <see cref="IConfiguration"/>.
        /// </summary>
        /// <param name="builder">The <see cref="IConfigurationBuilder"/> to use.</param>
        /// <returns>An <see cref="IConfigurationBuilder"/></returns>
        public static IConfigurationBuilder UsingCommonAuthenticationConfiguration(this IConfigurationBuilder builder)
        {
            var environment = $"{Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") ?? "Production"}";

            return builder.AddInMemoryCollection(environment == "Development" ? Development : Production);
        }

        private static KeyValuePair<string, string>[] Production => new[]{
            new KeyValuePair<string, string>("JWT_TOKEN_ISSUER", "https://identity.incremental.fun"),
            new KeyValuePair<string, string>("SPA_BASE_URI", "https://incremental.fun")
        };
        
        private static KeyValuePair<string, string>[] Development => new[]{
            new KeyValuePair<string, string>("JWT_TOKEN_ISSUER", "https://localhost:5003"),
            new KeyValuePair<string, string>("SPA_BASE_URI", "http://localhost:3000")
        };
    }
}