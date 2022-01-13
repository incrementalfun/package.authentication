using System.Security.Claims;

namespace Incremental.Common.Authentication
{
    /// <summary>
    /// Common claims for incremental.space
    /// </summary>
    public struct IncrementalClaims
    {
        private static string ClaimFormat(string claim) => $"incremental:{claim.ToLower()}";
        
        /// <summary>
        /// Generate Scope claim.
        /// </summary>
        /// <param name="scope"></param>
        /// <returns></returns>
        public static Claim Scope(string scope) => new Claim(ClaimFormat("scope"), scope.ToLower());
    }
}