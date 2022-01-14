namespace Incremental.Common.Authentication.Configuration;

/// <summary>
/// Common policies for Incremental
/// </summary>
public static class Policies
{
    /// <summary>
    /// Scope related policies.
    /// </summary>
    public struct Scope
    {
        /// <summary>
        /// Core scope policy name.
        /// </summary>
        public const string Core = "scope:core";

        /// <summary>
        /// Extension scope policy name.
        /// </summary>
        public const string Extension = "scope:extension";

        /// <summary>
        /// Service scope policy name.
        /// </summary>
        public const string Service = "scope:service";
            
    }
}