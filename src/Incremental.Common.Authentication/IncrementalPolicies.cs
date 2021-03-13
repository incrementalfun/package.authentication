namespace Incremental.Common.Authentication
{
    /// <summary>
    /// Common policies for incremental.space.
    /// </summary>
    public static class IncrementalPolicies
    {
        /// <summary>
        /// Scope related policies.
        /// </summary>
        public struct Scope
        {
            /// <summary>
            /// Core scope policy name.
            /// </summary>
            public const string Core = "Scope:Core";

            /// <summary>
            /// Extension scope policy name.
            /// </summary>
            public const string Extension = "Scope:Extension";
        }
    }
}