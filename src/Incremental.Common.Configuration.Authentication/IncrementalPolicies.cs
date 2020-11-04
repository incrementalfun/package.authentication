namespace Incremental.Common.Configuration.Authentication
{
    /// <summary>
    /// Common policies for incremental.space.
    /// </summary>
    public struct IncrementalPolicies
    {
        /// <summary>
        /// Scope related policies.
        /// </summary>
        public struct Scope
        {
            /// <summary>
            /// Core scope policy name.
            /// </summary>
            public static string Core => $"{nameof(Scope)}:{nameof(Core)}";
            /// <summary>
            /// Extension scope policy name.
            /// </summary>
            public static string Extension => $"{nameof(Scope)}:{nameof(Extension)}";
        }
    }
}