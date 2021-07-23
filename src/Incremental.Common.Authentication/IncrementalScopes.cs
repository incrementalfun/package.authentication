namespace Incremental.Common.Authentication
{
    /// <summary>
    /// Common scopes for incremental.space
    /// </summary>
    public struct IncrementalScopes
    {
        /// <summary>
        /// Core scope.
        /// </summary>
        public static string Core => nameof(Core);
        
        /// <summary>
        /// Extension scope.
        /// </summary>
        public static string Extension => nameof(Extension);
        
        /// <summary>
        /// Service scope.
        /// </summary>
        public static string Service => nameof(Service);
    }
}