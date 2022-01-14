namespace Incremental.Common.Authentication.Configuration;

/// <summary>
/// Common scopes for Incremental
/// </summary>
public struct Scopes
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