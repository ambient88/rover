namespace SubnetSearch.Core.Utilities;

public static class SafeUrl
{
    public static bool TryNormalizeHttp(string value, out string normalized)
    {
        normalized = string.Empty;
        if (value.Any(char.IsControl) ||
            !Uri.TryCreate(value, UriKind.Absolute, out var uri) ||
            uri.Scheme is not ("http" or "https"))
        {
            return false;
        }

        normalized = uri.GetComponents(UriComponents.AbsoluteUri, UriFormat.UriEscaped);
        return true;
    }
}
