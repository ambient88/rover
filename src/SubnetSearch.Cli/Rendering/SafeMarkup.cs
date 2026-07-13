namespace SubnetSearch.Cli.Rendering;

using SubnetSearch.Core.Utilities;

internal static class SafeMarkup
{
    public static string Link(string value)
    {
        string text = Markup.Escape(value);
        if (!SafeUrl.TryNormalizeHttp(value, out string target))
        {
            return text;
        }

        return $"[link={Markup.Escape(target)}]{text}[/]";
    }
}
