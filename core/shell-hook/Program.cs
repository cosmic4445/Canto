using System.Runtime.Versioning;
using Canto.Shell;

if (!OperatingSystem.IsWindows())
{
    Console.Error.WriteLine("CantoShell only runs on Windows.");
    return 1;
}

return Run(args);

[SupportedOSPlatform("windows")]
static int Run(string[] args)
{
    string command = args.Length > 0 ? args[0].ToLowerInvariant() : string.Empty;

    try
    {
        switch (command)
        {
            case "install":
            {
                string exe = args.Length > 1
                    ? args[1]
                    : Path.Combine(AppContext.BaseDirectory, "canto.exe");
                ContextMenu.Install(exe);
                Console.WriteLine("Canto context menu installed for the current user.");
                return 0;
            }
            case "uninstall":
                ContextMenu.Uninstall();
                Console.WriteLine("Canto context menu removed.");
                return 0;
            case "status":
                Console.WriteLine(ContextMenu.IsInstalled() ? "installed" : "not installed");
                return 0;
            default:
                Console.Error.WriteLine("usage: CantoShell <install [path-to-canto.exe] | uninstall | status>");
                return 2;
        }
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"error: {ex.Message}");
        return 1;
    }
}
