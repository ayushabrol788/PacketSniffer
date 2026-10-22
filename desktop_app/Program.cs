using System;
using System.Diagnostics;
using System.IO;
using System.Windows.Forms;

namespace CyberSentinel {
    static class Program {
        [STAThread]
        static void Main(string[] args) {
            try {
                string appDir = AppDomain.CurrentDomain.BaseDirectory;
                string htmlPath = Path.Combine(appDir, "ui", "index.html");

                if (!File.Exists(htmlPath)) {
                    MessageBox.Show(
                        "Could not find browser UI at:\n" + htmlPath,
                        "CyberSentinel Error",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Error
                    );
                    return;
                }

                // Dedicated isolated user profile for CyberSentinel Browser
                string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                string userDataDir = Path.Combine(localAppData, "CyberSentinelBrowser", "UserProfile");

                if (!Directory.Exists(userDataDir)) {
                    Directory.CreateDirectory(userDataDir);
                }

                string[] candidatePaths = new string[] {
                    @"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                    @"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
                    @"C:\Program Files\Google\Chrome\Application\chrome.exe",
                    @"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Google\Chrome\Application\chrome.exe"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Microsoft\Edge\Application\msedge.exe")
                };

                string browserPath = null;
                foreach (string path in candidatePaths) {
                    if (File.Exists(path)) {
                        browserPath = path;
                        break;
                    }
                }

                string fileUri = "file:///" + htmlPath.Replace('\\', '/');

                if (browserPath != null) {
                    // Flags ensure an isolated application window with relaxed embedding security for live iframe traffic analysis
                    string launchArgs = string.Format(
                        "--app=\"{0}\" --user-data-dir=\"{1}\" --window-size=1440,900 --window-position=50,30 --disable-web-security --disable-site-isolation-trials --disable-features=IsolateOrigins,site-per-process --allow-running-insecure-content --disable-infobars",
                        fileUri, userDataDir
                    );

                    Process.Start(new ProcessStartInfo {
                        FileName = browserPath,
                        Arguments = launchArgs,
                        UseShellExecute = true
                    });
                } else {
                    // Fallback to default OS browser
                    Process.Start(fileUri);
                }
            } catch (Exception ex) {
                MessageBox.Show(
                    "Failed to launch CyberSentinel Browser:\n" + ex.Message,
                    "CyberSentinel Error",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error
                );
            }
        }
    }
}
