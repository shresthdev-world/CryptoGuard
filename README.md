# Modern native desktop interface (2026 UI refresh)

**This ZIP contains a redesign of the original Tkinter desktop application, not a website.**
No browser, local web server or frontend build tools are required.

- **Quick classroom launch:** extract the ZIP and double-click `Run-Demo.cmd` (Python 3.11+ with Tkinter required).
- **Standard desktop launch:** `Start.cmd`, then select **Run safe demo** or **Start live monitor**.
- **Live monitoring setup:** run `Setup-Live.cmd` once to install `psutil` before starting live monitoring.
- Main **Python monitoring, evidence rules, portable isolation and Windows helper** are preserved from the supplied final project. `dashboard.py` is redesigned with sidebar, metric cards, activity chart, findings list and evidence inspector.
- `desktop-preview.png` shows the new desktop window. No network connection is needed for the simulated classroom demo.
- Native Defender/remediation integrations have not been fully verified in this Linux build environment; test them on your Windows device before a demonstration.

---

# Cryptojacking Detector
AKTU B.Tech · Semester III · Mini project

A Windows desktop application that connects a running app to its CPU/GPU load, network peers and mining-related evidence. Every finding names the process and explains the result. Decisions about removal belong to the device owner.

## Open on Windows
1. Extract the whole ZIP into a writable folder. Open the extracted folder.
2. Install Python 3.11 or later for Windows with Tcl/Tk if it is not already available.
3. For the offline presentation, double-click **Start.cmd**, then **Run demo**. Once Python is installed the demo needs no internet or third-party packages.
4. For live monitoring, run **Setup-Live.cmd** once. It creates a project-local Python environment and installs psutil using pip. Internet access is normally required for this setup. Open **Start.cmd** again and click **Start live**.
5. Click a process under **Processes**, then **Inspect selected process**. The review opens under **Findings**. Select a finding to see its process name, PID, path, measurements, evidence and coverage notes. Automatic findings also appear here as monitoring continues.

**Report:** Open **Project-Report.pdf**. The first page has editable fields for your name, roll number and college. Fill them and save a copy before submitting if your college requires identification.

## Present in two minutes

| On screen | What to explain |
|---|---|
| Run demo, then select Video export | CPU stays at 95% of one logical processor. The detector reports Unusual load. A normal video export can do this. |
| Select Pool client sample | The same load plus a mining protocol string gives Possible mining. A protocol string can exist in software without any mining taking place. |
| Select Simulated miner | The same process also connects to a listed destination in the demo. Its combined evidence gives Mining likely. |
| Click Demo removal and confirm | The app moves a harmless text file into a training quarantine. The evidence panel shows its new location. Click Demo removal again to restore it. |
| Start live and inspect a known app | Explain the observed Windows process, network data and any unavailable checks. End the presentation with Stop. |

## Read a live finding

| Finding | Meaning |
|---|---|
| Unusual load | CPU reaches at least 80% of one logical core for 10 consecutive readings, or a GPU engine reaches 80% for three distinct GPU samples. |
| Possible mining | A mining-related file/launch marker, configured pool hostname in launch arguments, or pool-associated TCP peer matched. |
| Mining likely | An observed pool-associated peer matches the same process as a Stratum launch argument, or as a mining file marker plus sustained load. |
| No indicators observed | The available checks during this review returned no match and no sustained-load event. |
| Limited visibility | A key check could not complete and no stronger signal was available. Read the coverage notes. |

## Handle a live finding

- On a mining-related finding, click **Remove miner**. The dialog names the app and path. For a suspected threat, choose **Scan selected file with Defender**. A fresh, exact-path Defender record can report Detected, Cleaned, Quarantined, Removed, Allowed or Blocked. If a result is unavailable, the app directs you to Protection history. Compare the affected file with the displayed path. For a detection needing action, choose **Quarantine** if offered. For a quarantined threat, **Remove** permanently removes it. You may need administrator privileges to view the details.
- If you recognize an installed mining app and want it gone, **Uninstall an installed app in Windows Settings** opens Installed apps. Select the matching product and use its **Uninstall** command.
- For **Mining likely** involving a supported standalone miner owned by your account under your local Desktop or Downloads, **End selected process** stops that process after confirmation. Then **Isolate portable file** moves its executable out of the launch path. **Isolated files** on the toolbar lets you restore it if needed. This option checks the selected SHA-256 hash, excludes linked files and never overwrites the destination. Both folders must be on one volume. The holding folder is a reversible move, not an antivirus execution sandbox.
- **Review actions** also offers approval of a verified file hash for load-only alerts and review of matching startup entries. A directly matching task, service or Run entry can be disabled after confirmation. A backup is kept under the data directory. Review shared applications and interpreter hosts carefully; the executable path may name the host while a tab, script or extension does the work.
- Ending a process stops the current run. Uninstalling, isolating or removing the responsible file changes how it can run again. Resume monitoring to check for recurrence.

## Files and troubleshooting

| Item | Purpose |
|---|---|
| Start.cmd / Setup-Live.cmd | Desktop launcher and one-time live-mode setup |
| detector.py / dashboard.py | Monitoring loop, offline demo, evidence display and user actions |
| evidence.py / pools.json | Process inspection, evidence rules and starter pool rules |
| portable.py / tools/windows.ps1 | Scoped portable-file isolation, recovery and Windows integrations |
| Project-Report.pdf / demo-dashboard.png | Submission report and actual screenshot of the demo |
| tests/test_detector.py | Reproducible regression suite, including a harmless Windows file-move check |

Windows results are under **%LOCALAPPDATA%\CryptojackingDetector**. Live findings go to alerts.jsonl and alerts.csv, manual checks go to process_reviews files, and demo results go to demo_alerts files. actions.jsonl records demo moves, completed portable isolations and Defender requests once an outcome is available. Defender and Windows Settings maintain their own histories. Raw command lines are omitted from detector logs.

If GPU counters, the DNS cache or a protected process cannot be read, the UI reports unavailable information. The starter pool list is intentionally small. Short sampling windows, unknown pools, CPU throttling and mining inside a browser or shared host can limit detection and attribution. A device-owner decision is needed to establish whether a mining workload was authorized.

If the GUI does not open, check the console message and the Python/Tk installation. If live mode reports missing psutil, rerun Setup-Live.cmd and reopen Start.cmd. Windows PowerShell and Microsoft Defender Antivirus are required for their corresponding integrations. On a managed device, Windows policy may prevent a requested action.

From PowerShell in the extracted folder, use the following commands after live setup.

    .\.venv\Scripts\python.exe detector.py --demo
    .\.venv\Scripts\python.exe detector.py --gui
    .\.venv\Scripts\python.exe -m unittest discover -s tests -v

The offline checks, dashboard demonstration and portable monitoring core were exercised in Linux. Run the included tests on the target Windows computer for the native file-move check. Try a known process for GPU/network visibility and check Defender status before a live presentation.
