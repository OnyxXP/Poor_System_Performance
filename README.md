# Poor_System_Performance
Generic but extensive cleanup of cookies/cache/temp files on Windows based assets (Workstation and server).

Explanation of Functions:

InstallCMTrace; Download and install Microsoft's CMTrace log viewing tool from SCCM.

DiskSpaceBefore; Captures disk space before the script removes any files.

ProcessWarning; Checks for open processes that will interfere with the script.

ProcessTermination; Closes all open processes that will interfere with the script.

DiskCleanup; Launches Microsoft Disk Cleanup (cleanmgr) and sets flags for all items that it's capable of cleaning.

Win10UpgradeCleanup; Removes all files related to the Windows 10 Upgrade project.

CleanCTemp; Checks folder size and deletes files older than 30 days old if folder is over 1GB.

CleanIISLogFiles; Cleans IIS Log files older than 14 days old.

StartupItems; Reports on Startup items. (IN PROGRESS)

UserCleanup; Removes Users that have not logged into the computer in over 30 days.

GPUpdate; Runs GPUpdate.

FlushDNS; Flushes DNS.

IECleanup; Removes Cookies and Cache from IE.

ChromeCleanup; Removes Cookies and Cache from Chrome.

FirefoxCleanup; Removes Cookies and Cache from Firefox.

UserTempFiles; Removes User specific temp files.

JavaCache; Removes Java cookies and cache.

AdobeAcrobat; Removes Adobe Acrobat cookies and cache.

AdobeFlash; Removes Adobe Flash cookies and cache.

OfficeCleanup; Removes cache from Office applications.

SystemTempFiles; Removes System level Temp files.

SystemLogFiles; Removes System level log files (NOT Event Viewer logs).

HelionUSMT; Checks for and removes the Helion USMT folder.

DiskCleanupCheck; Checks to see if Disk Cleanup is running and waits for it to complete if it is.

DiskSpaceAfter; Captures disk space after the script removes files.

Housecleaning; Reporting on script results.

ScriptEnding; Removing script files and stop logging.

WorkstationRestart; Prompts for logout and restart options.
