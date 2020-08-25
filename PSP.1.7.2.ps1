<#	
	.NOTES
	===========================================================================
	 Created on:   	20160901
	 Created by:   	Josh Meyer
	 Organization: 	Helion Technologies
	 Filename:     	PSP.VERSION.ps1
	===========================================================================
	.DESCRIPTION
		This script is designed to clean up un-needed cache, cookies and other temporary files from the computer.

Parameters:
"-Extras"
Switches:
-"Kaseya"
Explanation:
When this switch is provided, the script will check for HDD space and determine if it should run, or exit.
Example: PSP.VERSION.ps1 -Extras Kaseya

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
#>
###########
## Setup ##
###########

	## Setting Parameters
	## 20200720.jmeyer.Adding Parameters to combine several versions of the script.
Param (
	[parameter(Mandatory = $false, Position = 0)]
	[string]$Extras = $false
)

## 20200824.jmeyer.Moved console colors to top so entire script is uniform in color.
## Setting colors for various messages.
$Warningcolor = (Get-Host).PrivateData
$Warningcolor.WarningBackgroundColor = "Red"
$Warningcolor.WarningForegroundColor = "White"
$Debugcolor = (Get-Host).PrivateData
$Debugcolor.DebugBackgroundColor = "White"
$Debugcolor.DebugForegroundColor = "Blue"
$console.backgroundcolor = "Black"

Write-Host "Setting up..." -ForegroundColor Yellow

	## 20170929.jmeyer.Moved to 1.6 for full deployment at Helion.
	## 20200811.jmeyer.Moved to 1.7 due to combining several scripts.
$ScriptVersion = "PSP.1.7.2"

Write-Host "Checking Prerequisites..." -ForegroundColor Yellow
	## Checking Prerequisites
	## 20200812.jmeyer.Adding intelligence to script so it can run Server or Workstation cleanups based on OS.
$OSName = (Get-WmiObject Win32_OperatingSystem).Caption
if ($OSName -like '*server*')
{
	Write-Host "We are running on $OSName." -ForegroundColor Yellow
	Write-Host "Setting variables to adjust script for server usage." -ForegroundColor Yellow
	$ScriptIntelligence = "Server"
	Write-Host "Variables set for Server. Continuing..." -ForegroundColor Green
}
else
{
	Write-Host "We are running on $OSName." -ForegroundColor Yellow
	Write-Host "Setting variables to adjust script for workstation usage." -ForegroundColor Yellow
	$ScriptIntelligence = "Workstation"
	Write-Host "Variables set for Workstation. Continuing..." -ForegroundColor Green
}

	## 20200811.jmeyer.Adding Kaseya scheduled cleanup to this script.
if ($Extras -contains "Kaseya")
{
	Write-Host "Checking space requirements..." -ForegroundColor Green
	$FreeSpace = Get-WMIObject Win32_LogicalDisk -Filter "DriveType=3" | Where-Object DeviceID -eq 'C:' | Select-Object @{ L = "FreeSpace"; E = { $_.FreeSpace/1GB } }, @{ L = "TotalSize"; E = { $_.Size/1GB } }
	$PercentFree = ($FreeSpace.FreeSpace/$FreeSpace.TotalSize) * 100
	$PercentRequired = 20.0
	if ($PercentFree -ge $PercentRequired)
	{
		Write-Host "This version is designed to run on computers with less than 20% free space."
		Write-Host "We have more than 20% free space, exiting..."
		Write-Warning "Removing script files for security purposes..."
		## Self destructs script.
		Remove-Item -LiteralPath $PSCommandPath -Force
		Write-Host "File deletion completed" -ForegroundColor Green
		Start-Sleep -Seconds 6
		exit;
	}
}

Write-Host "Checking for administrative rights..." -ForegroundColor Yellow
	## Get the ID and security principal of the current user account.
$myWindowsID = [System.Security.Principal.WindowsIdentity]::GetCurrent();
$myWindowsPrincipal = New-Object System.Security.Principal.WindowsPrincipal($myWindowsID);
	## Get the security principal for the administrator role.
$adminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator;

	## Check to see if we are currently running as an administrator.
if ($myWindowsPrincipal.IsInRole($adminRole))
{
		## We are running as an administrator, so change the title and background colour to indicate this.
	Write-Host "We are running as administrator, changing the title to indicate this." -ForegroundColor Green
	$Host.UI.RawUI.WindowTitle = $myInvocation.MyCommand.Definition + "(Elevated)";
}
else
{
	Write-Host "We are not running as administrator. Relaunching as administrator." -ForegroundColor Yellow
		## We are not running as admin, so relaunch as admin.
	$NewProcess = New-Object System.Diagnostics.ProcessStartInfo "PowerShell";
		## Specify the current script path and name as a parameter with added scope and support for scripts with spaces in it's path.
	$NewProcess.Arguments = "& '" + $script:MyInvocation.MyCommand.Path + "'"
		## Indicate that the process should be elevated.
	$NewProcess.Verb = "runas";
		## Start the new process
	[System.Diagnostics.Process]::Start($newProcess);
		## Exit from the current, unelevated, process.
	Exit;
}

Write-Host "Continuing with setup..." -ForegroundColor Yellow

## 20170105.jmeyer.Changed colors of status's throughout entire script.

	## 20180706.jmeyer.Enabled logging if PowerShell 3 or greater is installed
	## Start log.
if ($PSVersionTable.PSVersion.Major -ge 3)
{
	Write-Host "We are running Powershell version 3 or greater. Logging enabled." -ForegroundColor Green
		## 20170622.jmeyer.Creating Log folder as this isn't used here.
		## 20180718.jmeyer.Adding If statement to check if directory exists first.
		## 20180928.jmeyer.Added Out-Null to suppress the "output" of New-Item.
	If ((Test-Path C:\Logs\) -eq $false)
	{
		New-Item C:\Logs\ -ItemType Directory | Out-Null
	}
	Start-Transcript -Path "C:\Logs\$ScriptVersion.$(Get-Date -UFormat %Y%m%d).log"
}

	## 20170329.jmeyer.Moved creator info towards the top.
$INFO = "
System Cleanup script written by Josh Meyer.
Please contact the author if you have any questions or concerns.
Contact info: jmeyer@heliontechnologies.com
**For complete ChangeLog, please contact the author.**

Script version: $ScriptVersion
"

Write-Host "Setting Variables..." -ForegroundColor Yellow
	## Setting Variables
$OS = Get-WmiObject Win32_OperatingSystem
$StartDate = (Get-Date).ToShortTimeString()
$30DaysBack = (Get-Date).AddDays(-30)
	## 20170110.jmeyer.Added Global ErrorActionPreference to streamline the code.
$ErrorActionPreference = 'SilentlyContinue'
$FSpaceBefore = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='C:'" | Select-Object FreeSpace
## 20200821.jmeyer.Added Try-Catch to the Domain Test.
try
{
	$DomainTest = (Test-ComputerSecureChannel)
}
catch [System.InvalidOperationException]
{
	$DomainTest = $null
}
## 20170125.jmeyer.Added all user's to cleanup.
$UserDir = "C:\Users\*\AppData"
$Chrome = Test-Path "$UserDir\Local\Google\Chrome"
	## 20161222.jmeyer.Added firefox cache
$Firefox = Test-Path "$UserDir\Local\Mozilla\Firefox"
$OfficeDir = "Local\Microsoft\Office"
$Office10 = Test-Path "$UserDir\$OfficeDir\14.0\OfficeFileCache"
$Office13 = Test-Path "$UserDir\$OfficeDir\15.0\OfficeFileCache"
$Office16 = Test-Path "$UserDir\$OfficeDir\16.0\OfficeFileCache"
$Windows10Upgrade = Test-Path C:\Windows10Upgrade
$Win10Upgrade = Test-Path C:\Win10Upgrade
$O365Install = Test-Path C:\O365Install
$TimeBeforeStart = 2
$WaitSeconds = 10
$Processes = Get-Process -Name iexplorer, chrome, MSACCESS, EXCEL, INFOPATH, ONENOTE, OUTLOOK, POWERPNT, MSPUB, WINWORD
	## Disk Cleanup Variables
$VName = "StateFlags0032"
$DirPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"
	## 20160419.jomeyer.removed System error minidump files
	## 20160430.jomeyer.Removed Windows 8 and XP options. These are obsolete.
$TempFolders = @("Active Setup Temp Folders", "Content Indexer Cleaner", "Downloaded Program Files", "GameNewsFiles",
	"GameStatisticsFiles", "GameUpdateFiles", "Internet Cache Files", "Memory Dump Files", "Offline Pages Files",
	"Old ChkDsk Files", "Previous Installations", "Recycle Bin", "Setup Log Files", "System error memory dump files",
	"Temporary Files", "Temporary Setup Files", "Temporary Sync Files", "Thumbnail Cache",
	"Upgrade Discarded Files", "Windows Error Reporting Archive Files", "Windows Error Reporting Queue Files",
	"Windows Error Reporting System Archive Files", "Windows Error Reporting System Queue Files", "Windows Upgrade Log Files",
	"Update Cleanup")
$CTempPath = "C:\Temp"
$CTempTest = Test-Path "C:\Temp"

Write-Host "Setting Functions..." -ForegroundColor Yellow
	## Setting Functions
	## 20200811.jmeyer.Created Functions for every task due to integrating Kaseya, Server and Workstation cleanups into one script.
function DiskSpaceBefore ()
{
	## Gather HDD free space prior to cleaning. Used for ticketing purposes.
	$env:Before = Get-WmiObject Win32_LogicalDisk | Where-Object { $_.DriveType -eq "3" } |
	Select-Object SystemName,
				  @{ Name = "Drive"; Expression = { ($_.DeviceID) } },
				  @{ Name = "Size (GB)"; Expression = { "{0:N1}" -f ($_.Size / 1gb) } },
				  @{ Name = "FreeSpace (GB)"; Expression = { "{0:N1}" -f ($_.Freespace / 1gb) } },
				  @{ Name = "PercentFree"; Expression = { "{0:P1}" -f ($_.FreeSpace / $_.Size) } } |
	Format-Table -AutoSize | Out-String
}

function ProcessWarning ()
{
	## Warning user that the script is going to kill applications.
	## 20160701.jomeyer.Checks for the following applications.
	## 20180702.jmeyer.Added Firefox to process list.
	## Specifies only the open applications that need to be closed.
	if ([bool]($processes))
	{
		Write-Warning "Please save all work and close the following applications before continuing.";
		Write-Warning "If you continue without closing the application, they will be forcefully closed and any unsaved changes will be lost!"
		If ([bool](Get-Process iexplore) -eq $true) { Write-Host "Internet Explorer" }
		If ([bool](Get-Process chrome) -eq $true) { Write-Host "Google Chrome" }
		If ([bool](Get-Process firefox) -eq $true) { Write-Host "Firefox" }
		If ([bool](Get-Process MSACCESS) -eq $true) { Write-Host "Microsoft Access" }
		If ([bool](Get-Process EXCEL) -eq $true) { Write-Host "Microsoft Excel" }
		If ([bool](Get-Process INFOPATH) -eq $true) { Write-Host "Microsoft InfoPath" }
		If ([bool](Get-Process ONENOTE) -eq $true) { Write-Host "Microsoft OneNote" }
		If ([bool](Get-Process ONENOTEM) -eq $true) { Write-Host "Microsoft OneNote" }
		If ([bool](Get-Process OUTLOOK) -eq $true) { Write-Host "Microsoft Outlook" }
		If ([bool](Get-Process POWERPNT) -eq $true) { Write-Host "Microsoft PowerPoint" }
		If ([bool](Get-Process MSPUB) -eq $true) { Write-Host "Microsoft Publisher" }
		If ([bool](Get-Process WINWORD) -eq $true) { Write-Host "Microsoft Word" }
		Write-Warning "Press any key to continue...";
		$x = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown");
	}
	else
	{
		Write-Host "All necessary applications are closed." -ForegroundColor Green;
		Write-Host "Continuing..." -ForegroundColor Green;
	}
}

function ProcessTermination ()
{
	if ([bool]($processes))
	{
		## 20190517.jmeyer.Added -Force.
		Write-Warning "Killing any processes that may be remaining...";
		Stop-Process -Name iexplorer, chrome, firefox, MSACCESS, EXCEL, INFOPATH, ONENOTE, ONENOTEM, OUTLOOK, POWERPNT, MSPUB, WINWORD -Force
	}
}

function DiskCleanup ()
{
	## 20170327.jmeyer.Moved Admin script to main script. Part 1.
	## Stops the Windows Update service.
	Stop-Service -Name wuauserv -Force
	
	## Stops the BITS service.
	Stop-Service -Name BITS -Force
	
	## Running Disk Cleanup, selecting all options that are allowed by Windows. This does NOT alter the registry. 
	Write-Host "Starting Disk Cleanup..." -ForegroundColor Yellow
	
	For ($i = 0; $i -lt $TempFolders.Count; $i++)
	{
		$RegKey = $DirPath + "\" + $TempFolders[$i]
		$StateValue = (Get-ItemProperty $RegKey).$VName
		If (-not $StateValue)
		{
			New-ItemProperty -Path $RegKey -Name $VName -Value "2" -PropertyType "dword" | out-null
		}
		Else
		{
			Set-ItemProperty -Path $RegKey -Name $VName -Value "2"
		}
		$RegKey = $DirPath
	}
	CLEANMGR /sagerun:32
	Write-Host "Disk Cleanup is starting..." -ForegroundColor Green
}

	## 20200811.jmeyer.Adding cleanup of Windows 10 Upgrade project files on upgraded assets.
function Win10UpgradeCleanup ()
{
	if ($OSName -like "*Windows 10*")
	{
		Write-Host "Checking for Windows 10 Upgrade folders..." -ForegroundColor Yellow
		if ($Windows10Upgrade -eq $true)
		{
			Write-Host "Found Windows10Upgrade folder." -ForegroundColor Green
			Write-Host "Removing Windows10Upgrade folder..." -ForegroundColor Yellow
			Remove-Item -Path C:\Windows10Upgrade -Force -Recurse
			Write-Host "Folder deleted!" -ForegroundColor Green
		}
		else
		{
			Write-Host "No Windows10Upgrade found!" -ForegroundColor Red
		}
		
		if ($Win10Upgrade -eq $true)
		{
			Write-Host "Found Win10Upgrade folder." -ForegroundColor Green
			Write-Host "Removing Win10Upgrade folder..." -ForegroundColor Yellow
			Remove-Item -Path C:\Win10Upgrade -Force -Recurse
			Write-Host "Folder deleted!" -ForegroundColor Green
		}
		else
		{
			Write-Host "No Win10Upgrade found!" -ForegroundColor Red
		}
		
		if ($O365Install -eq $true)
		{
			Write-Host "Found O365Install folder." -ForegroundColor Green
			Write-Host "Removing O365Install folder..." -ForegroundColor Yellow
			Remove-Item -Path C:\O365Install -Force -Recurse
			Write-Host "Folder deleted!" -ForegroundColor Green
		}
		else
		{
			Write-Host "No O365Install found!" -ForegroundColor Red
		}
	}
}

function StartupItems ()
{
	## 20170512.jmeyer.Gathering startup items for removal of startup items at a later revision.
	Write-Host "Gathering startup items..."
	Get-CimInstance Win32_StartupCommand | Select-Object Name, command, Location, User | Format-List | Out-File -FilePath C:\Logs\StartupItems.txt
	Write-Host "Completed. List saved to C:\Logs\StartupItems.txt."
}

function UserCleanup ()
{
	## 20190328.jmeyer.Added cleaning up user folders for users that have not logged in in over 30 days. Does not touch Helion, Special, Default User, Public, or All Users
	## 20191227.jmeyer.Adjusted removal to display only usernames of users that are being deleted, as they are being deleted. This is also written in the log now.
	If ($Extras -contains "Users")
	{
		Write-Host "Cleaning up unused User profiles in Users directory (Older than 30 days)..." -ForegroundColor Yellow
		$UserFolders = Get-WmiObject -Class Win32_UserProfile | Where-Object { ($_.localpath -notlike "*helion*") -and (!$_.Special) -and ($_.ConvertToDateTime($_.LastUseTime) -lt $30DaysBack) }
		
		foreach ($User in $UserFolders)
		{
			$Username = Split-Path -Path $User.LocalPath -Leaf -Resolve
			Write-Host = "Deleting user: $($Username)" -ForegroundColor Red
			$User | Remove-WmiObject
		}
		Write-Host "Completed!" -ForegroundColor Green
	}
}

function GPUpdate ()
{
	## 20200812.jmeyer.Rebuilt GPUpdate to a more modern approach.
	if ($DomainTest -eq $true)
	{
		Write-Host "Connected to a domain." -ForegroundColor Green
		Write-Host "Checking for RSAT: Group Policy Management Tools..." -ForegroundColor Yellow
		if ((Get-WindowsCapability -Name Rsat.GroupPolicy.Management.Tools* -Online).State -ne "Installed")
		{
			Write-Host "RSAT: Group Policy Management Tools are not installed." -ForegroundColor Yellow
			Write-Host "Installing RSAT: Group Policy Management Tools." -ForegroundColor Yellow
			Get-WindowsCapability -Name Rsat.GroupPolicy.Management.Tools* -Online | Add-WindowsCapability -Online
			## 20200814.jmeyer.Corrected If statement for installation of GP tools.
			if ((Get-WindowsCapability -Name Rsat.GroupPolicy.Management.Tools* -Online).State -ne "Installed")
			{
				Write-Host "RSAT: Group Policy Management Tools are installed." -ForegroundColor Green
				$RSATGPMT = "Installed"
			}
			else
			{
				Write-Host "RSAT: Group Policy Management Tools did not install." -ForegroundColor Red
				$RSATGPMT = $null
			}
		}
		else
		{
			Write-Host "RSAT: Group Policy Management Tools are already installed." -ForegroundColor Green
			$RSATGPMT = "Installed"
		}
		
		if($RSATGPMT -eq "Installed")
		{
			Write-Host "Running Policy Updates, please wait..." -ForegroundColor Yellow
			## Runs Group Policy Update and does NOT force a log-off.
			Invoke-GPUpdate
			Write-Host "Policy Update completed." -ForegroundColor Green
		}
		else
		{
			Write-Host "RSAT: Group Policy Management Tools are not installed." -ForegroundColor Yellow
			Write-Host "Unable to run GPUpdate." -ForegroundColor Yellow
		}
	}
	else
	{
		Write-Host "Not connected to a domain. Not running Policy Update." -ForegroundColor Yellow
	}
}

function FlushDNS ()
{
	Write-Host "Flushing DNS..." -ForegroundColor Yellow;
	Clear-DnsClientCache
	Write-Host "DNS Flush completed." -ForegroundColor Green
}

function IECleanup ()
{
	## Function for clearing IE Cache/Cookies. 
	## Does NOT delete saved passwords.
	Write-Host "Deleting IE Cookies/cache..." -ForegroundColor Yellow
	function Clear-IECachedData
	{
		## 20160418.jomeyer.Organized and added options
		if ($History) { RunDll32.exe InetCpl.cpl, ClearMyTracksByProcess 1 }
		if ($Cookies) { RunDll32.exe InetCpl.cpl, ClearMyTracksByProcess 2 }
		if ($TempIEFiles) { RunDll32.exe InetCpl.cpl, ClearMyTracksByProcess 4 }
		if ($OfflineTempFiles) { RunDll32.exe InetCpl.cpl, ClearMyTracksByProcess 8 }
		if ($FormData) { RunDll32.exe InetCpl.cpl, ClearMyTracksByProcess 16 }
		if ($All) { RunDll32.exe InetCpl.cpl, ClearMyTracksByProcess 255 }
		if ($AddOn) { RunDll32.exe InetCpl.cpl, ClearMyTracksByProcess 4096 }
		if ($AllplusAddOn) { RunDll32.exe InetCpl.cpl, ClearMyTracksByProcess 4351 }
	}
	do
	{
		## Calls function to perform the action.
		## 20160418.jomeyer.Clearing more cached data
		## 20170126.jmeyer.Removed "AllplusAddOn". This deleted Passwords.
		$continue2 = $true
		& Clear-IECachedData -History -Cookies -TempIEFiles -OfflineTempFiles -FormData -AddOn
	}
	While ($continue2 -eq $false)
	Write-Host "Completed!" -ForegroundColor Green
}

function ChromeCleanup ()
{
	## 20160510.jomeyer.Added Chrome cleanup
	Write-Host "Checking to see if Chrome is installed..." -ForegroundColor Yellow
	if ($Chrome -eq $true)
	{
		Write-Host "Chrome is installed." -ForegroundColor Green
		Write-Host "Deleting Chrome cache..." -ForegroundColor Yellow
		
		$ChromeDIR = "$UserDir\Local\Google\Chrome"
		
		Remove-Item -Path "$ChromeDIR\User Data\Default\*journal" -Force -Recurse
		Remove-Item -Path "$ChromeDIR\User Data\Default\Cookies" -Force -Recurse
		Remove-Item -Path "$ChromeDIR\User Data\Default\Cache\*" -Force -Recurse
		Remove-Item -Path "$ChromeDIR\User Data\Default\Storage\ext\*" -Force -Recurse
		Remove-Item -Path "$ChromeDIR\User Data\Default\Media Cache\*" -Force -Recurse
		Remove-Item -Path "$ChromeDIR\User Data\Default\GPUCache\*" -Force -Recurse
		Remove-Item -Path "$ChromeDIR\User Data\Default\Application Cache\Cache\*" -Force -Recurse
		Remove-Item -Path "$ChromeDIR\User Data\Default\File System\*" -Force -Recurse
		Remove-Item -Path "$ChromeDIR\User Data\Default\Service Worker\*" -Force -Recurse
		Remove-Item -Path "$ChromeDIR\User Data\Default\JumpListIcons\*" -Force -Recurse
		Remove-Item -Path "$ChromeDIR\User Data\Default\JumpListIconsOld\*" -Force -Recurse
		Remove-Item -Path "$ChromeDIR\User Data\Default\Local Storage\*" -Force -Recurse
		Remove-Item -Path "$ChromeDIR\User Data\Default\IndexedDB\*" -Force -Recurse
		Remove-Item -Path "$ChromeDIR\User Data\ShaderCache\GPUCache\*" -Force -Recurse
		Remove-Item -Path "$ChromeDIR\User Data\Default\Pepper Data\Shockwave Flash\WritableRoot\*" -Force -Recurse
		Remove-Item -Path "$ChromeDIR\ShaderCache\GPUCache\*" -Force -Recurse
		Write-Host "Completed!" -ForegroundColor Green
	}
	else
	{
		Write-Host "Cannot find Google Chrome." -ForegroundColor Red
	}
}

function FirefoxCleanup ()
{
	## 20161222.jmeyer.Added firefox cache removal
	Write-Host "Checking to see if Mozilla Firefox is installed..." -ForegroundColor Yellow
	if ($Firefox -eq $true)
	{
		Write-Host "Mozilla Firefox is installed." -ForegroundColor Green
		Write-Host "Deleting Mozilla Firefox cache..." -ForegroundColor Yellow
		
		## Variable for Mozilla Firefox Directory.
		$FirefoxDirL = "$UserDir\Local\Mozilla\Firefox"
		$FirefoxDirR = "$UserDir\Roaming\Mozilla\Firefox"
		
		## Remove all of Mozilla Firefox's Temporary Internet Files.
		Remove-Item -Path "$FirefoxDirL\\Profiles\*\cache2\entries\*" -Force -Recurse
		Remove-Item -Path "$FirefoxDirR\\Profiles\*\storage\default\*" -Force -Recurse
		
		Write-Host "Completed!" -ForegroundColor Green
	}
	else
	{
		Write-Host "Cannot find Mozilla Firefox." -ForegroundColor Red
	}
}

function UserTempFiles ()
{
	## Remove all files and folders in user's Temporary Internet Files. 
	## 20170327.jmeyer.Added .NET Framework log file removal.
	## 20170627.jmeyer.Moved .NET log files to the System Level log files section to clean up script.
	## 20170627.jmeyer.Added temporary internet files.
	Write-Host "Deleting User level Temporary Internet files..." -ForegroundColor Yellow
	Remove-Item -Path "$UserDir\Local\Microsoft\Windows\Temporary Internet Files\*" -Force -Recurse
	Remove-Item -Path "$UserDir\Local\Microsoft\Feeds Cache\*" -Force -Recurse
	Remove-Item -Path "$UserDir\Local\Microsoft\Internet Explorer\DOMStore\" -Force -Recurse
	Remove-Item -Path "$UserDir\Local\Microsoft\Windows\INetCache\" -Force -Recurse
	Remove-Item -Path "$UserDir\Local\Packages\windows_ie_ac_001\AC\INetCache" -Force -Recurse
	Remove-Item -Path "$UserDir\Local\Microsoft\Internet Explorer\Recovery" -Force -Recurse
	Write-Host "Completed!" -ForegroundColor Green
	
	## Deletes all user level Temp files.
	## 20160705.jomeyer.Added removal of ThumbNail cache, Crash Dumps, and ElevatedDiagnostics.
	## 20170627.jmeyer.Moved the below to User level Temp files section to clean up script and added program usage log files.
	Write-Host "Deleting User level Temp files..." -ForegroundColor Yellow
	Remove-Item -Path $UserDir\Local\Temp\* -Force -Recurse
	Remove-Item -Path $UserDir\Roaming\Microsoft\Windows\Cookies\*.txt -Force -Recurse
	Remove-Item -Path "$UserDir\Local\Microsoft\Explorer\thumb*.db" -Force -Recurse
	Remove-Item -Path "$UserDir\Local\CrashDumps\*" -Force -Recurse
	Remove-Item -Path "$UserDir\Local\ElevatedDiagnostics\*" -Force -Recurse
	Remove-Item -Path "$UserDir\Local\Microsoft\CLR_v4.0" -Force -Recurse
	Write-Host "Completed!" -ForegroundColor Green
	
	## Delets all files and folders in user's Office Cache folder.
	## 20160512.jomeyer.added office cache. This is not removed when Temp Inet Files are removed.
	Write-Host "Deleting User level Office Internet cache..." -ForegroundColor Yellow
	Remove-Item -Path "$UserDir\Local\Microsoft\Windows\Temporary Internet Files\Content.MSO" -Force -Recurse
	Write-Host "Completed!" -ForegroundColor Green
	
	## 20170127.jmeyer.Moved Outlook cache clearing together. Easier to track items in the script.
	## Delets all files and folders in user's Outlook cache folder.
	## 20160512.jomeyer.added Outlook cache. Temp Inet Files are already cleaned up, this is included in that.
	Write-Host "Deleting User level Outlook Internet cache..." -ForegroundColor Yellow
	Remove-Item -Path "$UserDir\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook" -Force -Recurse
	Write-Host "Completed!" -ForegroundColor Green
	
	## 20170127.jmeyer.Removed deletion of Recent documents history.
	
	## Delets all files and folders in user's Word cache folder.
	## 20160512.jomeyer.added office cache. This is not removed when Temp Inet Files are removed.
	Write-Host "Deleting User level Word Internet cache..." -ForegroundColor Yellow
	Remove-Item -Path "$UserDir\Local\Microsoft\Windows\Temporary Internet Files\Content.Word" -Force -Recurse
	Write-Host "Completed!" -ForegroundColor Green
	
	## Delets all files and folders in user's InfoPath Cache folder.
	## 20160419.jomeyer.No longer remove directory, only remove files in the directory.
	Write-Host "Deleting User level InfoPath cache..." -ForegroundColor Yellow
	Remove-Item -Path "$UserDir\Local\Microsoft\InfoPath\*" -Force -Recurse
	Write-Host "Completed!" -ForegroundColor Green
}

function JavaCache ()
{
	## 20160728.jomeyer.Added Java cache.
	Write-Host "Checking for User level Java Cache..." -ForegroundColor Yellow
	if ((Test-Path "$UserDir\LocalLow\Sun\Java\Deployment\cache") -eq $true)
	{
		Write-Host "Java Cache Found!" -ForegroundColor Green
		Write-host "Deleting Java Cache..." -ForegroundColor Yellow
		Remove-Item -Path "$UserDir\LocalLow\Sun\Java\Deployment\cache\*" -Force -Recurse
		Write-Host "Completed!" -ForegroundColor Green
	}
	else
	{
		Write-Host "No Java Cache found." -ForegroundColor Red
	}
}

function AdobeAcrobat ()
{
	## 20161109.jmeyer.Added Adobe cache check.
	## 20161226.jmeyer.Added Adobe Acrobat Standard/Pro cache.
	Write-Host "Checking for User level Adobe Cache..." -ForegroundColor Yellow
	if ((Test-Path "$UserDir\Local\Adobe\Acrobat\") -or (Test-Path "$UserDir\Roaming\Adobe\Acrobat\Distiller*\") -eq $true)
	{
		if ((Test-Path "$UserDir\Local\Adobe\Acrobat\") -eq $true)
		{
			Write-Host "Adobe Reader Cache found..." -ForegroundColor Green
			Write-Host "Removing Adobe Cache..." -ForegroundColor Yellow
			Remove-Item -Path "$UserDir\Local\Adobe\Acrobat\*.lst" -Force -Recurse
			Remove-Item -Path "$UserDir\Roaming\Adobe\Acrobat\DC\Cache\*.lst" -Force -Recurse
			Write-Host "Completed!" -ForegroundColor Green
		}
		
		if ((Test-Path "$UserDir\Roaming\Adobe\Acrobat\Distiller*\") -eq $true)
		{
			Write-Host "Adobe Acrobat cache found..." -ForegroundColor Green
			Write-Host "Removing Adobe Acrobat..." -ForegroundColor Yellow
			Remove-Item -Path "$UserDir\Roaming\Adobe\Acrobat\Distiller*\Cache\*" -Force -Recurse
			Write-Host "Completed!" -ForegroundColor Green
		}
	}
	else
	{
		Write-Host "No Adobe Cache found." -ForegroundColor Red
	}
}

function AdobeFlash ()
{
	## 20170327.jmeyer.Added Flash Player cache removal.
	Write-Host "Checking for User level Flash Player cache..." -ForegroundColor Yellow
	if ((Test-Path "$UserDir\Roaming\Macromedia\Flash Player\") -eq $true)
	{
		Write-Host "Adobe Flash Player cache found..." -ForegroundColor Green
		Write-Host "Removing Flash Player cache..." -ForegroundColor Yellow
		Remove-Item -Path "$UserDir\Roaming\Macromedia\Flash Player\*.sol" -Force -Recurse
		Write-Host "Completed!" -ForegroundColor Green
	}
	else
	{
		Write-Host "No Adobe Flash Player cache found." -ForegroundColor Red
	}
}

function OfficeCleanup ()
{
	## 20160512.jomeyer.Added removal of Office cache.
	## 20160707.jomeyer.Office 2010/13/16 cache locations.
	If ($Office10 -eq $true)
	{
		## 20160707.jomeyer.Office 2010 cache.
		Write-Host "Deleting User level Office 2010 file cache..." -ForegroundColor Yellow
		Remove-Item -Path "$UserDir\$OfficeDir\14.0\OfficeFileCache\*" -Force -Recurse
		Write-Host "Completed!" -ForegroundColor Green
	}
	else
	{
		Write-Host "No Office 2010 file cache found." -ForegroundColor Red
	}
		
	If ($Office13 -eq $true)
	{
		## 20160707.jomeyer.Office 2013 cache.
		Write-Host "Deleting User level Office 2013 file cache..." -ForegroundColor Yellow
		Remove-Item -Path "$UserDir\$OfficeDir\15.0\OfficeFileCache\*" -Force -Recurse
		Write-Host "Completed!" -ForegroundColor Green
	}
	else
	{
		Write-Host "No Office 2013 file cache found." -ForegroundColor Red
	}
		
	If ($Office16 -eq $true)
	{
		## 20160707.jomeyer.Office 2016 cache.
		Write-Host "Deleting User level Office 2016 file cache..." -ForegroundColor Yellow
		Remove-Item -Path "$UserDir\$OfficeDir\16.0\OfficeFileCache\*" -Force -Recurse
		Write-Host "Completed!" -ForegroundColor Green
	}
	else
	{
		Write-Host "No Office 2016 file cache found." -ForegroundColor Red
	}
}

function SystemTempFiles ()
{
	## Removes all files in the Windows Temp folder.
	Write-Host "Removing System level Temp files..." -ForegroundColor Yellow
	Remove-Item -Path C:\Windows\Temp\* -Force -Recurse
	Write-Host "Completed." -ForegroundColor Green
	
	## 20160706.jomeyer.Added prefetch data.
	Write-Host "Removing System level Prefetch Data..." -ForegroundColor Yellow
	Remove-Item -Path C:\Windows\Prefetch\*.pf -Force -Recurse
	Write-Host "Completed." -ForegroundColor Green
	
	## 20161223.jmeyer.Added FontCache.
	Write-Host "Removing System level FontCache..." -ForegroundColor Yellow
	Remove-Item C:\Windows\ServiceProfiles\LocalService\AppData\Local\FontCache* -Force -Recurse
	Write-Host "Completed." -ForegroundColor Green
}

function SystemLogFiles ()
{
	## 20170627.jmeyer.Added more log files and moved .NET log files to this section.
	## 20170125.jmeyer.Added Windows Log file removal. Several machines shows several GB of log data.
	Write-Host "Removing System level log files..." -ForegroundColor Yellow
	Remove-Item -Path C:\Windows\Logs\CBS\*.log -Force -Recurse
	Remove-Item -Path C:\Windows\Microsoft.NET\Framework\*.log -Force -Recurse
	Remove-Item -Path C:\Windows\Microsoft.NET\Framework64\*.log -Force -Recurse
	Remove-Item -Path C:\Windows\Microsoft.NET\Framework64\*.log -Force -Recurse
	Remove-Item -Path C:\Windows\Performance\WinSAT\*.log -Force -Recurse
	Remove-Item -Path C:\Windows\Panther\UnattendGC\*.log -Force -Recurse
	Remove-Item -Path C:\Windows\system32\config\systemprofile\AppData\Local\Microsoft\CLR_v4.0\UsageLogs\ -Force -Recurse
	Remove-Item -Path C:\Windows\SysWOW64\config\systemprofile\AppData\Local\Microsoft\CLR_v4.0_32\UsageLogs\ -Force -Recurse
	Remove-Item -Path C:\ProgramData\Microsoft\Windows\WER\ReportArchive\AppCrash* -Force -Recurse
	Write-Host "Completed!" -ForegroundColor Green
}

function CleanIISLogFiles ()
{
	## 20200812.jmeyer.Added cleanup of IIS Log files that are 14 days old or older.
	$IISFilePath = "C:\inetpub\logs"
	$14DaysBack = (Get-Date).AddDays(-14)
	$IISLog = "C:\Logs\IISLogs.txt"
	$ItemsToDelete = Get-ChildItem $IISFilePath -Recurse -File *.log | Where-Object { $_.LastWriteTime -lt $14DaysBack }
	
	Write-Host "Cheacking for IIS Log files..." -ForegroundColor Yellow
	if ($ItemsToDelete.Count -gt 0)
	{
		ForEach ($Item in $ItemsToDelete)
		{
			Write-Host "$($Item.BaseName) is older than $14DaysBack and will be deleted" | Add-Content $IISLog
			Get-item $Item | Remove-Item -Verbose -Force
		}
	}
	else
	{
		Write-Host "No items to be deleted today (Get-Date).DateTime" | Add-Content $IISLog
	}
	Write-Output "Cleanup of log files older than $14DaysBack completed..."
}

function HelionUSMT ()
{
	## 20190603.jmeyer.Removing USMT folder if it exists.
	Write-Host "Checking for Helion USMT folder..." -ForegroundColor Yellow
	if ((Test-Path C:\temp\helion_usmt) -eq $true)
	{
		Write-Host "Found Helion USMT folder. Deleting..." -ForegroundColor Green
		Remove-Item C:\temp\helion_usmt -Recurse -Force
		Write-Host "Completed!" -ForegroundColor Green
	}
	else
	{
		Write-Host "No Helion USMT folder found. Continuing..." -ForegroundColor Yellow
	}
}

function CleanCTemp ()
{
	## 20200811.jmeyer.Added cleanup of C:\Temp if over 1GB and older than 30 days old.
	Write-Host "Checking for folder: $CTempPath" -ForegroundColor Yellow
	if ($CTempTest -eq $true)
	{
		Write-Host "Found folder: $CTempPath" -ForegroundColor Green
		Write-Host "Checking folder size..." -ForegroundColor Yellow
		$CTempSize = (Get-ChildItem -Path $CTempPath | Measure-Object -Sum Length).Sum /1GB
		if ($CTempSize -ge 1.0)
		{
			Write-Host "Folder is $CTempSize GB. Deleting files older than 30 days old." -ForegroundColor Yellow
			Get-ChildItem -Path $CTempPath | Where-Object { $_.LastWriteTime -lt $30DaysBack } | Remove-Item -Force -Recurse
			Write-Host "Completed!" -ForegroundColor Green
		}
		else
		{
			Write-Host "Folder is not large enough to delete. Continuing..." -ForegroundColor Yellow
		}
	}
	else
	{
		Write-Host "Folder not found. Continuing..." -ForegroundColor Green
	}
}

function InstallCMTrace () {
		## 20191227.jmeyer.Installing CMTrace for log viewing.
	if ($PSVersionTable.PSVersion.Major -ge 3)
	{
		if ([System.Environment]::Is64BitProcess)
		{
			$CMTraceInstalled = "C:\Program Files (x86)\ConfigMgr 2012 Toolkit R2\ClientTools\CMTrace.exe"
		}
		else
		{
			$CMTraceInstalled = "C:\Program Files\ConfigMgr 2012 Toolkit R2\ClientTools\CMTrace.exe"
		}
		
		
		if ((Test-Path $CMTraceInstalled) -eq $true)
		{
			Write-Host "CMTrace is installed. Continuing..."
		}
		else
		{
			Write-Host "Installing CMTrace Log Viewer..."
			$CMtraceDL = "https://download.microsoft.com/download/5/0/8/508918E1-3627-4383-B7D8-AA07B3490D21/ConfigMgrTools.msi"
			$CMTrace = "C:\Temp\ConfigMgrTools.msi"
			Start-BitsTransfer -Source $CMtraceDL -Destination $CMTrace
			Start-Process $CMTrace -ArgumentList '/Quiet' -Wait
			Remove-Item $CMTrace -Force
			Write-Host "CMTrace installed! Continuing..." -ForegroundColor Green
		}
	}
}

function DiskCleanupCheck ()
{
	## 20160513.jomeyer.Moved Disk Cleanup wait/check to the end of the script to speed up the overall process.
	## 20160807.jomeyer.No longer has a 20 second delay when checking for Disk Cleanup.
	## 20170127.jmeyer.Added color to the Disk Cleanup host notifications.
	## 20170620.jmeyer.Moved re-start of wuauserv to the end.
	Write-Host "Checking to see if Disk Cleanup is running..." -ForegroundColor Yellow
	if ([bool](Get-Process cleanmgr) -eq $true)
	{
		Write-Host "Disk Cleanup is running." -ForegroundColor Yellow
		do
		{
			Write-Host "waiting for Disk Cleanup..." -ForegroundColor Yellow
			Start-Sleep 16
		}
		while ((Get-WmiObject win32_process | Where-Object { $_.processname -eq 'cleanmgr.exe' } | Measure-Object).count)
		Write-Host "Disk Cleanup has completed." -ForegroundColor Green
		## Restarts the Windows Update service.
		Get-Service -Name wuauserv | Start-Service -Verbose
		## BITS will restart automatically when needed.
		Write-Host "Gathering HDD information..." -ForegroundColor DarkMagenta
	}
	else
	{
		Write-Host "Disk Cleanup is not running, continuing." -ForegroundColor Yellow
		## Restarts the Windows Update service.
		Get-Service -Name wuauserv | Start-Service -Verbose
		## BITS will restart automatically when needed.
		Write-Host "Gathering HDD information..." -ForegroundColor DarkMagenta
	}
}

function DiskSpaceAfter ()
{
	## 20171207.jmeyer.Moved "Gathering HDD information" to the Disk Cleanup section due to the delay between Disk Cleanup and actual HDD info.
	## Gather HDD size and free space after cleaning. Used for ticketing purposes.
	$env:After = Get-WmiObject Win32_LogicalDisk | Where-Object { $_.DriveType -eq "3" } |
	Select-Object SystemName,
				  @{ Name = "Drive"; Expression = { ($_.DeviceID) } },
				  @{ Name = "Size (GB)"; Expression = { "{0:N1}" -f ($_.Size / 1gb) } },
				  @{ Name = "FreeSpace (GB)"; Expression = { "{0:N1}" -f ($_.Freespace / 1gb) } },
				  @{ Name = "PercentFree"; Expression = { "{0:P1}" -f ($_.FreeSpace / $_.Size) } } |
	Format-Table -AutoSize | Out-String
	
	$env:Size = Get-ChildItem C:\Users\* -Include *.iso, *.vhd -Recurse | Sort-Object Length -Descending |
	Select-Object Name, Directory, @{ Name = "Size (GB)"; Expression = { "{0:N2}" -f ($_.Length / 1GB) } } |
	Format-Table -AutoSize | Out-String
	
	$FSpaceAfter = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='C:'" | Select-Object FreeSpace
	$SpaceSaved = ($FSpaceAfter.FreeSpace / 1GB - $FSpaceBefore.FreeSpace / 1GB)
	Write-Host "Completed!" -ForegroundColor Magenta
	## Finished gathering space information
	
}

function Housecleaning ()
{
	## Sends some before and after info for ticketing purposes
	Hostname; Get-Date | Select-Object DateTime
	Write-Host "Before: $env:Before" -ForegroundColor Cyan
	Write-Host "After: $env:After" -ForegroundColor Cyan
	Write-Host "$env:Size" -ForegroundColor Cyan
	Write-Host "We just cleaned up $SpaceSaved GB of space." -ForegroundColor Green -BackgroundColor Black
	## 20170426.jmeyer.Created new total time calculation.
	$TotalTime = (New-TimeSpan -Start $StartDate -End (Get-Date).ToShortTimeString()).TotalMinutes
	Write-Host "Total time for cleanup was $TotalTime minutes."
}

function WorkstationRestart ()
{
	## 20160728.jomeyer.Added option for restart or logout. Logout is required.
	$title = "Helion Service Desk"
	$message = "A restart is recommended but a logout is required. Please choose an option below."
	$Restart = New-Object System.Management.Automation.Host.ChoiceDescription "&Restart.", "Restarts computer."
	$Logout = New-Object System.Management.Automation.Host.ChoiceDescription "&Logout.", "Logs out."
	$options = [System.Management.Automation.Host.ChoiceDescription[]]($Restart, $Logout)
	$result = $host.ui.PromptForChoice($title, $message, $options, 1)
	
	switch ($result)
	{
		0 { $Choice = $true }
		1 { $Choice = $false }
	}
	
	if ($Choice -eq $true)
	{
		
		Write-Warning "A restart will commence automatically in 10 seconds."
		Start-Sleep -Seconds $timeBeforeStart
		
		$waitSeconds .. 1 | Foreach-Object `
		{
			Write-Host "Time Remaining: $_" -ForegroundColor Yellow
			Start-Sleep -Seconds 1
		}
		## Restarts computer
		Restart-Computer -Force
	}
	else
	{
		Write-Warning "A Logout will commence automatically in 10 seconds."
		Start-Sleep -Seconds $timeBeforeStart
		
		$waitSeconds .. 1 | Foreach-Object `
		{
			Write-Host "Time Remaining: $_" -ForegroundColor Yellow
			Start-Sleep -Seconds 1
		}
		## Logs out
		CMD /C "shutdown /l"
	}
	$ErrorActionPreference = 'Continue'
}

function ScriptEnding ()
{
	## Post Creator information
	## 20170622.jmeyer.Added contact information to the end.
	Write-Host "$INFO" -ForegroundColor Cyan
		## Removing all script files for security reasons.
	Write-Warning "Removing script files for security purposes..."
		## Self destructs script.
	Remove-Item -LiteralPath $PSCommandPath -Force
	Remove-Item -Path "C:\Temp\mbstcmd.exe" -Force
	Write-Host "File deletion completed" -ForegroundColor Green
	
		## Stops Log.
	if ($PSVersionTable.PSVersion.Major -ge 3)
	{
		Write-Warning "Stopping log.."
		Stop-Transcript
	}
}

function ServerCleanup ()
{
	## 20200812.jmeyer.Server Cleanup function.
	DiskSpaceBefore
	ProcessWarning
	ProcessTermination
	DiskCleanup
	CleanIISLogFiles
	FlushDNS
	
	CleanCTemp
	DiskCleanupCheck
	DiskSpaceAfter
	Housecleaning
	ScriptEnding
}

function WorkstationCleanup ()
{
	## 20200812.jmeyer.Workstation Cleanup function.
	InstallCMTrace
	DiskSpaceBefore
	ProcessWarning
	ProcessTermination
	DiskCleanup
	Win10UpgradeCleanup
	StartupItems
	UserCleanup
	GPUpdate
	FlushDNS
	IECleanup
	ChromeCleanup
	FirefoxCleanup
	UserTempFiles
	JavaCache
	AdobeAcrobat
	AdobeFlash
	OfficeCleanup
	SystemTempFiles
	SystemLogFiles
	HelionUSMT
	CleanCTemp
	DiskCleanupCheck
	DiskSpaceAfter
	Housecleaning
	ScriptEnding
	WorkstationRestart
}

	## 20170327.jmeyer.Removed all file checks.These are no longer needed as script has been reduced to a single file.
Write-Host "Setup complete!" -ForegroundColor Green
##########################
## Start main code here ##
##########################
Write-Host "Beginning cleanup..." -ForegroundColor Green

Write-Host "Checking Script Intelligence variable..." -ForegroundColor Yellow
if ($ScriptIntelligence -eq "Server")
{
	Write-Host "We are running on $OSName." -ForegroundColor Green
	Write-Host "Running server cleanup..." -ForegroundColor Green
	ServerCleanup
}

if ($ScriptIntelligence -eq "Workstation")
{
	Write-Host "We are running on $OSName." -ForegroundColor Green
	Write-Host "Running workstation cleanup..." -ForegroundColor Green
	WorkstationCleanup
}

#######################
#  Ending of script   #
#######################

###########################
# Do not write below here #
###########################