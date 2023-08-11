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
-"-Optimizations"
Switches:
-"Kaseya"
-"Users"
-"Offboarding"
-"SFC"
-"DISM"
Explanation:
When Kaseya is provided, the script will check for HDD space and determine if it should run, or exit.
Example: PSP.VERSION.ps1 -Optimizations Kaseya
When Users is provided, the script will remove user folders for anyone that has not logged in in the last 30 days.
Example: PSP.VERSION.ps1 -Optimizations Users

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
SystemFiles; Removes System level log and temp files (NOT Event Viewer logs).
HelionUSMT; Checks for and removes the Helion USMT folder.

DiskCleanupCheck; Checks to see if Disk Cleanup is running and waits for it to complete if it is.
DiskSpaceAfter; Captures disk space after the script removes files.
Housecleaning; Reporting on script results.
ScriptEnding; Removing script files and stop logging.
WorkstationRestart; Prompts for logout and restart options.

TASKS:
Add Event Viewer entries for functions.
Allow log file to be defined with a parameter. Default to what's defined if the parameter isn't provided.
#>
################
## Parameters ##
################
#region Parameters
## 20200720.jmeyer.Adding Parameters to combine several versions of the script.
## 20230811.Added autoupdating.
Param (
	[parameter(Mandatory = $false, Position = 0)]
	[bool]$Optimizations = $false,
	[parameter(Mandatory = $false)]
	[bool]$Kaseya = $false,
	[parameter(Mandatory = $false)]
	[bool]$AutoUpdate = $true
)
#endregion Parameters
#############
## Modules ##
#############
#region Modules
Write-Host "Setting up Modules..." -ForegroundColor Yellow
#Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
## 20211012.jmeyer.Adjusted AD Module installation as this varies with Windows 10 builds.
## older than 1809: "Enable-WindowsOptionalFeature -Online -FeatureName RSATClient-Roles-AD-Powershell"
## 1809 and newer: "Add-WindowsCapability –online –Name "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0""
if (Get-Module -ListAvailable -Name ActiveDirectory)
{
	Write-Host "ActiveDirectory Module is installed." -ForegroundColor Green
}
else
{
	Add-WindowsCapability -Online -Name "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"
	#Get-WindowsCapability -Name "RSAT*" -Online | Add-WindowsCapability -Online
	Import-Module ActiveDirectory
}

#if (Get-Module -ListAvailable -Name PSWriteHTML)
#{
#	Write-Host "PSWriteHTML Module is already installed." -ForegroundColor Green
#}
#else
#{
#	Install-Module -Name PSWriteHTML -Force
#	Import-Module PSWriteHTML
#}
Write-Host "Finished setting up Modules." -ForegroundColor Green
#endregion Modules
###############
## Functions ##
###############
#region Functions
Write-Host "Setting Functions..." -ForegroundColor Yellow
## 20200811.jmeyer.Created Functions for efficiency, Kaseya automated deployment, and combining Server and Workstation cleanups into one script.
Write-Host "Setting up..." -ForegroundColor Yellow
Write-Host "Setting up security protocols..." -ForegroundColor Yellow
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls11 -bor [System.Net.SecurityProtocolType]::Tls12;
Write-Host "Creating Functions..." -ForegroundColor Yellow
#region StandardFunctions
function InitialSetup
{
	## Event log logging
	try
	{
		New-EventLog -LogName Application -Source "$ScriptName" -ErrorAction Stop
	}
	catch [System.InvalidOperationException]
	{
		Write-Host "Event Log Source for this script is already registered." -ForegroundColor Green
	}
	$StartTime = Get-Date
	Write-EventLog -Message "The $ScriptFullName script was started." -EventID 32700 -EntryType Information -LogName "Application" -Source "$ScriptName" -Category 1 -RawData 10, 20
	## Setting colors for various messages.
	$SetColors = (Get-Host).PrivateData
	$SetColors.WarningBackgroundColor = "Red"
	$SetColors.WarningForegroundColor = "White"
	$SetColors.DebugBackgroundColor = "White"
	$SetColors.DebugForegroundColor = "DarkBlue"
	$SetColors.VerboseBackgroundColor = "Red"
	$SetColors.VerboseForegroundColor = "White"
	#$DebugPreference = 'Continue'
}
function Logging
{
	if ($PSVersionTable.PSVersion.Major -ge 3)
	{
		Write-Host "We are running Powershell version 3 or greater. Logging enabled." -ForegroundColor Green
		if ((Test-Path C:\Logs\) -eq $false)
		{
			$null = New-Item C:\Logs\ -ItemType Directory
		}
		$LogFile = "C:\Logs\$ScriptFullName.$(Get-Date -UFormat %Y%m%d).log"
		Start-Transcript -Path $LogFile
		Write-EventLog -Message "Logging started for $ScriptFullName and can be located at $LogFile." -EventID 32702 -EntryType Information -LogName "Application" -Source "$ScriptName" -Category 1 -RawData 10, 20
	}
}
function AdminElevation
{
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
}
function AutoUpdate()
{
	if ($AutoUpdate)
	{
		Write-Host "Auto Updates are enabled. Checking for updates..."
		if (Test-Connection 8.8.8.8 -Count 1 -Quiet)
		{
			Write-Host "Internet connection verified..."
			$UpdateAvailable = $false
			$NewVersionNumber = $null
			try
			{
				Write-Host "Checking for newer version..."
				## For use with PUBLIC GitHub Repos
				[version]$NewVersionNumber = (New-Object System.Net.WebClient).DownloadString($GitHubVersion).Trim([Environment]::NewLine)
				[version]$CurrentVersionNumber = $ScriptVersionNumber
				Write-Host "Version information found..."
				Write-Host "Checking version numbers..."
				if ($NewVersionNumber -gt $CurrentVersionNumber)
				{
					Write-Host "Newer version found!"
					Write-Host "Current Version: $ScriptVersionNumber"
					Write-Host "New Version: $NewVersionNumber"
					Write-Host "Update available. Removing existing script and downloading update..."
					Remove-Item $PSCommandPath -Force -Verbose
					## For use with PUBLIC GitHub Repos
					(New-Object System.Net.Webclient).DownloadFile($NewScriptFile, $PSCommandPath)
					Write-Host "Script downloaded. Starting updated script and exiting the current script..." -ForegroundColor Blue
					Start-Sleep 5
					if ([String]::IsNullOrEmpty($Optimizations))
					{
						## Used if only Optimizations contains data.
						Start-Process PowerShell -Arg "$PSCommandPath -AutoUpdate 0 -Optimizations $Optimizations"
						ScriptEnding
					}
					else
					{
						Start-Process PowerShell -Arg "$PSCommandPath -AutoUpdate 0"
						ScriptEnding
					}
				}
				else
				{
					Write-Host "We are running the latest version. Continuing..."
				}
			}
			catch [System.Exception]
			{
				Write-Host $_
			}
		}
		else
		{
			Write-Host "Unable to check for updates. Internet connection not available."
		}
	}
}
function Prerequisites
{
	## Script requirements
	if ($OSName -like '*server*')
	{
		Write-Host "We are running on $OSName." -ForegroundColor Yellow
		Write-Host "Setting variables to adjust script for server usage." -ForegroundColor Yellow
		$ScriptIntelligence = "Server"
		Write-Host "Variables set for Server. Continuing..." -ForegroundColor Green
		Write-EventLog -LogName "Application" -Source "$ScriptName" -EventID 32701 -EntryType Information -Message "This script is set to be ran on a Server." -Category 1 -RawData 10, 20
	}
	else
	{
		Write-Host "We are running on $OSName." -ForegroundColor Yellow
		Write-Host "Setting variables to adjust script for workstation usage." -ForegroundColor Yellow
		$ScriptIntelligence = "Workstation"
		Write-Host "Variables set for Workstation. Continuing..." -ForegroundColor Green
		Write-EventLog -LogName "Application" -Source "$ScriptName" -EventID 32701 -EntryType Information -Message "This script is set to be ran on a Workstation." -Category 1 -RawData 10, 20
	}
}
#endregion StandardFunctions
function UnzipFile
{
    <#
.SYNOPSIS
   UnzipFile is a function which extracts the contents of a zip file.
.DESCRIPTION
   UnzipFile is a function which extracts the contents of a zip file specified via the -File parameter to the
location specified via the -Destination parameter. This function first checks to see if the .NET Framework 4.5
is installed and uses it for the unzipping process, otherwise COM is used.
.PARAMETER File
    The complete path and name of the zip file in this format: C:\zipfiles\myzipfile.zip
.PARAMETER Destination
    The destination folder to extract the contents of the zip file to. If a path is no specified, the current path
is used.
.PARAMETER ForceCOM
    Switch parameter to force the use of COM for the extraction even if the .NET Framework 4.5 is present.
.EXAMPLE
   UnzipFile -File C:\zipfiles\AdventureWorks2012_Database.zip -Destination C:\databases\
.EXAMPLE
   UnzipFile -File C:\zipfiles\AdventureWorks2012_Database.zip -Destination C:\databases\ -ForceCOM
.EXAMPLE
   'C:\zipfiles\AdventureWorks2012_Database.zip' | UnzipFile
.EXAMPLE
    Get-ChildItem -Path C:\zipfiles | ForEach-Object {$_.fullname | UnzipFile -Destination C:\databases}
.INPUTS
   String
.OUTPUTS
   None
.NOTES
   Author:  Mike F Robbins
   Website: http://mikefrobbins.com
   Twitter: @mikefrobbins
#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true,
				   ValueFromPipeline = $true)]
		[ValidateScript({
				If ((Test-Path -Path $_ -PathType Leaf) -and ($_ -like "*.zip"))
				{
					$true
				}
				else
				{
					Throw "$_ is not a valid zip file. Enter in 'C:\Folder\File.zip' format"
				}
			})]
		[string]$File,
		[ValidateNotNullOrEmpty()]
		[ValidateScript({
				If (Test-Path -Path $_ -PathType Container)
				{
					$true
				}
				else
				{
					Throw "$_ is not a valid destination folder. Enter in 'C:\Destination' format"
				}
			})]
		[string]$Destination = (Get-Location).Path,
		[switch]$ForceCOM
	)
	If (-not $ForceCOM -and ($PSVersionTable.PSVersion.Major -ge 3) -and
		((Get-ItemProperty -Path "HKLM:\Software\Microsoft\NET Framework Setup\NDP\v4\Full" -ErrorAction SilentlyContinue).Version -like "4.5*" -or
			(Get-ItemProperty -Path "HKLM:\Software\Microsoft\NET Framework Setup\NDP\v4\Client" -ErrorAction SilentlyContinue).Version -like "4.5*"))
	{
		Write-Verbose -Message "Attempting to Unzip $File to location $Destination using .NET 4.5"
		try
		{
			[System.Reflection.Assembly]::LoadWithPartialName("System.IO.Compression.FileSystem") | Out-Null
			[System.IO.Compression.ZipFile]::ExtractToDirectory("$File", "$Destination")
		}
		catch
		{
			Write-Warning -Message "Unexpected Error. Error details: $_.Exception.Message"
		}
	}
	else
	{
		Write-Verbose -Message "Attempting to Unzip $File to location $Destination using COM"
		try
		{
			$shell = New-Object -ComObject Shell.Application
			$shell.Namespace($destination).copyhere(($shell.NameSpace($file)).items())
		}
		catch
		{
			Write-Warning -Message "Unexpected Error. Error details: $_.Exception.Message"
		}
	}
}
function DiskSpaceBefore
{
	## Gather HDD free space prior to cleaning. Used for ticketing purposes.
	$env:Before = Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DriveType -eq "3" } |
	Select-Object SystemName,
				  @{ Name = "Drive"; Expression = { ($_.DeviceID) } },
				  @{ Name = "Size (GB)"; Expression = { "{0:N1}" -f ($_.Size / 1GB) } },
				  @{ Name = "FreeSpace (GB)"; Expression = { "{0:N1}" -f ($_.Freespace / 1GB) } },
				  @{ Name = "PercentFree"; Expression = { "{0:P1}" -f ($_.FreeSpace / $_.Size) } } |
	Format-Table -AutoSize | Out-String
	$env:FSpaceBefore = (Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'").FreeSpace / 1GB
}
function ProcessWarning
{
	Write-Host "Gathering open processes..." -ForegroundColor Yellow
	## Warning user that the script is going to kill applications and specifies only the open applications that need to be closed.
	## 20210322.jmeyer.Added error action due to changes with how exe's are interacted with.
	$OpenProcessesUnique = Get-Process -Name $ProcessList -ErrorAction SilentlyContinue | select -Unique
	
	if ($Kaseya -notcontains "Yes")
	{
		if ([bool]($OpenProcessesUnique))
		{
			Write-Warning "Please save all work and close the following applications before continuing.";
			Write-Warning "If you continue without closing the application, they will be forcefully closed and any unsaved changes will be lost!"
			foreach ($Process in $OpenProcessesUnique)
			{
				$TempProcess = (Get-Process -Name $Process).Product
				Write-Host "$($TempProcess[0])"
			}
			Write-Warning "Press any key to continue...";
			$x = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown");
		}
		else
		{
			Write-Host "All necessary applications are closed." -ForegroundColor Green;
			Write-Host "Continuing..." -ForegroundColor Green;
		}
	}
	else
	{
		Write-Host "This script was launched from Kaseya, we are unable to warn the user to close the following open processes." -ForegroundColor Red
		foreach ($Process in $OpenProcessesUnique)
		{
			if ([bool](Get-Process -Name $Process))
			{
				$TempProcess = (Get-Process -Name $Process).Product
				Write-Host "$($TempProcess[0])"
			}
		}
	}
}
function ProcessTermination
{
	if ([bool]($OpenProcessesUnique))
	{
		Write-Warning "Killing any required processes that are still open..."
		$OpenProcesses = Get-Process -Name $ProcessList -ErrorAction SilentlyContinue
		foreach ($Process in $OpenProcesses)
		{
			## 20190517.jmeyer.Added -Force.
			## 20230201.jmeyer.Added -Verbose
			Stop-Process -Name $Process -Force -ErrorAction SilentlyContinue -Verbose
		}
	}
}
function DiskCleanup
{
	## 20170327.jmeyer.Moved Admin script to main script. Part 1.
	## Stops the Windows Update service.
	Stop-Service -Name wuauserv -Force
	## Stops the BITS service.
	Stop-Service -Name BITS -Force
	## Running Disk Cleanup, selecting all options that are allowed by Windows. This does NOT alter the registry. 
	## 20230131.jmeyer.Added try/catch to handle errors for keys that do not exist. 
	Write-Host "Starting Disk Cleanup..." -ForegroundColor Yellow
	for ($i = 0; $i -lt $TempFolders.Count; $i++)
	{
		$RegKey = $DirPath + "\" + $TempFolders[$i]
		try
		{
			$StateValue = (Get-ItemProperty $RegKey).$VName
		}
		catch [System.Management.Automation.ItemNotFoundException]
		{
			Write-Host "The registry key was not found. Moving on..." -ForegroundColor Yellow
		}
		if (-not $StateValue)
		{
			try
			{
				New-ItemProperty -Path $RegKey -Name $VName -Value "2" -PropertyType "dword" | Out-Null
			}
			catch [System.Management.Automation.ItemNotFoundException]
			{
				Write-Host "The registry key was not found. Moving on..." -ForegroundColor Yellow
			}
		}
		else
		{
			try
			{
				Set-ItemProperty -Path $RegKey -Name $VName -Value "2"
			}
			catch [System.Management.Automation.ItemNotFoundException]
			{
				Write-Host "The registry key was not found. Moving on..." -ForegroundColor Yellow
			}
		}
		$RegKey = $DirPath
	}
	## 20210322.jmeyer.Added /SETUP to remove previous installations of Windows.
	CLEANMGR /sagerun:32 /SETUP
	Write-Host "Disk Cleanup is starting..." -ForegroundColor Green
	Write-EventLog -LogName "Application" -Source "$ScriptName" -EventID 32701 -EntryType Information -Message "Disk Cleanup is starting." -Category 1 -RawData 10, 20
}
## 20200811.jmeyer.Adding cleanup of Windows 10 Upgrade project files on upgraded assets.
function Win10UpgradeCleanup
{
	if ($Optimizations -contains "Offboarding")
	{
		Write-Host "Checking for Windows 10 Upgrade folders..." -ForegroundColor Yellow
		if ($Windows10Upgrade)
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
		
		if ($Win10Upgrade)
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
		
		if ($O365Install)
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
	elseif ($OSName -like "*Windows 10*")
	{
		Write-Host "Checking for Windows 10 Upgrade folders..." -ForegroundColor Yellow
		if ($Windows10Upgrade)
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
		
		if ($Win10Upgrade)
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
		
		if ($O365Install)
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
	elseif ($OSName -like "*Server*")
	{
		Write-Host "Checking for Windows 10 Upgrade folders..." -ForegroundColor Yellow
		if ($ServerWin10Upgrade -ne $null)
		{
			Write-Host "Found Win10Upgrade folder." -ForegroundColor Green
			Write-Host "Removing Win10Upgrade folder..." -ForegroundColor Yellow
			Remove-Item -Path $ServerWin10Upgrade -Force -Recurse
			Write-Host "Folder deleted!" -ForegroundColor Green
		}
		else
		{
			Write-Host "No Win10Upgrade found!" -ForegroundColor Red
		}
		
		if ($ServerO365Install -ne $null)
		{
			Write-Host "Found O365Install folder." -ForegroundColor Green
			Write-Host "Removing O365Install folder..." -ForegroundColor Yellow
			Remove-Item -Path $ServerO365Install -Force -Recurse
			Write-Host "Folder deleted!" -ForegroundColor Green
		}
		else
		{
			Write-Host "No O365Install found!" -ForegroundColor Red
		}
	}
}
function StartupItems
{
	## 20170512.jmeyer.Gathering startup items for removal of startup items at a later revision.
	## 20210813.jmeyer.Added If statement for offboarding as this step won't be needed if the client is off-boarding.
	if ($Optimizations -contains "Offboarding")
	{
		Write-Host "Skipping Startup Item check."
	}
	else
	{
		Write-Host "Gathering startup items..."
		Get-CimInstance Win32_StartupCommand | Select-Object Name, command, Location, User | Format-List | Out-File -FilePath C:\Logs\StartupItems.txt
		Write-Host "Completed. List saved to C:\Logs\StartupItems.txt."
	}
}
function UserCleanup
{
	## 20201224.jmeyer.Added Removal of Helion accounts for offboarding regardless of last login and removing other users per limitations previously outlined. 
	## 20190328.jmeyer.Added cleaning up user folders for users that have not logged in in over 30 days. Does not touch Helion, Special, Default User, Public, or All Users
	## 20191227.jmeyer.Adjusted removal to display only usernames of users that are being deleted, as they are being deleted. This is also written in the log now.
	if ($Optimizations -contains "Users")
	{
		Write-Host "Cleaning up unused User profiles in Users directory (Older than 30 days)..." -ForegroundColor Yellow
		$UserFolders = Get-CimInstance -ClassName Win32_UserProfile |
		Where-Object { ($_.localpath -notlike "*helion*") -and (!$_.Special) -and (($_.LastUseTime) -lt $DaysBack) }
		
		foreach ($User in $UserFolders)
		{
			$Username = Split-Path -Path $User.LocalPath -Leaf -Resolve
			Write-Host = "Deleting user: $($Username)" -ForegroundColor Red
			$User | Remove-CimInstance
		}
		Write-Host "Completed!" -ForegroundColor Green
	}
	elseif ($Optimizations -contains "Offboarding")
	{
		Write-Host "Cleaning up unused User profiles in Users directory (Older than 30 days)..." -ForegroundColor Yellow
		$UserFolders = Get-CimInstance -ClassName Win32_UserProfile | Where-Object { (!$_.Special) -and (($_.LastUseTime) -lt $DaysBack) }
		
		foreach ($User in $UserFolders)
		{
			$Username = Split-Path -Path $User.LocalPath -Leaf -Resolve
			Write-Host = "Deleting user: $($Username)" -ForegroundColor Red
			$User | Remove-CimInstance
		}
		
		Write-Host "Removing all helion account information..." -ForegroundColor Yellow
		$HelionAccounts = Get-CimInstance -ClassName Win32_UserProfile | Where-Object { ($_.localpath -like "*helion*") }
		
		foreach ($Account in $HelionAccounts)
		{
			$Username = Split-Path -Path $Account.LocalPath -Leaf -Resolve
			Write-Host = "Deleting user: $($Username)" -ForegroundColor Red
			$Account | Remove-CimInstance
		}
		Write-Host "Completed!" -ForegroundColor Green
	}
}
## 20210727.jmeyer.Adjusted $timeout variable time.
function InstallRSATGPMT($Timeout = 300)
{
	Write-Host "Starting RSAT GPO Job..." -ForegroundColor Yellow
	$RSATJob = Start-Job {
		Write-Host "Checking for RSAT: Group Policy Management Tools..." -ForegroundColor Yellow
		if ((Get-WindowsCapability -Name Rsat.GroupPolicy.Management.Tools* -Online).State -ne "Installed")
		{
			Write-Host "RSAT: Group Policy Management Tools are not installed." -ForegroundColor Yellow
			Write-Host "Installing RSAT: Group Policy Management Tools." -ForegroundColor Yellow
			Get-WindowsCapability -Name Rsat.GroupPolicy.Management.Tools* -Online | Add-WindowsCapability -Online
			## 20200814.jmeyer.Corrected if statement for installation of GP tools.
			if ((Get-WindowsCapability -Name Rsat.GroupPolicy.Management.Tools* -Online).State -eq "Installed")
			{
				Write-Host "RSAT: Group Policy Management Tools are installed." -ForegroundColor Green
				$Env:RSATGPMT = "Installed"
			}
			else
			{
				Write-Host "RSAT: Group Policy Management Tools did not install." -ForegroundColor Red
				$Env:RSATGPMT = $null
			}
		}
		else
		{
			Write-Host "RSAT: Group Policy Management Tools are already installed." -ForegroundColor Green
			$Env:RSATGPMT = "Installed"
		}
	}
	Receive-Job $RSATJob
	Write-Host "Job started!"
	## 20210727.jmeyer.**Move wait and GPUpdate to later in the script.**
}
function GPUpdate
{
	## 20200812.jmeyer.Rebuilt GPUpdate to a more modern approach.
	if ($DomainTest)
	{
		Write-Host "We are connected to the '$Env:USERDOMAIN' domain." -ForegroundColor Green
		if ([ref]$Env:RSATGPMT -eq "Installed")
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
function FlushDNS
{
	Write-Host "Flushing DNS..." -ForegroundColor Yellow;
	Clear-DnsClientCache
	Write-Host "DNS Flush completed." -ForegroundColor Green
}
function IECleanup
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
function EdgeCleanup
{
	## 20210922.jmeyer.Added Microsoft Edge cleanup.
	Write-Host "Checking to see if Microsoft Edge is installed..." -ForegroundColor Yellow
	if ($Edge)
	{
		Write-Host "Deleting Microsoft Edge cache..." -ForegroundColor Yellow
		Remove-Item -Path "$EdgeDIR\User Data\Default\*journal" -Force -Recurse -ErrorAction SilentlyContinue
		#Remove-Item -Path "$EdgeDIR\User Data\Default\Cookies" -Force -Recurse -ErrorAction SilentlyContinue
		Remove-Item -Path "$EdgeDIR\User Data\Default\Cache\*" -Force -Recurse -ErrorAction SilentlyContinue
		Remove-Item -Path "$EdgeDIR\User Data\Default\Storage\ext\*" -Force -Recurse -ErrorAction SilentlyContinue
		#Remove-Item -Path "$EdgeDIR\User Data\Default\Media Cache\*" -Force -Recurse -ErrorAction SilentlyContinue
		Remove-Item -Path "$EdgeDIR\User Data\Default\GPUCache\*" -Force -Recurse -ErrorAction SilentlyContinue
		#Remove-Item -Path "$EdgeDIR\User Data\Default\Application Cache\Cache\*" -Force -Recurse -ErrorAction SilentlyContinue
		#Remove-Item -Path "$EdgeDIR\User Data\Default\File System\*" -Force -Recurse -ErrorAction SilentlyContinue
		Remove-Item -Path "$EdgeDIR\User Data\Default\Service Worker\*" -Force -Recurse -ErrorAction SilentlyContinue
		Remove-Item -Path "$EdgeDIR\User Data\Default\JumpListIcons\*" -Force -Recurse -ErrorAction SilentlyContinue
		Remove-Item -Path "$EdgeDIR\User Data\Default\JumpListIconsOld\*" -Force -Recurse -ErrorAction SilentlyContinue
		Remove-Item -Path "$EdgeDIR\User Data\Default\Local Storage\*" -Force -Recurse -ErrorAction SilentlyContinue
		Remove-Item -Path "$EdgeDIR\User Data\Default\IndexedDB\*" -Force -Recurse -ErrorAction SilentlyContinue
		Remove-Item -Path "$EdgeDIR\User Data\Default\Pepper Data\Shockwave Flash\WritableRoot\*" -Force -Recurse -ErrorAction SilentlyContinue
		Remove-Item -Path "$EdgeDIR\User Data\ShaderCache\GPUCache\*" -Force -Recurse -ErrorAction SilentlyContinue
		#Remove-Item -Path "$EdgeDIR\ShaderCache\GPUCache\*" -Force -Recurse -ErrorAction SilentlyContinue
		Write-Host "Completed!" -ForegroundColor Green
	}
	else
	{
		Write-Host "Cannot find Microsoft Edge." -ForegroundColor Red
	}
	
	## 20220824.jmeyer.Added Edge optimizations. NOTE: Config files required!
	if ($Optimizations -contains "Edge" -or "All")
	{
		$EdgeFilePath = ".\ConfigurationFiles\EdgeSettings.json"
		If (Test-Path $EdgeFilePath)
		{
			Write-EventLog -EventId 80 -Message "Edge Policy Settings" -LogName 'Virtual Desktop Optimization' -Source 'EdgeVDOT' -EntryType Information
			Write-Host "[VDI Optimize] Edge Policy Settings" -ForegroundColor Cyan
			$EdgeSettings = Get-Content $EdgeFilePath | ConvertFrom-Json
			If ($EdgeSettings.Count -gt 0)
			{
				Write-EventLog -EventId 80 -Message "Processing Edge Policy Settings ($($EdgeSettings.Count) Hives)" -LogName 'Virtual Desktop Optimization' -Source 'EdgeVDOT' -EntryType Information
				Write-Verbose "Processing Edge Policy Settings ($($EdgeSettings.Count) Hives)"
				Foreach ($Key in $EdgeSettings)
				{
					If ($Key.VDIState -eq 'Enabled')
					{
						If ($key.RegItemValueName -eq 'DefaultAssociationsConfiguration')
						{
							Copy-Item .\ConfigurationFiles\DefaultAssociationsConfiguration.xml $key.RegItemValue -Force
						}
						If (Get-ItemProperty -Path $Key.RegItemPath -Name $Key.RegItemValueName -ErrorAction SilentlyContinue)
						{
							Write-EventLog -EventId 80 -Message "Found key, $($Key.RegItemPath) Name $($Key.RegItemValueName) Value $($Key.RegItemValue)" -LogName 'Virtual Desktop Optimization' -Source 'EdgeVDOT' -EntryType Information
							Write-Verbose "Found key, $($Key.RegItemPath) Name $($Key.RegItemValueName) Value $($Key.RegItemValue)"
							Set-ItemProperty -Path $Key.RegItemPath -Name $Key.RegItemValueName -Value $Key.RegItemValue -Force
						}
						Else
						{
							If (Test-path $Key.RegItemPath)
							{
								Write-EventLog -EventId 80 -Message "Path found, creating new property -Path $($Key.RegItemPath) -Name $($Key.RegItemValueName) -PropertyType $($Key.RegItemValueType) -Value $($Key.RegItemValue)" -LogName 'Virtual Desktop Optimization' -Source 'EdgeVDOT' -EntryType Information
								Write-Verbose "Path found, creating new property -Path $($Key.RegItemPath) Name $($Key.RegItemValueName) PropertyType $($Key.RegItemValueType) Value $($Key.RegItemValue)"
								New-ItemProperty -Path $Key.RegItemPath -Name $Key.RegItemValueName -PropertyType $Key.RegItemValueType -Value $Key.RegItemValue -Force | Out-Null
							}
							Else
							{
								Write-EventLog -EventId 80 -Message "Creating Key and Path" -LogName 'Virtual Desktop Optimization' -Source 'EdgeVDOT' -EntryType Information
								Write-Verbose "Creating Key and Path"
								New-Item -Path $Key.RegItemPath -Force | New-ItemProperty -Name $Key.RegItemValueName -PropertyType $Key.RegItemValueType -Value $Key.RegItemValue -Force | Out-Null
							}
							
						}
					}
				}
			}
			Else
			{
				Write-EventLog -EventId 80 -Message "No Edge Policy Settings Found!" -LogName 'Virtual Desktop Optimization' -Source 'EdgeVDOT' -EntryType Warning
				Write-Warning "No Edge Policy Settings found"
			}
		}
		Else
		{
			Write-Host "Foo, nothing to do here"
		}
	}
}
function ChromeCleanup
{
	## 20160510.jomeyer.Added Chrome cleanup
	Write-Host "Checking to see if Chrome is installed..." -ForegroundColor Yellow
	if ($Chrome)
	{
		Write-Host "Chrome is installed." -ForegroundColor Green
		Write-Host "Deleting Chrome cache..." -ForegroundColor Yellow
		Remove-Item -Path "$ChromeDIR\User Data\Default\*journal" -Force -Recurse -ErrorAction SilentlyContinue
		Remove-Item -Path "$ChromeDIR\User Data\Default\Cookies" -Force -Recurse -ErrorAction SilentlyContinue
		Remove-Item -Path "$ChromeDIR\User Data\Default\Cache\*" -Force -Recurse -ErrorAction SilentlyContinue
		Remove-Item -Path "$ChromeDIR\User Data\Default\Storage\ext\*" -Force -Recurse -ErrorAction SilentlyContinue
		Remove-Item -Path "$ChromeDIR\User Data\Default\Media Cache\*" -Force -Recurse -ErrorAction SilentlyContinue
		Remove-Item -Path "$ChromeDIR\User Data\Default\GPUCache\*" -Force -Recurse -ErrorAction SilentlyContinue
		Remove-Item -Path "$ChromeDIR\User Data\Default\Application Cache\Cache\*" -Force -Recurse -ErrorAction SilentlyContinue
		Remove-Item -Path "$ChromeDIR\User Data\Default\File System\*" -Force -Recurse -ErrorAction SilentlyContinue
		Remove-Item -Path "$ChromeDIR\User Data\Default\Service Worker\*" -Force -Recurse -ErrorAction SilentlyContinue
		Remove-Item -Path "$ChromeDIR\User Data\Default\JumpListIcons\*" -Force -Recurse -ErrorAction SilentlyContinue
		Remove-Item -Path "$ChromeDIR\User Data\Default\JumpListIconsOld\*" -Force -Recurse -ErrorAction SilentlyContinue
		Remove-Item -Path "$ChromeDIR\User Data\Default\Local Storage\*" -Force -Recurse -ErrorAction SilentlyContinue
		Remove-Item -Path "$ChromeDIR\User Data\Default\IndexedDB\*" -Force -Recurse -ErrorAction SilentlyContinue
		Remove-Item -Path "$ChromeDIR\User Data\Default\Pepper Data\Shockwave Flash\WritableRoot\*" -Force -Recurse -ErrorAction SilentlyContinue
		Remove-Item -Path "$ChromeDIR\User Data\ShaderCache\GPUCache\*" -Force -Recurse -ErrorAction SilentlyContinue
		Remove-Item -Path "$ChromeDIR\ShaderCache\GPUCache\*" -Force -Recurse -ErrorAction SilentlyContinue
		Write-Host "Completed!" -ForegroundColor Green
	}
	else
	{
		Write-Host "Cannot find Google Chrome." -ForegroundColor Red
	}
}
function FirefoxCleanup
{
	## 20161222.jmeyer.Added firefox cache removal
	Write-Host "Checking to see if Mozilla Firefox is installed..." -ForegroundColor Yellow
	if ($Firefox)
	{
		Write-Host "Mozilla Firefox is installed." -ForegroundColor Green
		Write-Host "Deleting Mozilla Firefox cache..." -ForegroundColor Yellow
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
## 20220824.jmeyer.Disable and remove Windows Media Player
function WindowsMediaPlayer
{
	If ($Optimizations -contains "WindowsMediaPlayer" -or "All")
	{
		try
		{
			Write-EventLog -EventId 10 -Message "[VDI Optimize] Disable / Remove Windows Media Player" -LogName 'Virtual Desktop Optimization' -Source 'WindowsMediaPlayer' -EntryType Information
			Write-Host "[VDI Optimize] Disable / Remove Windows Media Player" -ForegroundColor Cyan
			Disable-WindowsOptionalFeature -Online -FeatureName WindowsMediaPlayer -NoRestart | Out-Null
			Get-WindowsPackage -Online -PackageName "*Windows-mediaplayer*" | ForEach-Object {
				Write-EventLog -EventId 10 -Message "Removing $($_.PackageName)" -LogName 'Virtual Desktop Optimization' -Source 'WindowsMediaPlayer' -EntryType Information
				Remove-WindowsPackage -PackageName $_.PackageName -Online -ErrorAction SilentlyContinue -NoRestart | Out-Null
			}
		}
		catch
		{
			Write-EventLog -EventId 110 -Message "Disabling / Removing Windows Media Player - $($_.Exception.Message)" -LogName 'Virtual Desktop Optimization' -Source 'WindowsMediaPlayer' -EntryType Error
		}
	}
}
## 20220824.jmeyer.Remove Appx Packages. NOTE: Config files required!
function AppxPackages
{
	If ($Optimizations -contains "AppxPackages" -or "All")
	{
		$AppxConfigFilePath = ".\ConfigurationFiles\AppxPackages.json"
		If (Test-Path $AppxConfigFilePath)
		{
			Write-EventLog -EventId 20 -Message "[VDI Optimize] Removing Appx Packages" -LogName 'Virtual Desktop Optimization' -Source 'AppxPackages' -EntryType Information
			Write-Host "[VDI Optimize] Removing Appx Packages" -ForegroundColor Cyan
			$AppxPackage = (Get-Content $AppxConfigFilePath | ConvertFrom-Json).Where({ $_.VDIState -eq 'Disabled' })
			If ($AppxPackage.Count -gt 0)
			{
				Foreach ($Item in $AppxPackage)
				{
					try
					{
						Write-EventLog -EventId 20 -Message "Removing Provisioned Package $($Item.AppxPackage)" -LogName 'Virtual Desktop Optimization' -Source 'AppxPackages' -EntryType Information
						Write-Verbose "Removing Provisioned Package $($Item.AppxPackage)"
						Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -like ("*{0}*" -f $Item.AppxPackage) } | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Out-Null
						
						Write-EventLog -EventId 20 -Message "Attempting to remove [All Users] $($Item.AppxPackage) - $($Item.Description)" -LogName 'Virtual Desktop Optimization' -Source 'AppxPackages' -EntryType Information
						Write-Verbose "Attempting to remove [All Users] $($Item.AppxPackage) - $($Item.Description)"
						Get-AppxPackage -AllUsers -Name ("*{0}*" -f $Item.AppxPackage) | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
						
						Write-EventLog -EventId 20 -Message "Attempting to remove $($Item.AppxPackage) - $($Item.Description)" -LogName 'Virtual Desktop Optimization' -Source 'AppxPackages' -EntryType Information
						Write-Verbose "Attempting to remove $($Item.AppxPackage) - $($Item.Description)"
						Get-AppxPackage -Name ("*{0}*" -f $Item.AppxPackage) | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
					}
					catch
					{
						Write-EventLog -EventId 120 -Message "Failed to remove Appx Package $($Item.AppxPackage) - $($_.Exception.Message)" -LogName 'Virtual Desktop Optimization' -Source 'AppxPackages' -EntryType Error
						Write-Warning "Failed to remove Appx Package $($Item.AppxPackage) - $($_.Exception.Message)"
					}
				}
			}
			Else
			{
				Write-EventLog -EventId 20 -Message "No AppxPackages found to disable" -LogName 'Virtual Desktop Optimization' -Source 'AppxPackages' -EntryType Warning
				Write-Warning "No AppxPackages found to disable in $AppxConfigFilePath"
			}
		}
		Else
		{
			
			Write-EventLog -EventId 20 -Message "Configuration file not found - $AppxConfigFilePath" -LogName 'Virtual Desktop Optimization' -Source 'AppxPackages' -EntryType Warning
			Write-Warning "Configuration file not found -  $AppxConfigFilePath"
		}
		
	}
}
## 20220824.jmeyer.Disable Windows Traces. NOTE: Config files required!
function AutoLoggers
{
	If ($Optimizations -contains "AutoLoggers" -or "All")
	{
		$AutoLoggersFilePath = ".\ConfigurationFiles\Autologgers.Json"
		If (Test-Path $AutoLoggersFilePath)
		{
			Write-EventLog -EventId 50 -Message "Disable AutoLoggers" -LogName 'Virtual Desktop Optimization' -Source 'AutoLoggers' -EntryType Information
			Write-Host "[VDI Optimize] Disable Autologgers" -ForegroundColor Cyan
			$DisableAutologgers = (Get-Content $AutoLoggersFilePath | ConvertFrom-Json).Where({ $_.Disabled -eq 'True' })
			If ($DisableAutologgers.count -gt 0)
			{
				Write-EventLog -EventId 50 -Message "Disable AutoLoggers" -LogName 'Virtual Desktop Optimization' -Source 'AutoLoggers' -EntryType Information
				Write-Verbose "Processing Autologger Configuration File"
				Foreach ($Item in $DisableAutologgers)
				{
					Write-EventLog -EventId 50 -Message "Updating Registry Key for: $($Item.KeyName)" -LogName 'Virtual Desktop Optimization' -Source 'AutoLoggers' -EntryType Information
					Write-Verbose "Updating Registry Key for: $($Item.KeyName)"
					Try
					{
						New-ItemProperty -Path ("{0}" -f $Item.KeyName) -Name "Start" -PropertyType "DWORD" -Value 0 -Force -ErrorAction Stop | Out-Null
					}
					Catch
					{
						Write-EventLog -EventId 150 -Message "Failed to add $($Item.KeyName)`n`n $($Error[0].Exception.Message)" -LogName 'Virtual Desktop Optimization' -Source 'AutoLoggers' -EntryType Error
					}
					
				}
			}
			Else
			{
				Write-EventLog -EventId 50 -Message "No Autologgers found to disable" -LogName 'Virtual Desktop Optimization' -Source 'AutoLoggers' -EntryType Warning
				Write-Verbose "No Autologgers found to disable"
			}
		}
		Else
		{
			Write-EventLog -EventId 150 -Message "File not found: $AutoLoggersFilePath" -LogName 'Virtual Desktop Optimization' -Source 'AutoLoggers' -EntryType Error
			Write-Warning "File Not Found: $AutoLoggersFilePath"
		}
	}
}
## 20220824.jmeyer.Disable Services. NOTE: Config files required!
function Services
{
	If ($Optimizations -contains "Services" -or "All")
	{
		$ServicesFilePath = ".\ConfigurationFiles\Services.json"
		If (Test-Path $ServicesFilePath)
		{
			Write-EventLog -EventId 60 -Message "Disable Services" -LogName 'Virtual Desktop Optimization' -Source 'Services' -EntryType Information
			Write-Host "[VDI Optimize] Disable Services" -ForegroundColor Cyan
			$ServicesToDisable = (Get-Content $ServicesFilePath | ConvertFrom-Json).Where({ $_.VDIState -eq 'Disabled' })
			
			If ($ServicesToDisable.count -gt 0)
			{
				Write-EventLog -EventId 60 -Message "Processing Services Configuration File" -LogName 'Virtual Desktop Optimization' -Source 'Services' -EntryType Information
				Write-Verbose "Processing Services Configuration File"
				Foreach ($Item in $ServicesToDisable)
				{
					Write-EventLog -EventId 60 -Message "Attempting to Stop Service $($Item.Name) - $($Item.Description)" -LogName 'Virtual Desktop Optimization' -Source 'Services' -EntryType Information
					Write-Verbose "Attempting to Stop Service $($Item.Name) - $($Item.Description)"
					try
					{
						Stop-Service $Item.Name -Force -ErrorAction SilentlyContinue
					}
					catch
					{
						Write-EventLog -EventId 160 -Message "Failed to disable Service: $($Item.Name) `n $($_.Exception.Message)" -LogName 'Virtual Desktop Optimization' -Source 'Services' -EntryType Error
						Write-Warning "Failed to disable Service: $($Item.Name) `n $($_.Exception.Message)"
					}
					Write-EventLog -EventId 60 -Message "Attempting to disable Service $($Item.Name) - $($Item.Description)" -LogName 'Virtual Desktop Optimization' -Source 'Services' -EntryType Information
					Write-Verbose "Attempting to disable Service $($Item.Name) - $($Item.Description)"
					Set-Service $Item.Name -StartupType Disabled
				}
			}
			Else
			{
				Write-EventLog -EventId 60 -Message "No Services found to disable" -LogName 'Virtual Desktop Optimization' -Source 'Services' -EntryType Warnnig
				Write-Verbose "No Services found to disable"
			}
		}
		Else
		{
			Write-EventLog -EventId 160 -Message "File not found: $ServicesFilePath" -LogName 'Virtual Desktop Optimization' -Source 'Services' -EntryType Error
			Write-Warning "File not found: $ServicesFilePath"
		}
	}
}
## 20220824.jmeyer.Disable Services. NOTE: Config files required!
function NetworkOptimization
{
	If ($Optimizations -contains "NetworkOptimizations" -or "All")
	{
		$NetworkOptimizationsFilePath = ".\ConfigurationFiles\LanManWorkstation.json"
		If (Test-Path $NetworkOptimizationsFilePath)
		{
			Write-EventLog -EventId 70 -Message "Configure LanManWorkstation Settings" -LogName 'Virtual Desktop Optimization' -Source 'NetworkOptimizations' -EntryType Information
			Write-Host "[VDI Optimize] Configure LanManWorkstation Settings" -ForegroundColor Cyan
			$LanManSettings = Get-Content $NetworkOptimizationsFilePath | ConvertFrom-Json
			If ($LanManSettings.Count -gt 0)
			{
				Write-EventLog -EventId 70 -Message "Processing LanManWorkstation Settings ($($LanManSettings.Count) Hives)" -LogName 'Virtual Desktop Optimization' -Source 'NetworkOptimizations' -EntryType Information
				Write-Verbose "Processing LanManWorkstation Settings ($($LanManSettings.Count) Hives)"
				Foreach ($Hive in $LanManSettings)
				{
					If (Test-Path -Path $Hive.HivePath)
					{
						Write-EventLog -EventId 70 -Message "Found $($Hive.HivePath)" -LogName 'Virtual Desktop Optimization' -Source 'NetworkOptimizations' -EntryType Information
						Write-Verbose "Found $($Hive.HivePath)"
						$Keys = $Hive.Keys.Where{ $_.SetProperty -eq $true }
						If ($Keys.Count -gt 0)
						{
							Write-EventLog -EventId 70 -Message "Create / Update LanManWorkstation Keys" -LogName 'Virtual Desktop Optimization' -Source 'NetworkOptimizations' -EntryType Information
							Write-Verbose "Create / Update LanManWorkstation Keys"
							Foreach ($Key in $Keys)
							{
								If (Get-ItemProperty -Path $Hive.HivePath -Name $Key.Name -ErrorAction SilentlyContinue)
								{
									Write-EventLog -EventId 70 -Message "Setting $($Hive.HivePath) -Name $($Key.Name) -Value $($Key.PropertyValue)" -LogName 'Virtual Desktop Optimization' -Source 'NetworkOptimizations' -EntryType Information
									Write-Verbose "Setting $($Hive.HivePath) -Name $($Key.Name) -Value $($Key.PropertyValue)"
									Set-ItemProperty -Path $Hive.HivePath -Name $Key.Name -Value $Key.PropertyValue -Force
								}
								Else
								{
									Write-EventLog -EventId 70 -Message "New $($Hive.HivePath) -Name $($Key.Name) -Value $($Key.PropertyValue)" -LogName 'Virtual Desktop Optimization' -Source 'NetworkOptimizations' -EntryType Information
									Write-Host "New $($Hive.HivePath) -Name $($Key.Name) -Value $($Key.PropertyValue)"
									New-ItemProperty -Path $Hive.HivePath -Name $Key.Name -PropertyType $Key.PropertyType -Value $Key.PropertyValue -Force | Out-Null
								}
							}
						}
						Else
						{
							Write-EventLog -EventId 70 -Message "No LanManWorkstation Keys to create / update" -LogName 'Virtual Desktop Optimization' -Source 'NetworkOptimizations' -EntryType Warning
							Write-Warning "No LanManWorkstation Keys to create / update"
						}
					}
					Else
					{
						Write-EventLog -EventId 70 -Message "Registry Path not found $($Hive.HivePath)" -LogName 'Virtual Desktop Optimization' -Source 'NetworkOptimizations' -EntryType Warning
						Write-Warning "Registry Path not found $($Hive.HivePath)"
					}
				}
			}
			Else
			{
				Write-EventLog -EventId 70 -Message "No LanManWorkstation Settings foun" -LogName 'Virtual Desktop Optimization' -Source 'NetworkOptimizations' -EntryType Warning
				Write-Warning "No LanManWorkstation Settings found"
			}
		}
		Else
		{
			Write-EventLog -EventId 70 -Message "File not found - $NetworkOptimizationsFilePath" -LogName 'Virtual Desktop Optimization' -Source 'NetworkOptimizations' -EntryType Warning
			Write-Warning "File not found - $NetworkOptimizationsFilePath"
		}
		
		# NIC Advanced Properties performance settings for network biased environments
		Write-EventLog -EventId 70 -Message "Configuring Network Adapter Buffer Size" -LogName 'Virtual Desktop Optimization' -Source 'NetworkOptimizations' -EntryType Information
		Write-Host "[VDI Optimize] Configuring Network Adapter Buffer Size" -ForegroundColor Cyan
		Set-NetAdapterAdvancedProperty -DisplayName "Send Buffer Size" -DisplayValue 4MB -NoRestart
        <#  NOTE:
            Note that the above setting is for a Microsoft Hyper-V VM.  You can adjust these values in your environment...
            by querying in PowerShell using Get-NetAdapterAdvancedProperty, and then adjusting values using the...
            Set-NetAdapterAdvancedProperty command.
        #>
	}
}
function UserTempFiles
{
	## Remove all files and folders in user's Temporary Internet Files. 
	## 20170327.jmeyer.Added .NET Framework log file removal.
	## 20170627.jmeyer.Moved .NET log files to the System Level log files section to clean up script.
	## 20170627.jmeyer.Added temporary internet files.
	Write-Host "Deleting User level Temporary Internet files..." -ForegroundColor Yellow
	Remove-Item -Path "$UserDir\Local\Microsoft\Windows\Temporary Internet Files\*" -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "$UserDir\Local\Microsoft\Feeds Cache\*" -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "$UserDir\Local\Microsoft\Internet Explorer\DOMStore\*" -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "$UserDir\Local\Microsoft\Windows\INetCache\*" -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "$UserDir\Local\Packages\windows_ie_ac_001\AC\INetCache" -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "$UserDir\Local\Microsoft\Internet Explorer\Recovery" -Force -Recurse -ErrorAction SilentlyContinue
	Write-Host "Completed!" -ForegroundColor Green
	
	## Deletes all user level Temp files.
	## 20160705.jomeyer.Added removal of ThumbNail cache, Crash Dumps, and ElevatedDiagnostics.
	## 20170627.jmeyer.Moved the below to User level Temp files section to clean up script and added program usage log files.
	Write-Host "Deleting User level Temp files..." -ForegroundColor Yellow
	Remove-Item -Path "$UserDir\Local\Temp\*" -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "$UserDir\Roaming\Microsoft\Windows\Cookies\*.txt" -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "$UserDir\Local\Microsoft\Explorer\thumb*.db" -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "$UserDir\Local\CrashDumps\*" -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "$UserDir\Local\ElevatedDiagnostics\*" -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "$UserDir\Local\Microsoft\CLR_v4.0" -Force -Recurse -ErrorAction SilentlyContinue
	Write-Host "Completed!" -ForegroundColor Green
	
	## Delets all files and folders in user's Office Cache folder.
	## 20160512.jomeyer.added office cache. This is not removed when Temp Inet Files are removed.
	Write-Host "Deleting User level Office Internet cache..." -ForegroundColor Yellow
	Remove-Item -Path "$UserDir\Local\Microsoft\Windows\Temporary Internet Files\Content.MSO" -Force -Recurse -ErrorAction SilentlyContinue
	Write-Host "Completed!" -ForegroundColor Green
	
	## 20170127.jmeyer.Moved Outlook cache clearing together. Easier to track items in the script.
	## Delets all files and folders in user's Outlook cache folder.
	## 20160512.jomeyer.added Outlook cache. Temp Inet Files are already cleaned up, this is included in that.
	Write-Host "Deleting User level Outlook Internet cache..." -ForegroundColor Yellow
	Remove-Item -Path "$UserDir\Local\Microsoft\Windows\Temporary Internet Files\Content.Outlook" -Force -Recurse -ErrorAction SilentlyContinue
	Write-Host "Completed!" -ForegroundColor Green
	
	## 20170127.jmeyer.Removed deletion of Recent documents history.
	
	## Delets all files and folders in user's Word cache folder.
	## 20160512.jomeyer.added office cache. This is not removed when Temp Inet Files are removed.
	Write-Host "Deleting User level Word Internet cache..." -ForegroundColor Yellow
	Remove-Item -Path "$UserDir\Local\Microsoft\Windows\Temporary Internet Files\Content.Word" -Force -Recurse -ErrorAction SilentlyContinue
	Write-Host "Completed!" -ForegroundColor Green
	
	## Delets all files and folders in user's InfoPath Cache folder.
	## 20160419.jomeyer.No longer remove directory, only remove files in the directory.
	Write-Host "Deleting User level InfoPath cache..." -ForegroundColor Yellow
	Remove-Item -Path "$UserDir\Local\Microsoft\InfoPath\*" -Force -Recurse -ErrorAction SilentlyContinue
	Write-Host "Completed!" -ForegroundColor Green
}
function JavaCache
{
	## 20160728.jomeyer.Added Java cache.
	Write-Host "Checking for User level Java Cache..." -ForegroundColor Yellow
	if ($JavaCacheTest)
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
function AdobeAcrobat
{
	## 20161109.jmeyer.Added Adobe cache check.
	## 20161226.jmeyer.Added Adobe Acrobat Standard/Pro cache.
	Write-Host "Checking for User level Adobe Cache..." -ForegroundColor Yellow
	if ($AdobeReaderCacheTest -or $AdobeAcrobatCacheTest)
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
function AdobeFlash
{
	## 20170327.jmeyer.Added Flash Player cache removal.
	Write-Host "Checking for User level Flash Player cache..." -ForegroundColor Yellow
	if ($AdobeFlashCacheTest)
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
function OfficeCleanup
{
	## 20160512.jomeyer.Added removal of Office cache.
	## 20160707.jomeyer.Office 2010/13/16 cache locations.
	Write-Host "Checking for Microsoft Office Cache..." -ForegroundColor Yellow
	if ($Office10)
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
	
	if ($Office13)
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
	
	if ($Office16)
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
## 20220824.jmeyer.Combined SystemTempFiles and SystemLogFiles together in the same function to simplify script. 
function SystemFiles
{
	## Removes all files in the Windows Temp folder.
	Write-Host "Removing System level Temp files..." -ForegroundColor Yellow
	Remove-Item -Path $env:TEMP\* -Force -Recurse -ErrorAction SilentlyContinue
	Write-Host "Completed." -ForegroundColor Green
	
	## 20160706.jomeyer.Added prefetch data.
	Write-Host "Removing System level Prefetch Data..." -ForegroundColor Yellow
	Remove-Item -Path C:\Windows\Prefetch\*.pf -Force -Recurse -ErrorAction SilentlyContinue
	Write-Host "Completed." -ForegroundColor Green
	
	## 20161223.jmeyer.Added FontCache.
	Write-Host "Removing System level FontCache..." -ForegroundColor Yellow
	Remove-Item C:\Windows\ServiceProfiles\LocalService\AppData\Local\FontCache* -Force -Recurse -ErrorAction SilentlyContinue
	Write-Host "Completed." -ForegroundColor Green
	
	## 20220824.jmeyer.Combining several type of files and removing regardless of directory.
	Write-Host "Removing .tmp, .etl, .evtx, thumbcache*.db, *.log files not in use" -ForegroundColor Yellow
	Get-ChildItem -Path C:\ -Include *.tmp, *.dmp, *.etl, *.evtx, thumbcache*.db, *.log -File -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -ErrorAction SilentlyContinue
	Write-Host "Completed." -ForegroundColor Green
	
	## 20170627.jmeyer.Added more log files and moved .NET log files to this section.
	## 20170125.jmeyer.Added Windows Log file removal. Several machines shows several GB of log data.
	Write-Host "Removing System level log files..." -ForegroundColor Yellow
	Remove-Item -Path $env:windir\Logs\CBS\*.log -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path $env:windir\Microsoft.NET\Framework\*.log -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path $env:windir\Microsoft.NET\Framework64\*.log -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path $env:windir\Microsoft.NET\Framework64\*.log -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path $env:windir\Performance\WinSAT\*.log -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path $env:windir\Panther\UnattendGC\*.log -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path $env:windir\system32\config\systemprofile\AppData\Local\Microsoft\CLR_v4.0\UsageLogs\ -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path $env:windir\SysWOW64\config\systemprofile\AppData\Local\Microsoft\CLR_v4.0_32\UsageLogs\ -Force -Recurse -ErrorAction SilentlyContinue
	## 20220824.jmeyer.Expanding on removal of WER report archives
	Remove-Item -Path $env:ProgramData\Microsoft\Windows\WER\Temp\* -Recurse -Force -ErrorAction SilentlyContinue
	Remove-Item -Path $env:ProgramData\Microsoft\Windows\WER\ReportArchive\* -Recurse -Force -ErrorAction SilentlyContinue
	Remove-Item -Path $env:ProgramData\Microsoft\Windows\WER\ReportQueue\* -Recurse -Force -ErrorAction SilentlyContinue
	
	Clear-BCCache -Force -ErrorAction SilentlyContinue
	
	Write-Host "Completed!" -ForegroundColor Green
}
function CleanIISLogFiles
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
			Get-item $Item | Remove-Item -Verbose -Force -ErrorAction SilentlyContinue
		}
	}
	else
	{
		Write-Host "No items to be deleted today (Get-Date).DateTime" | Add-Content $IISLog
	}
	Write-Output "Cleanup of log files older than $14DaysBack completed..."
}
function HelionUSMT
{
	## 20190603.jmeyer.Removing USMT folder if it exists.
	Write-Host "Checking for Helion USMT folder..." -ForegroundColor Yellow
	if ($HelionUSMT)
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
function CleanCTemp
{
	## 20200811.jmeyer.Added cleanup of C:\Temp if over 500MB and older than 30 days old.
	## 20230130.jmeyer.Added cleanup of C:\Temp if over 100MB and older than 30 days old.
	Write-Host "Checking for folder: $CTempPath" -ForegroundColor Yellow
	if ($CTempTest)
	{
		Write-Host "Found folder: $CTempPath" -ForegroundColor Green
		if ($Optimizations -contains "Offboarding")
		{
			Remove-Item -LiteralPath $CTempPath -Force -Recurse
		}
		else
		{
			Write-Host "Checking folder size..." -ForegroundColor Yellow
			if ($CTempSize -ge .1)
			{
				Write-Host "Folder is $CTempSize GB. Deleting files older than $DaysBack days old." -ForegroundColor Yellow
				Get-ChildItem -Path $CTempPath | Where-Object { $_.LastWriteTime -lt $DaysBack } | Remove-Item -Force -Recurse
				Write-Host "Completed!" -ForegroundColor Green
			}
			else
			{
				Write-Host "Folder is not large enough to delete. Continuing..." -ForegroundColor Yellow
			}
		}
	}
	else
	{
		Write-Host "Folder not found. Continuing..." -ForegroundColor Green
	}
}
function ClearRecycleBin
{
	## 20201205.jmeyer.Added clearing the Recylce Bin for all users.
	Write-Host "Clearing the Recycle Bin..." -ForegroundColor Yellow
	Clear-RecycleBin -DriveLetter C -Force
	Write-Host "Completed!" -ForegroundColor Green
}
## 20201226.jmeyer.Added removal of items in the Kaseya Patch folder that are older than 6 months.
function KaseyaPatchCleanu
{
	Write-Host "Removing items in the Kaseya Patch folder that are older than 6 months..." -ForegroundColor Yellow
	Get-ChildItem -Path $KPatchPath | Where-Object { $_.LastWriteTime -lt $KaseyaPatchDays } | Remove-Item -Force -Recurse
	Write-Host "Completed!" -ForegroundColor Green
}
function InstallCMTrace
{
	## 20220126.jmeyer.CMTrace download has been removed by Microsoft and is no longer available. Disabling function.
	
	## 20191227.jmeyer.Installing CMTrace for log viewing.
	## 20210322.jmeyer.Added try/catch to BITS due to random errors starting BITS. Added if statement to installation if download fails.
	if ($PSVersionTable.PSVersion.Major -ge 3)
	{
		Write-EventLog -LogName "Application" -Source "$ScriptName" -EventID 32701 -EntryType Information -Message "Checking for CMTrace." -Category 1 -RawData 10, 20
		if ($Architecture -eq "64-bit")
		{
			$CMTraceInstalled = Test-Path "C:\Program Files (x86)\ConfigMgr 2012 Toolkit R2\ClientTools\CMTrace.exe"
		}
		else
		{
			$CMTraceInstalled = Test-Path "C:\Program Files\ConfigMgr 2012 Toolkit R2\ClientTools\CMTrace.exe"
		}
		
		
		if ($CMTraceInstalled)
		{
			Write-Host "CMTrace is installed. Continuing..." -ForegroundColor Green
			Write-EventLog -LogName "Application" -Source "$ScriptName" -EventID 32701 -EntryType Information -Message "CMTrace is already installed." -Category 1 -RawData 10, 20
		}
		else
		{
			Write-Host "Installing CMTrace Log Viewer..."
			$CMtraceDL = "https://download.microsoft.com/download/5/0/8/508918E1-3627-4383-B7D8-AA07B3490D21/ConfigMgrTools.msi"
			$CMTrace = "C:\Temp\ConfigMgrTools.msi"
			try
			{
				Start-BitsTransfer -Source $CMtraceDL -Destination $CMTrace -ErrorAction Stop
			}
			catch
			{
				Write-Host "CMTrace didn't download. Unable to install." -ForegroundColor Yellow
				$error[0].Exception.Message
			}
			
			if ((Test-Path $CMTrace))
			{
				try
				{
					Start-Process $CMTrace -ArgumentList '/Quiet' -Wait
				}
				catch
				{
					Write-Warning "CMTrace did not install correctly!"
					$error[0].Exception.Message
					Write-EventLog -LogName "Application" -Source "$ScriptName" -EventID 32701 -EntryType Information -Message "CMTrace failed to install." -Category 1 -RawData 10, 20
				}
				
				if ($Architecture -eq "64-bit")
				{
					$CMTraceInstalled = Test-Path "C:\Program Files (x86)\ConfigMgr 2012 Toolkit R2\ClientTools\CMTrace.exe"
				}
				else
				{
					$CMTraceInstalled = Test-Path "C:\Program Files\ConfigMgr 2012 Toolkit R2\ClientTools\CMTrace.exe"
				}
				
				if ($CMTraceInstalled)
				{
					Write-Host "CMTrace installed! Continuing..." -ForegroundColor Green
					Write-EventLog -LogName "Application" -Source "$ScriptName" -EventID 32701 -EntryType Information -Message "CMTrace installed successfully." -Category 1 -RawData 10, 20
				}
				else
				{
					Write-Host "CMTrace did not install correctly!" -ForegroundColor Yellow
					Write-EventLog -LogName "Application" -Source "$ScriptName" -EventID 32701 -EntryType Information -Message "CMTrace failed to install." -Category 1 -RawData 10, 20
				}
				
				Remove-Item $CMTrace -Force
			}
		}
	}
}
function SFC
{
	if ($Optimizations -contains "SFC")
	{
		Write-Host "Starting System File Checker..." -ForegroundColor Yellow
		Write-EventLog -LogName "Application" -Source "$ScriptName" -EventID 32701 -EntryType Information -Message "Performing SFC Scan." -Category 1 -RawData 10, 20
		SFC /SCANNOW
	}
}
## 20220531.jmeyer.Added DISM Component Cleanup.
function DISM
{
	if ($Optimizations -contains "DISM")
	{
		Write-Host "Starting Deployment Image Servicing and Management (DISM) with Restore Health..." -ForegroundColor Yellow
		Write-EventLog -LogName "Application" -Source "$ScriptName" -EventID 32701 -EntryType Information -Message "Performing DISM with Restore Health." -Category 1 -RawData 10, 20
		## This attempts to locate corruption or missing components and attemps to repair them.
		DISM /online /Cleanup-Image /RestoreHealth
		Write-Host "Starting Deployment Image Servicing and Management (DISM) with Component Cleanup..." -ForegroundColor Yellow
		Write-EventLog -LogName "Application" -Source "$ScriptName" -EventID 32701 -EntryType Information -Message "Performing DISM with Component Cleanup." -Category 1 -RawData 10, 20
		## This cleans up the C:\Windows\WinSxS folder properly.
		DISM /online /Cleanup-Image /StartComponentCleanup /ResetBase
	}
}
function DiskCleanupCheck
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
		while ((Get-CimInstance win32_process | Where-Object { $_.processname -eq 'cleanmgr.exe' } | Measure-Object).count)
		Write-Host "Disk Cleanup has completed." -ForegroundColor Green
		## Restarts the Windows Update service.
		Get-Service -Name wuauserv | Start-Service -Verbose
		## BITS will restart automatically when needed.
		Write-Host "Gathering HDD information..." -ForegroundColor Yellow
	}
	else
	{
		Write-Host "Disk Cleanup is not running, continuing." -ForegroundColor Yellow
		## Restarts the Windows Update service.
		Get-Service -Name wuauserv | Start-Service -Verbose
		## BITS will restart automatically when needed.
		Write-Host "Gathering HDD information..." -ForegroundColor Yellow
	}
}
function DiskSpaceAfter
{
	## Gather HDD size and free space after cleaning. Used for ticketing purposes.
	$Env:After = Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DriveType -eq "3" } |
	Select-Object SystemName,
				  @{ Name = "Drive"; Expression = { ($_.DeviceID) } },
				  @{ Name = "Size (GB)"; Expression = { "{0:N1}" -f ($_.Size / 1GB) } },
				  @{ Name = "FreeSpace (GB)"; Expression = { "{0:N1}" -f ($_.Freespace / 1GB) } },
				  @{ Name = "PercentFree"; Expression = { "{0:P1}" -f ($_.FreeSpace / $_.Size) } } |
	Format-Table -AutoSize | Out-String
	
	$Env:Size = Get-ChildItem C:\Users\* -Include *.iso, *.vhd -Recurse | Sort-Object Length -Descending |
	Select-Object Name, Directory, @{ Name = "Size (GB)"; Expression = { "{0:N2}" -f ($_.Length / 1GB) } } |
	Format-Table -AutoSize | Out-String
	$Env:FSpaceAfter = (Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'").FreeSpace / 1GB
	
	## 20210707.jmeyer.Adjusted variables for space reporting.
	$Math = ($Env:FSpaceAfter - $Env:FSpaceBefore)
	$env:SpaceSaved = [math]::Round($Math, 2)
	Write-Host "Completed!" -ForegroundColor Green
	## Finished gathering space information
}
## jmeyer.20210210.Renamed function from Housecleaning to Reporting
function Reporting
{
	# Sends some before and after info for ticketing purposes
	Write-Host "Before: $Env:Before" -ForegroundColor Cyan
	Write-Host "After: $Env:After" -ForegroundColor Cyan
	Write-Host "$Env:Size" -ForegroundColor Cyan
	Write-Host "We have cleaned up $($Env:SpaceSaved)GB of space." -ForegroundColor Green
	# 20170426.jmeyer.Cleaned up time reporting.
	$TotalTime = (New-TimeSpan -Start $StartDate -End (Get-Date).ToShortTimeString()).TotalMinutes
	Write-Host "Total time for cleanup was $TotalTime minutes." -ForegroundColor Green
}
function WorkstationRestart
{
	## 20201204.jmeyer.Removing restart/logoff option if running for offboarding.
	if ($Optimizations -notcontains "Offboarding")
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
			## 20200911.jmeyer.Removed CimInstance restart and now using native PowerShell.
			## Stops Log.
			if ($PSVersionTable.PSVersion.Major -ge 3)
			{
				Write-Warning "Stopping log.."
				Write-EventLog -LogName "Application" -Source "$ScriptName" -EventID 32701 -EntryType Information -Message "The $ScriptVersion script has ended." -Category 1 -RawData 10, 20
				Stop-Transcript
			}
			Restart-Computer -Force -Delay 5
		}
		else
		{
			Write-Host "Please logout!"
#			Write-Warning "A Logout will commence automatically in 10 seconds."
#			Start-Sleep -Seconds $timeBeforeStart
#			
#			$waitSeconds .. 1 | Foreach-Object `
#			{
#				Write-Host "Time Remaining: $_" -ForegroundColor Yellow
#				Start-Sleep -Seconds 1
#			}
#			## Logs out
#			## 20210325.jmeyer.Adjusted CimInstance for logout.
#			Invoke-CimMethod -MethodName Win32Shutdown -ClassName Win32_OperatingSystem -Arguments @{ Flags = 4 }
		}
	}
}
##20210727.jmeyer.Moved WorkstationRestart function into ScriptEnding function to simplify ending.
function ScriptEnding ($DeleteFiles)
{
	Write-Host "Cleaning up..." -ForegroundColor DarkYellow
	$DebugPreference = 'SilentlyContinue'
	## Removing all script files for security reasons.
	Write-Host "Removing script files for security purposes..." -ForegroundColor Red
	if (-not ([String]::IsNullOrEmpty($DeleteFiles)))
	{
		
		foreach ($file in $DeleteFiles)
		{
			Remove-Item -Path "$DeleteFiles" -Force -Recurse -Verbose
		}
	}
	## Self destructs script.
	Remove-Item -Path "$PSCommandPath" -Force -Verbose
	Write-Host "Removing any log files that were created over $DaysBack ago..." -ForegroundColor Red
	Get-ChildItem -Path "C:\Logs\$ScriptName.*" | Where-Object { $_.LastWriteTime -lt $DaysBack } | Remove-Item -Force -Recurse -Verbose
	Write-Host "File deletion completed" -ForegroundColor Green
	if ($ScriptIntelligence -eq "Workstation")
	{
		WorkstationRestart
	}
	## Stops Log.
	if ($PSVersionTable.PSVersion.Major -ge 3)
	{
		Write-Host "Stopping log..." -ForegroundColor Red
		Write-EventLog -Message "The $ScriptFullName script has ended." -EventID 32701 -EntryType Information -LogName "Application" -Source "$ScriptName" -Category 1 -RawData 10, 20
		Stop-Transcript
	}
	## Clearing all variable content for security reasons.
	Clear-Variable -Name * -Force -ErrorAction SilentlyContinue
	exit
}
function ServerCleanup
{
	## 20200812.jmeyer.Server Cleanup function.
	#InstallCMTrace
	DiskSpaceBefore
	ProcessWarning
	ProcessTermination
	DiskCleanup
	CleanIISLogFiles
	InstallRSATGPMT
	FlushDNS
	IECleanup
	EdgeCleanup
	ChromeCleanup
	FirefoxCleanup
	JavaCache
	#KaseyaPatchCleanup
	CleanCTemp
	Win10UpgradeCleanup
	ClearRecycleBin
	DiskCleanupCheck
	DiskSpaceAfter
	Reporting
}
function WorkstationCleanup
{
	## 20200812.jmeyer.Workstation Cleanup function.
	DiskSpaceBefore
	ProcessWarning
	ProcessTermination
	DiskCleanup
	#InstallCMTrace
	InstallRSATGPMT
	StartupItems
	SFC
	DISM
	UserCleanup
	FlushDNS
	IECleanup
	EdgeCleanup
	ChromeCleanup
	FirefoxCleanup
	UserTempFiles
	JavaCache
	AdobeAcrobat
	AdobeFlash
	OfficeCleanup
	SystemFiles
	HelionUSMT
	CleanCTemp
	Win10UpgradeCleanup
	ClearRecycleBin
	GPUpdate
	DiskCleanupCheck
	DiskSpaceAfter
	Reporting
}
## 20170327.jmeyer.Removed all file checks.These are no longer needed as script has been reduced to a single file.
Write-Host "Setup complete!" -ForegroundColor Green
#endregion Functions
###############
## Variables ##
###############
#region Variables
Write-Host "Setting Variables..." -ForegroundColor Yellow
## 20170929.jmeyer.Moved to 1.6 for full deployment at Helion.
## 20200811.jmeyer.Moved to 1.7 due to combining several scripts.
$ScriptName = "Poor_System_Performance"
$ScriptVersionNumber = "1.7.9.0"
$ScriptVersion = "$ScriptName.$ScriptVersionNumber"
$Domain = $env:USERDOMAIN
$FQDN = (Get-ADDomain).DistinguishedName
$Computer = $env:COMPUTERNAME
$OSName = (Get-CimInstance Win32_OperatingSystem).Caption
$Architecture = (Get-CimInstance Win32_OperatingSystem).OSArchitecture
$BuildNumber = (Get-CimInstance Win32_OperatingSystem).BuildNumber
$StartDate = (Get-Date).ToShortTimeString()
$DaysBack = (Get-Date).AddDays(-30)
## 20200821.jmeyer.Added Try-Catch to the Domain Test.
try
{
	$DomainTest = (Test-ComputerSecureChannel)
}
catch [System.InvalidOperationException]
{
	$DomainTest = $null
}
if ($Optimizations -contains "VDI")
{
	$Optimizations =+ "Edge"
}
## GitHub Variables for AutoUpdate
$GHUserName = "OnyxXP"
## URL's for version check and script file
$GitHubVersion = "https://raw.githubusercontent.com/$GHUserName/$($ScriptName)/main/CurrentVersion.txt"
$NewScriptFile = "https://raw.githubusercontent.com/$GHUserName/$($ScriptName)/main/$($ScriptName).ps1"
## 20170125.jmeyer.Added all user's to cleanup.
$UserDir = "C:\Users\*\AppData"
$OfficeDir = "Local\Microsoft\Office"
$Chrome = Test-Path "$UserDir\Local\Google\Chrome"
$ChromeDIR = "$UserDir\Local\Google\Chrome"
$Edge = Test-Path "$UserDir\Local\Microsoft\Edge"
$EdgeDIR = "$UserDir\Local\Microsoft\Edge"
	## 20161222.jmeyer.Added firefox cache.
$FirefoxDirL = "$UserDir\Local\Mozilla\Firefox"
$FirefoxDirR = "$UserDir\Roaming\Mozilla\Firefox"
$Firefox = Test-Path "$UserDir\Local\Mozilla\Firefox"
$Office10 = Test-Path "$UserDir\$OfficeDir\14.0\OfficeFileCache"
$Office13 = Test-Path "$UserDir\$OfficeDir\15.0\OfficeFileCache"
$Office16 = Test-Path "$UserDir\$OfficeDir\16.0\OfficeFileCache"
$JavaCacheTest = Test-Path "$UserDir\LocalLow\Sun\Java\Deployment\cache"
$AdobeReaderCacheTest = Test-Path "$UserDir\Local\Adobe\Acrobat\"
$AdobeAcrobatCacheTest = Test-Path "$UserDir\Roaming\Adobe\Acrobat\Distiller*\"
$AdobeFlashCacheTest = Test-Path "$UserDir\Roaming\Macromedia\Flash Player\"
	## 20200814.jmeyer.Added Helion USMT and Windows 10 Upgrade file removals.
$HelionUSMT = Test-Path C:\temp\helion_usmt
$Windows10Upgrade = Test-Path C:\Windows10Upgrade
$Win10Upgrade = Test-Path C:\Win10Upgrade
$O365Install = Test-Path C:\O365Install
$ServerWin10Upgrade = (Get-CimInstance Win32_Share | Where-Object { $_.Name -like 'Win10Upgrade$' }).Path
$ServerO365Install = (Get-CimInstance Win32_Share | Where-Object { $_.Name -like 'O365Install$' }).Path
$TimeBeforeStart = 2
$WaitSeconds = 10
## 20180702.jmeyer.Added Firefox.
## 20230201.jmeyer.Added Edge.
$ProcessList = "iexplorer", "msedge", "chrome", "MSACCESS", "EXCEL", "INFOPATH", "ONENOTE", "OUTLOOK", "POWERPNT", "MSPUB", "WINWORD"
$ProcessArray = @("iexplorer", "msedge", "chrome", "MSACCESS", "EXCEL", "INFOPATH", "ONENOTE", "OUTLOOK", "POWERPNT", "MSPUB", "WINWORD")
$VName = "StateFlags0032"
$DirPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"
	## 20160419.jomeyer.removed System error minidump files
	## 20160430.jomeyer.Removed Windows 8 and XP options. These are obsolete.
	## 20210322.jmeyer.Removed options that are no longer available in Windows 10.
$TempFolders = @("Active Setup Temp Folders", "Content Indexer Cleaner", "D3D Shader Cache", "Delivery Optimization Files", "Downloaded Program Files",
	"Internet Cache Files", "Offline Pages Files", "Old ChkDsk Files", "Previous Installations", "Recycle Bin", "RetailDemo Offline Content",
	"Setup Log Files", "System error memory dump files", "System error minidump files", "Temporary Files", "Temporary Setup Files",
	"Temporary Sync Files", "Thumbnail Cache", "Update Cleanup", "Upgrade Discarded Files", "Windows Defender", "Windows Error Reporting Files",
	"Windows ESD installation files". "Windows Reset Log Files", "Windows Upgrade Log Files")
	## 20200814.jmeyer.Added C:\Temp file and Kaseya temp file removals.
$CTempPath = "C:\Temp"
$CTempTest = Test-Path "C:\Temp"
$CTempSize = (Get-ChildItem -Path $CTempPath | Measure-Object -Sum Length).Sum /1GB
$KPatchPath = 
$KaseyaPatchDays = (Get-Date).AddDays(-180)
$FreeSpace = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | Where-Object DeviceID -eq 'C:' | Select-Object @{ L = "FreeSpace"; E = { $_.FreeSpace/1GB } }, @{ L = "TotalSize"; E = { $_.Size/1GB } }
$PercentFree = ($FreeSpace.FreeSpace/$FreeSpace.TotalSize) * 100
$PercentRequired = 20.0
## Script support files to remove after completion.
$OptimizationsZip = "$PSScriptRoot\Config.zip"
$FilesToDelete = @($OptimizationsZip)
Write-Host "Finished setting up variables." -ForegroundColor Green
#endregion Variables
###########
## Setup ##
###########
#region InitialSetup
InitialSetup
#endregion InitialSetup
#############################
## Administrator Elevation ##
#############################
#region AdminElevation
AdminElevation
#endregion AdminElevation
#############
## Logging ##
#############
#region Logging
Logging
#endregion Logging
################
## AutoUpdate ##
################
#region AutoUpdate
AutoUpdate
#endregion AutoUpdate
###################
## Prerequisites ##
###################
#region Prerequisites
Write-Host "Checking Prerequisites..." -ForegroundColor Yellow
Prerequisites
#endregion Prerequisites
#############
## ACTIONS ##
#############
#region ACTIONS
Write-Host "Beginning cleanup..." -ForegroundColor Green
Write-EventLog -LogName "Application" -Source "$ScriptName" -EventID 32701 -EntryType Information -Message "Beginning cleanup." -Category 1 -RawData 10, 20

Write-Host "Checking Script Intelligence variable..." -ForegroundColor Yellow
if ($ScriptIntelligence -eq "Server")
{
	Write-Host "We are running on $OSName." -ForegroundColor Green
	Write-Host "Running server cleanup..." -ForegroundColor Green
	Write-EventLog -LogName "Application" -Source "$ScriptName" -EventID 32701 -EntryType Information -Message "Cleanup configured for Servers." -Category 1 -RawData 10, 20
	## Perform cleanup.
	ServerCleanup
}
elseif ($ScriptIntelligence -eq "Workstation")
{
	Write-Host "We are running on $OSName." -ForegroundColor Green
	Write-Host "Running workstation cleanup..." -ForegroundColor Green
	Write-EventLog -LogName "Application" -Source "$ScriptName" -EventID 32701 -EntryType Information -Message "Cleanup configured for Workstations." -Category 1 -RawData 10, 20
	## Perform cleanup.
	WorkstationCleanup
}
#endregion ACTIONS
######################
## Ending of script ##
######################
#region ENDING
ScriptEnding -DeleteFiles $FilesToDelete
#endregion ENDING
#############################
## Do not write below here ##
#############################