function isElevated {
    # are we running in elevated shell?
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        return $false
    } else {
        return $true
    }
}

function Get-HostDetails {
    Param (
        [switch]$json
    )

    $hostname = [System.Net.Dns]::GetHostName()
    $executiondate = Get-Date -UFormat "%A, %B %d, %Y %T %Z"
    $domain = Get-WMIObject Win32_ComputerSystem | Select-Object -ExpandProperty Domain
    $osinformation = @{}
    $osinformation.Add("OSName", (Get-WmiObject -class Win32_OperatingSystem).Caption)
    $osinformation.Add("OSVersion", (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").displayversion)
    $osinformation.Add("OSArchitecture", (Get-WmiObject -class Win32_OperatingSystem).OSArchitecture)
    $osinformation.Add("OSBuild", (Get-WmiObject -class Win32_OperatingSystem).BuildNumber)

    if ($json) {
        $hostinformation = @{"ExecutionDate" = $executiondate; "Hostname" = $hostname; "Domain" = $domain; "OSInformation" = $osinformation}
        return $hostinformation
    }
    else 
    { 
        Write-Host "Hostname: " -NoNewline
        Write-Host $hostname -ForegroundColor Green
        Write-Host "Domain: " -NoNewline
        Write-Host $domain -ForegroundColor Green
        Write-Host "Execution Date: " -NoNewline
        Write-Host $executiondate -ForegroundColor Green
        Write-Host "OS Name: " -NoNewline
        Write-Host $osinformation.OSName -ForegroundColor Green
        Write-Host "OS Version: " -NoNewline
        Write-Host $osinformation.OSVersion -ForegroundColor Green
        Write-Host "OS Architecture: " -NoNewline
        Write-Host $osinformation.OSArchitecture -ForegroundColor Green
        Write-Host "OS Build: " -NoNewline
        Write-Host $osinformation.OSBuild -ForegroundColor Green
    }
}

function Get-AuditPolicy {
    Param (
        [switch]$json
    )
    
    $replacements = "[^a-zA-Z_]"

    if ($json) {
        $auditpolicy = @{}
        $catorgies = auditpol /list /category /r | ConvertFrom-Csv | Select -ExpandProperty "Category/Subcategory"
        foreach ($catorgy in $catorgies) {
            $x = @{}
            $results = auditpol /get /category:$catorgy /r | ConvertFrom-Csv
            foreach ($result in $results) {
                $x.Add(($result.Subcategory -replace $replacements, '_'), $result."Inclusion Setting")
            }
            $auditpolicy.Add(($catorgy -replace $replacements, '_'), $x) | Out-Null
        }
        return $auditpolicy
    }
    else 
    { 
        $catorgies = auditpol /list /category /r | ConvertFrom-Csv | Select-Object -ExpandProperty "Category/Subcategory"
        foreach ($catorgy in $catorgies) {
            Write-Host $catorgy -ForegroundColor Green
            auditpol /get /category:$catorgy /r | ConvertFrom-Csv | Format-Table -AutoSize 'Subcategory', @{
                Label      = 'Inclusion Setting'
                Expression = {
                    switch ($_.'Inclusion Setting') {
                        'No Auditing' { $color = "5;31"; break }
                        'Success and Failure' { $color = '32'; break }
                        'Success' { $color = "33"; break }
                        default { $color = "0" }
                    }
                    $e = [char]27
                    "$e[${color}m$($_.'Inclusion Setting')${e}[0m"
                }
            }
        }
    }
}

function Get-PowerShellAuditPolicy {
    param (
        [switch]$json
    )

    if ($json) {
        $powershellauditpolicy = @{}
        $powershellauditpolicy.Add("ScriptBlockLogging", $(try {if ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue).EnableScriptBlockLogging -eq 1) {"Enabled"} else {"Disabled"}} catch {"Registry Key Not Found"}))
        $powershellauditpolicy.Add("ModuleLogging", $(try {if ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -ErrorAction SilentlyContinue).EnableModuleLogging -eq 1) {"Enabled"} else {"Disabled"}} catch {"Registry Key Not Found"}))
        $powershellauditpolicy.Add("ModuleNames", $(try {(Get-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames\")} catch {"Registry Key Not Found"}))
        $powershellauditpolicy.Add("Transcription", $(try {if ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription" -ErrorAction SilentlyContinue).EnableTranscripting -eq 1) {"Enabled"} else {"Disabled"}} catch {"Registry Key Not Found"}))
        $powershellauditpolicy.Add("TranscriptionOutputDirectory", $(try {(Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription" -ErrorAction SilentlyContinue).OutputDirectory} catch {"Registry Key Not Found"}))
        return $powershellauditpolicy
    } 
    else 
    {
        write-host "ScriptBlockLogging: " -NoNewline
        try {
            if ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue).EnableScriptBlockLogging -eq 1) {
                write-host "Enabled" -ForegroundColor Green
            }
            else {
                write-host "Disabled" -ForegroundColor Red
            }
        }
        catch {
            write-host "Registry Key Not Found" -ForegroundColor Red
        }
        write-host "ModuleLogging: " -NoNewline
        try {
            if ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -ErrorAction SilentlyContinue).EnableModuleLogging -eq 1) {
                write-host "Enabled" -ForegroundColor Green
            }
            else {
                write-host "Disabled" -ForegroundColor Red
            }
        }
        catch {
            write-host "Registry Key Not Found" -ForegroundColor Red
        }
        write-host "ModuleNames: " -NoNewline
        try {
            write-host (Get-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames\") -ForegroundColor Green
        }
        catch {
            write-host "Registry Key Not Found" -ForegroundColor Red
        }
        write-host "Transcription: " -NoNewline
        try {
            if ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription" -ErrorAction SilentlyContinue).EnableTranscripting -eq 1) {
                write-host "Enabled" -ForegroundColor Green
            }
            else {
                write-host "Disabled" -ForegroundColor Red
            }
        }
        catch {
            write-host "Registry Key Not Found" -ForegroundColor Red
        }
        write-host "TranscriptionOutputDirectory: " -NoNewline
        try {
            write-host (Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription" -ErrorAction SilentlyContinue).OutputDirectory -ForegroundColor Green
        }
        catch {
            write-host "Registry Key Not Found" -ForegroundColor Red
        }
    }
}

function Get-SysmonConfig {
    param (
        [switch]$json
    )

    if ($json) {
        $sysmonconfig = @{}
        $sysmonconfig.Add("SysmonConfig", $(try {if ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sysmon/Operational" -ErrorAction SilentlyContinue).Enabled -eq 1) {"Enabled"} else {"Disabled"}} catch {"Sysmon not installed"}))
        return $sysmonconfig
    }
    else 
    {
        write-host "SysmonConfig: " -NoNewline
        try {
            if ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sysmon/Operational" -ErrorAction SilentlyContinue).Enabled -eq 1) {
                write-host "Enabled" -ForegroundColor Green
            }
            else {
                write-host "Disabled" -ForegroundColor Red
            }
        }
        catch {
            write-host "Sysmon not installed" -ForegroundColor Red
        }
    }    
}

# main 
function Invoke-AuditCheck {
    param (
        [switch]$json,
        [Parameter(Mandatory=$false, HelpMessage="Output file name")] [string]$outputfile
    )

    if (-not (isElevated)) {
        Write-Host "This script must be run in an elevated shell" -ForegroundColor Red
        exit 1
    }
    
    if ($json) {
        $hostdetails = Get-HostDetails -json
        $auditpolicy = Get-AuditPolicy -json
        $powershellauditpolicy = Get-PowerShellAuditPolicy -json
        $sysmonconfig = Get-SysmonConfig -json
        $auditcheck = @{"HostDetails" = $hostdetails; "AuditPolicy" = $auditpolicy; "PowerShellAuditPolicy" = $powershellauditpolicy; "SysmonConfig" = $sysmonconfig}
        if ($outputfile.Length -ne 0) {
            $auditcheck | ConvertTo-Json -Depth 10 | Out-File $outputfile
            Write-Host "Audit check complete. Results saved to $outputfile" -ForegroundColor Green
        }
        else {
            $auditcheck | ConvertTo-Json -Depth 10
        }
    }
    else {
        Write-Host
        Write-Host "==============================================" -ForegroundColor Green
        Write-Host "Gathering host details" -ForegroundColor Green
        Get-HostDetails
    
        Write-Host
        Write-Host "==============================================" -ForegroundColor Green
        Write-Host "Gathering audit policy" -ForegroundColor Green
        Get-AuditPolicy

        Write-Host
        Write-Host "==============================================" -ForegroundColor Green
        Write-Host "Gathering PowerShell audit policy" -ForegroundColor Green
        Get-PowerShellAuditPolicy

        Write-Host
        Write-Host "==============================================" -ForegroundColor Green
        Write-Host "Gathering Sysmon config" -ForegroundColor Green
        Get-SysmonConfig

        Write-Host
    }
}

