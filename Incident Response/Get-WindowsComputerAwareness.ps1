<#
.SYNOPSIS
    Get-WindowsComputerAwareness.ps1
.DESCRIPTION
    This script will retrieve sustiational awareness information from the event logs on a Windows computer.
.PARAMETER ComputerName
    The name of the computer to retrieve the event logs from.
.PARAMETER Credential
    The credentials to use to connect to the computer.
.PARAMETER Lookback
    The number of days to look back in the event logs. Default is -1 (all events).
.PARAMETER ExportToCSV
    Export the results to a CSV file.
.PARAMETER All
    Retrieve all the events.
.PARAMETER SuccessfulLogons
    Retrieve the successful logons.
.PARAMETER FailedLogons
    Retrieve the failed logons.
.PARAMETER ExplicitCredentials
    Retrieve the explicit credentials.
.PARAMETER OutboundRDPConnections
    Retrieve the outbound RDP connections.
#>
[CmdletBinding()]
Param (
    [Parameter(Mandatory = $false)]
    [String]$ComputerName,
    [Parameter(Mandatory = $false)]
    [System.Management.Automation.PSCredential]$Credential,
    [Parameter(Mandatory = $false)]
    [Int]$Lookback = -1,
    [Parameter(Mandatory = $false)]
    [Switch]$ExportToCSV,
    [Parameter(Mandatory = $false)]
    [Switch]$All,
    [Parameter(Mandatory = $false)]
    [Switch]$SuccessfulLogons,
    [Parameter(Mandatory = $false)]
    [Switch]$FailedLogons,
    [Parameter(Mandatory = $false)]
    [Switch]$ExplicitCredentials,
    [Parameter(Mandatory = $false)]
    [Switch]$OutboundRDPConnections
)

# https://www.ired.team/offensive-security/enumeration-and-discovery/windows-event-ids-for-situational-awareness

Begin {
    # Check if we running as an administrator
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Host "This script must be run as an administrator." -ForegroundColor Red
        Break
    }

    # If the All switch was specified, set all the switches to true
    if ($All) {
        $SuccessfulLogons = $true
        $FailedLogons = $true
        $ExplicitCredentials = $true
        $OutboundRDPConnections = $true
    }

    # Check if at least one switch was specified
    if (-not ($SuccessfulLogons -or $FailedLogons -or $ExplicitCredentials -or $OutboundRDPConnections)) {
        Write-Host "You must specify at least one switch." -ForegroundColor Red
        Break
    }
    
    # Check if the lookback parameter was specified
    if ($Lookback) { $Lookback = $Lookback }

    # Set start and end time
    $StartTime = (Get-Date).AddDays($Lookback)
    $EndTime = (Get-Date)

    # If switch was specified, add it to the CollectEvents array
    $CollectEvents = @()
    if ($SuccessfulLogons) { $CollectEvents += "SuccessfulLogons" }
    if ($FailedLogons) { $CollectEvents += "FailedLogons" }
    if ($ExplicitCredentials) { $CollectEvents += "ExplicitCredentials" }
    if ($OutboundRDPConnections) { $CollectEvents += "OutboundRDPConnections" }

    # Create the arrays for required logs and events
    $RequiredLogs = @()
    foreach ($CollectEvent in $CollectEvents) {
        switch ($CollectEvent) {
            "SuccessfulLogons" {
                $SuccessfulLogonsEvents = @()
                $RequiredLogs += "Security"
            }
            "FailedLogons" {
                $FailedLogonsEvents = @()
                $RequiredLogs += "Security"
            }
            "ExplicitCredentials" {
                $ExplicitCredentialsEvents = @()
                $RequiredLogs += "Security"
            }
            "OutboundRDPConnections" {
                $OutboundRDPConnectionsEvents = @()
                $RequiredLogs += "Microsoft-Windows-TerminalServices-RDPClient/Operational"
            }
        }
    }

    # Remove duplicate logs
    $RequiredLogs = $RequiredLogs | Sort-Object | Get-Unique

    # Retrieve the required logs
    foreach ($log in $RequiredLogs) {
        switch ($log) {
            "Security" {
                # Create the filter for the Security logs
                $SecurityLogsFilter = @{}
                $SecurityLogsFilter.Add("LogName", "Security")
                $SecurityLogsFilter.Add("StartTime", $StartTime)
                $SecurityLogsFilter.Add("EndTime", $EndTime)
                $SecurityLogsFilter.Add("ProviderName", "Microsoft-Windows-Security-Auditing")

                # Get the Security logs
                Write-Host "Retrieving the Security logs ..." -ForegroundColor Green
                if ($ComputerName) {
                    try {
                        if ($Credential) {
                            $SecurityEvents = Get-WinEvent -ComputerName $ComputerName -Credential $Credential -FilterHashtable $SecurityLogsFilter
                        } else {
                            $SecurityEvents = Get-WinEvent -ComputerName $ComputerName -FilterHashtable $SecurityLogsFilter
                        }
                    }
                    catch {
                        Write-Host "Unable to connect to $ComputerName" -ForegroundColor Red
                        Write-Host $_
                        break
                    }
                } else {
                    $SecurityEvents = Get-WinEvent -FilterHashtable $SecurityLogsFilter
                }
            }
            "Microsoft-Windows-TerminalServices-RDPClient/Operational" {
                # Create the filter for the Microsoft-Windows-TerminalServices-RDPClient/Operational logs
                $RDPClientLogsFilter = @{}
                $RDPClientLogsFilter.Add("LogName", "Microsoft-Windows-TerminalServices-RDPClient/Operational")
                $RDPClientLogsFilter.Add("StartTime", $StartTime)
                $RDPClientLogsFilter.Add("EndTime", $EndTime)

                # Get the Microsoft-Windows-TerminalServices-RDPClient/Operational logs
                Write-Host "Retrieving the Microsoft-Windows-TerminalServices-RDPClient/Operational logs ..." -ForegroundColor Green
                if ($ComputerName) {
                    try {
                        if ($Credential) {
                            $RDPClientEvents = Get-WinEvent -ComputerName $ComputerName -Credential $Credential -FilterHashtable $RDPClientLogsFilter
                        } else {
                            $RDPClientEvents = Get-WinEvent -ComputerName $ComputerName -FilterHashtable $RDPClientLogsFilter
                        }
                    }
                    catch {
                        Write-Host "Unable to connect to $ComputerName" -ForegroundColor Red
                        Write-Host $_
                        break
                    }
                } else {
                    $RDPClientEvents = Get-WinEvent -FilterHashtable $RDPClientLogsFilter
                }
            }
        }
    }
}
Process {
    # Process the events
    foreach ($CollectEvent in $CollectEvents) {
        switch ($CollectEvent) {
            "SuccessfulLogons" {
                # Get the successful logons
                Write-Host "Retrieving the successful logons ..." -ForegroundColor Green
                $LogEvents = $SecurityEvents | Where-Object { $_.ID -eq 4624 }
                if ($LogEvents) {
                    $LogEvents | ForEach-Object {
                        $LogEvent = New-Object psobject
                        
                        # LogonType (https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624#logon-type))
                        switch ($_.Properties[8].Value) { 
                            0 { $LogonTypeDescription = "System" }
                            2 { $LogonTypeDescription = "Interactive" }
                            3 { $LogonTypeDescription = "Network" }
                            4 { $LogonTypeDescription = "Batch" }
                            5 { $LogonTypeDescription = "Service" }
                            7 { $LogonTypeDescription = "ScreenUnlock" }
                            8 { $LogonTypeDescription = "NetworkCleartext" }
                            9 { $LogonTypeDescription = "NewCredentials" }
                            10 { $LogonTypeDescription = "RemoteInteractive" }
                            11 { $LogonTypeDescription = "CachedInteractive" }
                            12 { $LogonTypeDescription = "CachedRemoteInteractive" }
                            13 { $LogonTypeDescription = "CachedUnlock" }
                        }

                        $subjecUser = $_.Properties[2].Value + "\" + $_.Properties[1].Value
                        $targetUser = $_.Properties[6].Value + "\" + $_.Properties[5].Value

                        $LogEvent | Add-Member -MemberType NoteProperty -Name "TimeCreated" -Value $_.TimeCreated
                        $LogEvent | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $_.MachineName
                        $LogEvent | Add-Member -MemberType NoteProperty -Name "LogonType" -Value $_.Properties[8].Value
                        $LogEvent | Add-Member -MemberType NoteProperty -Name "LogonTypeDescription" -Value $LogonTypeDescription
                        $LogEvent | Add-Member -MemberType NoteProperty -Name "LogonProcessName" -Value $_.Properties[9].Value
                        $LogEvent | Add-Member -MemberType NoteProperty -Name "AuthenticationPackageName" -Value $_.Properties[10].Value
                        $LogEvent | Add-Member -MemberType NoteProperty -Name "RestrictedAdminMode" -Value $_.Properties[21].Value
                        $LogEvent | Add-Member -MemberType NoteProperty -Name "ProcessId" -Value $_.Properties[16].Value
                        $LogEvent | Add-Member -MemberType NoteProperty -Name "ProcessName" -Value $_.Properties[17].Value
                        $LogEvent | Add-Member -MemberType NoteProperty -Name "SubjectUser" -Value $subjecUser
                        $LogEvent | Add-Member -MemberType NoteProperty -Name "TargetUser" -Value $targetUser
                        $LogEvent | Add-Member -MemberType NoteProperty -Name "WorkstationName" -Value $_.Properties[11].Value
                        $LogEvent | Add-Member -MemberType NoteProperty -Name "IpAddress" -Value $_.Properties[18].Value
                        $LogEvent | Add-Member -MemberType NoteProperty -Name "IpPort" -Value $_.Properties[19].Value
                        $SuccessfulLogonsEvents += $LogEvent
                    }            
                }
            }
            "FailedLogons" {
                # Get the failed logons
                Write-Host "Retrieving the failed logons ..." -ForegroundColor Green
                $LogEvents = $SecurityEvents | Where-Object { $_.ID -eq 4625 }
                if ($LogEvents) {
                    $LogEvents | ForEach-Object {
                        $LogEvent = New-Object psobject
                        
                        # LogonType (https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625#logon-type))
                        # https://errorco.de/win32/ntstatus-h
                        switch ($_.Properties[10].Value) { 
                            0 { $LogonTypeDescription = "System" }
                            2 { $LogonTypeDescription = "Interactive" }
                            3 { $LogonTypeDescription = "Network" }
                            4 { $LogonTypeDescription = "Batch" }
                            5 { $LogonTypeDescription = "Service" }
                            7 { $LogonTypeDescription = "ScreenUnlock" }
                            8 { $LogonTypeDescription = "NetworkCleartext" }
                            9 { $LogonTypeDescription = "NewCredentials" }
                            10 { $LogonTypeDescription = "RemoteInteractive" }
                            11 { $LogonTypeDescription = "CachedInteractive" }
                            12 { $LogonTypeDescription = "CachedRemoteInteractive" }
                            13 { $LogonTypeDescription = "CachedUnlock" }
                        }

                        switch ($_.Properties[8].Value) {
                            "%%2304" { $FailureReason = "An Error occurred during Logon." }
                            "%%2305" { $FailureReason = "The specified user account has expired." }
                            "%%2309" { $FailureReason = "The specified account's password has expired." }
                            "%%2310" { $FailureReason = "Account currently disabled." }
                            "%%2311" { $FailureReason = "Account logon time restriction violation." }
                            "%%2312" { $FailureReason = "User not allowed to logon at this computer." }
                            "%%2313" { $FailureReason = "Unknown user name or bad password." }
                        }

                        switch ($_.Properties[7].Value) {
                            "-1073741710" { $Status = "The referenced account is currently disabled and may not be logged on to." } # STATUS_ACCOUNT_DISABLED (0xC0000072)
                            "-1073741260" { $Status = "The user account has been automatically locked because too many invalid logon attempts or password change attempts have been requested." } # STATUS_ACCOUNT_LOCKED_OUT (0xC0000234)
                            "-1073741714" { $Status = "Indicates a referenced user name and authentication information are valid, but some user account restriction has prevented successful authentication (such as time-of-day restrictions)." } # STATUS_ACCOUNT_RESTRICTION (0xC000006E)
                            "-1073741715" { $Status = "The attempted logon is invalid. This is either due to a bad username or authentication information." } # STATUS_LOGON_FAILURE (0xC000006D)
                            "-1073741711" { $Status = "The user account's password has expired." } # STATUS_PASSWORD_EXPIRED (0xC0000071)
                            "-1073741276" { $Status = "The user's password must be changed before signing in." } # STATUS_PASSWORD_MUST_CHANGE (0xC0000224)
                            "-1073741421" { $Status = "The user's account has expired." } # STATUS_ACCOUNT_EXPIRED (0xC0000193)
                            "-1073741517" { $Status = "The time at the Primary Domain Controller is different than the time at the Backup Domain Controller or member server by too large an amount." } # STATUS_TIME_DIFFERENCE_AT_DC (0xC0000133)
                            "-1073741275" { $Status = "The object was not found." } # STATUS_NOT_FOUND (0xC0000225)
                            "-1073741477" { $Status = "A user has requested a type of logon (e.g., interactive or network) that has not been granted. An administrator has control over who may logon interactively and through the network." } # STATUS_LOGON_TYPE_NOT_GRANTED (0xC000015B)
                            "-1073741074" { $Status = "A security context was deleted before the context was completed. This is considered a logon failure." } # STATUS_UNFINISHED_CONTEXT_DELETED (0xC00002EE)
                            "-1073741730" { $Status = "There are currently no logon servers available to service the logon request." } # STATUS_NO_LOGON_SERVERS (0xC000005E)
                            "-1073741604" { $Status = "Indicates the Sam Server was in the wrong state to perform the desired operation." } # STATUS_INVALID_SERVER_STATE (0xC00000DC)
                            "-1073741422" { $Status = "An attempt was made to logon, but the netlogon service was not started." } # STATUS_NETLOGON_NOT_STARTED (0xC0000192)
                            "-1073740781" { $Status = "Logon Failure: The machine you are logging onto is protected by an authentication firewall. The specified account is not allowed to authenticate to the machine." } # STATUS_AUTHENTICATION_FIREWALL_FAILED (0xC0000413)
                            "-1073741670" { $Status = "Insufficient system resources exist to complete the API." } # STATUS_INSUFFICIENT_RESOURCES (0xC000009A)                            
                            Default {
                                $Status = "Unknown failure reason (Status: " + $_.Properties[7].Value + ") # Lookup https://errorco.de/ntstatus for more information."
                            }
                        }

                        switch ($_.Properties[9].Value) {
                            "-1073741718" { $SubStatus = "When trying to update a password, this return status indicates that the value provided as the current password is not correct." } # STATUS_WRONG_PASSWORD (0xC000006A)
                            "-1073741517" { $SubStatus = "The time at the Primary Domain Controller is different than the time at the Backup Domain Controller or member server by too large an amount." } # STATUS_TIME_DIFFERENCE_AT_DC (0xC0000133)
                            "-1073741712" { $SubStatus = "The user account is restricted such that it may not be used to log on from the source workstation." } # STATUS_INVALID_WORKSTATION (0xC0000070)
                            "-1073741700" { $SubStatus = "An attempt was made to reference a token that doesn't exist. This is typically done by referencing the token associated with a thread when the thread is not impersonating a client." } # STATUS_NO_TOKEN (0xC000007C)
                            "-1073741724" { $SubStatus = "The specified account does not exist." } # STATUS_NO_SUCH_USER (0xC0000064)
                            "-1073741713" { $SubStatus = "The user account has time restrictions and may not be logged onto at this time." } # STATUS_INVALID_LOGON_HOURS (0xC000006F)
                            "-1073740928" { $SubStatus = "An incorrect PIN was presented to the smart card" } # STATUS_SMARTCARD_WRONG_PIN (0xC0000380)
                            Default {
                                $SubStatus = "Unknown failure reason (SubStatus: " + $_.Properties[9].Value + ") # Lookup https://errorco.de/ntstatus for more information."
                            }
                        }

                        $subjecUser = $_.Properties[2].Value + "\" + $_.Properties[1].Value
                        $targetUser = $_.Properties[6].Value + "\" + $_.Properties[5].Value

                        $LogEvent | Add-Member -MemberType NoteProperty -Name "TimeCreated" -Value $_.TimeCreated
                        $LogEvent | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $_.MachineName
                        $LogEvent | Add-Member -MemberType NoteProperty -Name "LogonType" -Value $_.Properties[10].Value
                        $LogEvent | Add-Member -MemberType NoteProperty -Name "LogonTypeDescription" -Value $LogonTypeDescription
                        $LogEvent | Add-Member -MemberType NoteProperty -Name "LogonProcessName" -Value $_.Properties[11].Value
                        $LogEvent | Add-Member -MemberType NoteProperty -Name "AuthenticationPackageName" -Value $_.Properties[12].Value
                        $LogEvent | Add-Member -MemberType NoteProperty -Name "ProcessId" -Value $_.Properties[17].Value
                        $LogEvent | Add-Member -MemberType NoteProperty -Name "ProcessName" -Value $_.Properties[18].Value
                        $LogEvent | Add-Member -MemberType NoteProperty -Name "Status" -Value $Status
                        $LogEvent | Add-Member -MemberType NoteProperty -Name "FailureReason" -Value $FailureReason
                        $LogEvent | Add-Member -MemberType NoteProperty -Name "SubStatus" -Value $SubStatus
                        $LogEvent | Add-Member -MemberType NoteProperty -Name "SubjectUser" -Value $subjecUser
                        $LogEvent | Add-Member -MemberType NoteProperty -Name "TargetUser" -Value $targetUser
                        $LogEvent | Add-Member -MemberType NoteProperty -Name "WorkstationName" -Value $_.Properties[13].Value
                        $LogEvent | Add-Member -MemberType NoteProperty -Name "IpAddress" -Value $_.Properties[19].Value
                        $LogEvent | Add-Member -MemberType NoteProperty -Name "IpPort" -Value $_.Properties[20].Value
                        $FailedLogonsEvents += $LogEvent
                    }            
                }
            }
            "ExplicitCredentials" {
                # Get the explicit credentials
                Write-Host "Retrieving the explicit credentials ..." -ForegroundColor Green
            }
            "OutboundRDPConnections" {
                # Get the outbound RDP connections
                Write-Host "Retrieving the outbound RDP connections ..." -ForegroundColor Green
                $LogEvents = $RDPClientEvents | Where-Object { $_.ID -eq 1024 }
                if ($LogEvents) {
                    $LogEvents | ForEach-Object {
                        $LogEvent = New-Object psobject
                        $LogEvent | Add-Member -MemberType NoteProperty -Name "TimeCreated" -Value $_.TimeCreated
                        $LogEvent | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $_.MachineName
                        $LogEvent | Add-Member -MemberType NoteProperty -Name "Message" -Value $_.Message
                        $LogEvent | Add-Member -MemberType NoteProperty -Name "ServerName" -Value $_.Properties[1].Value
                        $OutboundRDPConnectionsEvents += $LogEvent
                    }
                }
            }
        }
    }
}

End {
    Write-Host
    Write-Host "==========================={ Summary }===========================" -ForegroundColor Green
    Write-Host
    Write-Host "Log collection completed at $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")" 
    Write-Host "Log start time: $StartTime"
    Write-Host "Log end time: $EndTime" 
    Write-Host
    Write-Host "Total number of successful logons: $($SuccessfulLogonsEvents.Count)"
    Write-Host "Total number of failed logons: $($FailedLogonsEvents.Count)" 
    Write-Host "Total number of explicit credentials: $($ExplicitCredentialsEvents.Count)"
    Write-Host "Total number of outbound RDP connections: $($OutboundRDPConnectionsEvents.Count)"
    Write-Host


    foreach ($CollectEvent in $CollectEvents) {
        switch ($CollectEvent) {
            "SuccessfulLogons" {
                Write-Host
                Write-Host "==========================={ Successful Logons }===========================" -ForegroundColor Green
                Write-Output $SuccessfulLogonsEvents
                Write-Host
            }
            "FailedLogons" {
                Write-Host
                Write-Host "==========================={ Failed Logons }===========================" -ForegroundColor Green
                Write-Output $FailedLogonsEvents
                Write-Host
            }
            "ExplicitCredentials" {
                Write-Host
                Write-Host "==========================={ Explicit Credentials }===========================" -ForegroundColor Green
                Write-Output $ExplicitCredentialsEvents
                Write-Host
            }
            "OutBoundRDPConnections" {
                Write-Host
                Write-Host "==========================={ Outbound RDP Connections }===========================" -ForegroundColor Green
                Write-Output $OutboundRDPConnectionsEvents
                Write-Host
            }
        }
    }

    if ($ExportToCSV) {
        foreach ($CollectEvent in $CollectEvents) {
            switch ($CollectEvent) {
                "SuccessfulLogons" {
                    # Check if path exists
                    $CSVOutput = "$(Get-Location)\CSVOutput"
                    if (!(Test-Path $CSVOutput)) {
                        New-Item -ItemType Directory -Path $CSVOutput -Force
                    }
                    $SuccessfulLogonsEvents | Export-Csv -Path "$($CSVOutput)\SuccessfulLogons.csv" -NoTypeInformation | Out-Null
                }
                "FailedLogons" {
                    # Check if path exists
                    $CSVOutput = "$(Get-Location)\CSVOutput"
                    if (!(Test-Path $CSVOutput)) {
                        New-Item -ItemType Directory -Path $CSVOutput -Force
                    }
                    $FailedLogonsEvents | Export-Csv -Path "$($CSVOutput)\FailedLogons.csv" -NoTypeInformation | Out-Null
                }
                "ExplicitCredentials" {
                    # Check if path exists
                    $CSVOutput = "$(Get-Location)\CSVOutput"
                    if (!(Test-Path $CSVOutput)) {
                        New-Item -ItemType Directory -Path $CSVOutput -Force
                    }
                    $ExplicitCredentialsEvents | Export-Csv -Path "$($CSVOutput)\ExplicitCredentials.csv" -NoTypeInformation | Out-Null
                }
                "OutBoundRDPConnections" {
                    # Check if path exists
                    $CSVOutput = "$(Get-Location)\CSVOutput"
                    if (!(Test-Path $CSVOutput)) {
                        New-Item -ItemType Directory -Path $CSVOutput -Force
                    }
                    $OutboundRDPConnectionsEvents | Export-Csv -Path "$($CSVOutput)\OutboundRDPConnections.csv" -NoTypeInformation | Out-Null
                }
            }
        }
    }
}

