function Get-DefenderASR {
    $asrrulesGUIDmatrix = @()
    $asrrulesGUIDmatrix += [PSCustomObject]@{
        Name = "Block abuse of exploited vulnerable signed drivers"
        GUID = "56a863a9-875e-4185-98a7-b882c64b5ce5"
    }
    $asrrulesGUIDmatrix += [PSCustomObject]@{
        Name = "Block Adobe Reader from creating child processes"
        GUID = "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c"
    }
    $asrrulesGUIDmatrix += [PSCustomObject]@{
        Name = "Block all Office applications from creating child processes"
        GUID = "d4f940ab-401b-4efc-aadc-ad5f3c50688a"
    }
    $asrrulesGUIDmatrix += [PSCustomObject]@{
        Name = "Block credential stealing from the Windows local security authority subsystem (lsass.exe)"
        GUID = "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"
    }
    $asrrulesGUIDmatrix += [PSCustomObject]@{
        Name = "Block executable content from email client and webmail"
        GUID = "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550"
    }
    $asrrulesGUIDmatrix += [PSCustomObject]@{
        Name = "Block executable files from running unless they meet a prevalence, age, or trusted list criterion"
        GUID = "01443614-cd74-433a-b99e-2ecdc07bfc25"
    }
    $asrrulesGUIDmatrix += [PSCustomObject]@{
        Name = "Block execution of potentially obfuscated scripts"
        GUID = "5beb7efe-fd9a-4556-801d-275e5ffc04cc"
    }
    $asrrulesGUIDmatrix += [PSCustomObject]@{
        Name = "Block JavaScript or VBScript from launching downloaded executable content"
        GUID = "d3e037e1-3eb8-44c8-a917-57927947596d"
    }
    $asrrulesGUIDmatrix += [PSCustomObject]@{
        Name = "Block Office applications from creating executable content"
        GUID = "3b576869-a4ec-4529-8536-b80a7769e899"
    }
    $asrrulesGUIDmatrix += [PSCustomObject]@{
        Name = "Block Office applications from injecting code into other processes"
        GUID = "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84"
    }
    $asrrulesGUIDmatrix += [PSCustomObject]@{
        Name = "Block Office communication application from creating child processes"
        GUID = "26190899-1602-49e8-8b27-eb1d0a1ce869"
    }
    $asrrulesGUIDmatrix += [PSCustomObject]@{
        Name = "Block persistence through WMI event subscription"
        GUID = "e6db77e5-3df2-4cf1-b95a-636979351e5b"
    }
    $asrrulesGUIDmatrix += [PSCustomObject]@{
        Name = "Block process creations originating from PSExec and WMI commands"
        GUID = "d1e49aac-8f56-4280-b9ba-993a6d77406c"
    }
    $asrrulesGUIDmatrix += [PSCustomObject]@{
        Name = "Block untrusted and unsigned processes that run from USB"
        GUID = "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4"
    }
    $asrrulesGUIDmatrix += [PSCustomObject]@{
        Name = "Block Win32 API calls from Office macros"
        GUID = "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b"
    }
    $asrrulesGUIDmatrix += [PSCustomObject]@{
        Name = "Use advanced protection against ransomware"
        GUID = "c1db55ab-c21a-4637-bb3f-a12568109d35"
    }

    write-host "[i] Getting Defender ASR Rules"
    write-host
    $mpprefence = Get-MpPreference

    if ([System.String]::isnullorempty($mpprefence.AsrRuleIdPreference)) {
        $index = 0
        $asrrules = @()
        foreach ($guid in $mpprefence.AttackSurfaceReductionRules_Ids) {
            $asrrules += [PSCustomObject]@{
                Name = $asrrulesGUIDmatrix.Where({$_.GUID -eq $guid}).Name
                Action = switch ($mpprefence.AttackSurfaceReductionRules_Actions[$index]) {
                    0 {"Disable"}
                    1 {"Enabled"}
                    2 {"Audit Mode"}
                    5 {"Not Configured"}
                    6 {"Warn"}
                }
            }
            $index++
        }
        $asrrules
    }
    else {
        Write-Host "[!] ASR Rule ID Preference is not empty"
    }
}

# main 
Get-DefenderASR
