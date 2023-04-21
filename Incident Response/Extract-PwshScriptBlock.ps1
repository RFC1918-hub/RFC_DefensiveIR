<#
.SYNOPSIS
    Extracts PowerShell script blocks from file or event logs.
.DESCRIPTION
    Extracts PowerShell script blocks from file or event logs.
.PARAMETER ComputerName
    Computer name to connect to.
.PARAMETER Credential
    Credential to use to connect to remote computer.
.PARAMETER Path
    Path to file or event log.
.PARAMETER List
    List all script blocks.
.PARAMETER Show
    Show script block.
.PARAMETER Dump
    Dump script block to files.
.PARAMETER ScriptBlockId
    Script block ID to dump.
.PARAMETER OutputDirectory
    Directory to output files to.
.PARAMETER Keyword
    Keyword to search for.
.EXAMPLE
    Extract-PwshScriptBlock.ps1 -List

    Listing all PowerShell script blocks

    ScriptBlockId                        ScriptBlockPath                                                                                                       MessageTotal ExecutionDate
    -------------                        ---------------                                                                                                       ------------ -------------
    841bf47c-d702-47cb-abbb-d2e101146d38 C:\Users\RFC\source\repos\RFC_DefensiveIR\Extract-PwshScriptBlock.ps1                                               1            4/21/2023 7:34:29 PM
    ed1c8e4b-25c5-4348-a19b-d16d46b5cce7 C:\Users\RFC\.vscode\extensions\ms-vscode.powershell-2023.3.3\modules\PSScriptAnalyzer\1.21.0\PSScriptAnalyzer.psm1 1            4/21/2023 7:19:38 PM
    e8219575-0e6d-41b7-bf91-cc53a5b7aa80 C:\Users\RFC\.vscode\extensions\ms-vscode.powershell-2023.3.3\modules\PSScriptAnalyzer\1.21.0\PSScriptAnalyzer.psm1 1            4/21/2023 7:13:45 PM

.EXAMPLE
    Extract-PwshScriptBlock.ps1 -Dump

.EXAMPLE
    Extract-PwshScriptBlock.ps1 -Path C:\Temp\Logs\Microsoft-Windows-PowerShell.evtx -List -Keyword "Invoke-WebRequest"

    Listing all PowerShell script blocks

    ScriptBlockId   : 841bf47c-d702-47cb-abbb-d2e101146d38
    ScriptBlockPath : C:\Users\RFC\source\repos\RFC_DefensiveIR\Extract-PwshScriptBlock.ps1
    MessageNumber   : 1
    MessageTotal    : 1
    ExecutionDate   : 4/21/2023 7:34:29 PM

    ScriptBlockId   : 8e9b6f40-7c1e-44f6-b2c0-d899c662c011
    ScriptBlockPath : C:\Users\RFC\source\repos\RFC_DefensiveIR\Extract-PwshScriptBlock.ps1
    MessageNumber   : 1
    MessageTotal    : 1
    ExecutionDate   : 4/21/2023 2:04:29 PM

.EXAMPLE
    Extract-PwshScriptBlock.ps1 -Show -Keyword "Invoke-WebRequest"

    Showing all PowerShell script blocks with keyword "Invoke-WebRequest"

    ScriptBlockId   : 841bf47c-d702-47cb-abbb-d2e101146d38
    ScriptBlockPath : Extract-PwshScriptBlock.ps1
    MessageNumber   : 1
    MessageTotal    : 1
    ScriptBlockText : {
                        $Event = $_
                        $Event.Properties | ForEach-Object {
                            if ($_.Name -eq "ScriptBlockText") {
                                $ScriptBlock = $_.Value
                                $ScriptBlock = $ScriptBlock -replace '^\s*ScriptBlock ID: ', ''
                                $ScriptBlock = $ScriptBlock -replace '^\s*Path: ', ''
                                $ScriptBlock = $ScriptBlock -replace '^\s*Line: ', ''
                                $ScriptBlock = $ScriptBlock -replace '^\s*Position: ', ''
                                $ScriptBlock = $ScriptBlock -replace '^\s*Command: ', ''
                                $ScriptBlock = $ScriptBlock -replace '^\s*User: ', ''
                                $ScriptBlock = $ScriptBlock -replace '^\s*Host: ', ''
                                $ScriptBlock = $ScriptBlock -replace '^\s*Process ID: ', ''
                                $ScriptBlock = $ScriptBlock -replace '^\s*Runspace ID: ', ''
                                $ScriptBlock = $ScriptBlock -replace '^\s*Pipeline ID: ', ''
                                $ScriptBlock = $ScriptBlock -replace '^\s*Command Name: ', ''
                                $ScriptBlock = $ScriptBlock -replace '^\s*Command Type: ', ''
                                $ScriptBlock = $ScriptBlock -replace '^\s*ScriptBlock Text: ', ''
                                $ScriptBlock = $ScriptBlock -replace '^\s*$', ''
                                $ScriptBlock
                            }
                        }
                    }

    ExecutionDate   : 4/21/2023 7:34:29 PM

.EXAMPLE
    Extract-PwshScriptBlock.ps1 -Dump -OutputDirectory C:\Temp\Output

.EXAMPLE
    Extract-PwshScriptBlock.ps1 -Dump -ComputerName DC01 -Credential (Get-Credential) -OutputDirectory C:\Temp\Output
#>
[CmdletBinding()]
Param (
    [Parameter(Mandatory=$false)]
    [string]$ComputerName,
    [Parameter(Mandatory=$false)]
    [pscredential]$Credential,
    [Parameter(Mandatory=$false)]
    [string]$Path,
    [Parameter(Mandatory=$false)]
    [switch]$List,
    [Parameter(Mandatory=$false)]
    [switch]$Show,
    [Parameter(Mandatory=$false)]
    [switch]$Dump,
    [Parameter(Mandatory=$false)]
    [string]$ScriptBlockId,
    [Parameter(Mandatory=$false)]
    [string]$OutputDirectory,
    [Parameter(Mandatory=$false)]
    [string]$Keyword
)

Begin {

    $ScriptBlocks = @()

    if ($Path) {
        $Filter = @{
            "ProviderName"="Microsoft-Windows-PowerShell";
            "Id"=4104;
            "Path"=$Path;
        }
    } else {
        $Filter = @{
            "ProviderName"="Microsoft-Windows-PowerShell";
            "Id"=4104;
        }
    }
    
    if ($ComputerName) {
        try {
            if ($Credential) {
                $EventLog = Get-WinEvent -ComputerName $ComputerName -Credential $Credential -FilterHashtable $Filter
            } else {
                $EventLog = Get-WinEvent -ComputerName $ComputerName -FilterHashtable $Filter
            }
        }
        catch {
            Write-Host "Unable to connect to $ComputerName" -ForegroundColor Red
            Write-Output $_
        }
    } else {
        try {
            $EventLog = Get-WinEvent -FilterHashtable $Filter
        }
        catch {
            Write-Host "Unable to read event log" -ForegroundColor Red
            Write-Output $_
        }
    }
}
Process {
    if (-not $List -and -not $Dump -and -not $Show) {
        Write-Host "Please specify either -List or -Dump or -Show" -ForegroundColor Red
        break
    } elseif ($Keyword -and -not ($List -or $Show)) {
        Write-Host "Please specify -List or -Show when using -Keyword" -ForegroundColor Red
        break
    } elseif ($ScriptBlockId -and -not $Dump) {
        Write-Host "Please specify -Dump when using -ScriptBlockId" -ForegroundColor Red
        break
    } elseif ($OutputDirectory -and -not $Dump) {
        Write-Host "Please specify -Dump when using -OutputDirectory" -ForegroundColor Red
        break
    } elseif ($OutputDirectory -and -not (Test-Path $OutputDirectory)) {
        Write-Host "Output directory does not exist" -ForegroundColor Red
        break
    } 

    if ($List) {
        Write-Host "Listing all PowerShell script blocks"
        $EventLog | ForEach-Object {
            $EventXML = [xml]$_.ToXml()

            $MessageNumber = $EventXML.Event.EventData.Data[0].'#text'
            $MessageTotal = $EventXML.Event.EventData.Data[1].'#text'
            $ScriptBlockText = $EventXML.Event.EventData.Data[2].'#text'
            $ScriptBlockId = $EventXML.Event.EventData.Data[3].'#text'

            if (($ScriptBlockPath = $EventXML.Event.EventData.Data[4].'#text') -eq $null) {
                $ScriptBlockPath = $EventXML.Event.EventData.Data[3].'#text'
            }
            $ScriptBlockEvent = New-Object psobject

            if ($Keyword) {
                if ($ScriptBlockText -like "*$Keyword*") {
                    $ScriptBlockEvent | Add-Member -MemberType NoteProperty -Name "ScriptBlockId" -Value $ScriptBlockId
                    $ScriptBlockEvent | Add-Member -MemberType NoteProperty -Name "ScriptBlockPath" -Value $ScriptBlockPath
                    $ScriptBlockEvent | Add-Member -MemberType NoteProperty -Name "MessageNumber" -Value $MessageNumber
                    $ScriptBlockEvent | Add-Member -MemberType NoteProperty -Name "MessageTotal" -Value $MessageTotal
                    $ScriptBlockEvent | Add-Member -MemberType NoteProperty -Name "ExecutionDate" -Value $_.TimeCreated
                    $ScriptBlocks += $ScriptBlockEvent
                }
            } elseif ($MessageNumber -eq $MessageTotal) {
                $ScriptBlockEvent | Add-Member -MemberType NoteProperty -Name "ScriptBlockId" -Value $ScriptBlockId
                $ScriptBlockEvent | Add-Member -MemberType NoteProperty -Name "ScriptBlockPath" -Value $ScriptBlockPath
                $ScriptBlockEvent | Add-Member -MemberType NoteProperty -Name "MessageTotal" -Value $MessageTotal
                $ScriptBlockEvent | Add-Member -MemberType NoteProperty -Name "ExecutionDate" -Value $_.TimeCreated
                $ScriptBlocks += $ScriptBlockEvent
            }   
        }
    } elseif ($Dump) {
        Write-Host "Dumping all PowerShell script blocks"
        $TempScriptBlocksText = ""
        $TempScriptBlocksPath = ""

        if ($OutputDirectory) {
            $OutputPath = $OutputDirectory
        } else {
            if (Test-Path "$(Get-Location)\Output") {
                Remove-Item -Path "Output\*" -Recurse -Force
            } else {
                New-Item -Path "Output" -ItemType Directory | Out-Null
            }
            $OutputPath = "$(Get-Location)\Output"
        } 

        $OriginalPath = Get-Location
        Set-Location -Path $OutputPath

        $EventLog | ForEach-Object {
            $EventXML = [xml]$_.ToXml()

            $MessageNumber = $EventXML.Event.EventData.Data[0].'#text'
            $MessageTotal = $EventXML.Event.EventData.Data[1].'#text'
            $ScriptBlockText = $EventXML.Event.EventData.Data[2].'#text'
            $ScriptBlockId = $EventXML.Event.EventData.Data[3].'#text'

            if (($ScriptBlockPath = $EventXML.Event.EventData.Data[4].'#text') -eq $null) {
                $ScriptBlockPath = $ScriptBlockId
            } else {
                $ScriptBlockPath = $EventXML.Event.EventData.Data[4].'#text'
                $ScriptBlockPath = Split-Path -Path $ScriptBlockPath -Leaf
            }

            $ScriptBlockEvent = New-Object psobject

            if ($Id) {
                if ($ScriptBlockId -eq $Id) {
                    if ($MessageNumber -eq 1 -and $MessageTotal -eq 1) {
                        $ScriptBlockEvent | Add-Member -MemberType NoteProperty -Name "ScriptBlockId" -Value $ScriptBlockId
                        $ScriptBlockEvent | Add-Member -MemberType NoteProperty -Name "ScriptBlockPath" -Value $ScriptBlockPath
                        $ScriptBlockEvent | Add-Member -MemberType NoteProperty -Name "MessageTotal" -Value $MessageTotal
                        $ScriptBlockEvent | Add-Member -MemberType NoteProperty -Name "ExecutionDate" -Value $_.TimeCreated
                        $ScriptBlocks += $ScriptBlockEvent
                        Out-File -FilePath $ScriptBlockPath -InputObject $ScriptBlockText
                    } elseif ($MessageNumber -eq $MessageTotal) {
                        $TempScriptBlocksText = $ScriptBlockText
                        $TempScriptBlocksPath = $ScriptBlockPath
                        $ScriptBlockEvent | Add-Member -MemberType NoteProperty -Name "ScriptBlockId" -Value $ScriptBlockId
                        $ScriptBlockEvent | Add-Member -MemberType NoteProperty -Name "ScriptBlockPath" -Value $ScriptBlockPath
                        $ScriptBlockEvent | Add-Member -MemberType NoteProperty -Name "MessageTotal" -Value $MessageTotal
                        $ScriptBlockEvent | Add-Member -MemberType NoteProperty -Name "ExecutionDate" -Value $_.TimeCreated
                        $ScriptBlocks += $ScriptBlockEvent
                    } elseif ($MessageNumber -ne 1) {
                        $TempScriptBlocksText = $ScriptBlockText + $TempScriptBlocksText
                    } else {
                        $TempScriptBlocksText = $ScriptBlockText + $TempScriptBlocksText
                        Out-File -FilePath $TempScriptBlocksPath -InputObject $TempScriptBlocksText
                        $TempScriptBlocksText = ""
                        $TempScriptBlocksPath = ""
                    }
                }
            } else {
                if ($MessageNumber -eq 1 -and $MessageTotal -eq 1) {
                    $ScriptBlockEvent | Add-Member -MemberType NoteProperty -Name "ScriptBlockId" -Value $ScriptBlockId
                    $ScriptBlockEvent | Add-Member -MemberType NoteProperty -Name "ScriptBlockPath" -Value $ScriptBlockPath
                    $ScriptBlockEvent | Add-Member -MemberType NoteProperty -Name "MessageTotal" -Value $MessageTotal
                    $ScriptBlockEvent | Add-Member -MemberType NoteProperty -Name "ExecutionDate" -Value $_.TimeCreated
                    $ScriptBlocks += $ScriptBlockEvent
                    Out-File -FilePath $ScriptBlockPath -InputObject $ScriptBlockText
                } elseif ($MessageNumber -eq $MessageTotal) {
                    $TempScriptBlocksText = $ScriptBlockText
                    $TempScriptBlocksPath = $ScriptBlockPath
                    $ScriptBlockEvent | Add-Member -MemberType NoteProperty -Name "ScriptBlockId" -Value $ScriptBlockId
                    $ScriptBlockEvent | Add-Member -MemberType NoteProperty -Name "ScriptBlockPath" -Value $ScriptBlockPath
                    $ScriptBlockEvent | Add-Member -MemberType NoteProperty -Name "MessageTotal" -Value $MessageTotal
                    $ScriptBlockEvent | Add-Member -MemberType NoteProperty -Name "ExecutionDate" -Value $_.TimeCreated
                    $ScriptBlocks += $ScriptBlockEvent
                } elseif ($MessageNumber -ne 1) {
                    $TempScriptBlocksText = $ScriptBlockText + $TempScriptBlocksText
                } else {
                    $TempScriptBlocksText = $ScriptBlockText + $TempScriptBlocksText
                    Out-File -FilePath $TempScriptBlocksPath -InputObject $TempScriptBlocksText
                    $TempScriptBlocksText = ""
                    $TempScriptBlocksPath = ""
                }
            }
        }
        Set-Location -Path $OriginalPath
    } elseif ($Show) {
        Write-Host "Displaying all PowerShell script blocks containing the keyword '$Keyword'"
        $EventLog | ForEach-Object {
            $EventXML = [xml]$_.ToXml()

            $MessageNumber = $EventXML.Event.EventData.Data[0].'#text'
            $MessageTotal = $EventXML.Event.EventData.Data[1].'#text'
            $ScriptBlockText = $EventXML.Event.EventData.Data[2].'#text'
            $ScriptBlockId = $EventXML.Event.EventData.Data[3].'#text'

            if (($ScriptBlockPath = $EventXML.Event.EventData.Data[4].'#text') -eq $null) {
                $ScriptBlockPath = $EventXML.Event.EventData.Data[3].'#text'
            }
            $ScriptBlockEvent = New-Object psobject

            if ($Keyword) {
                if ($ScriptBlockText -like "*$Keyword*") {
                    $ScriptBlockEvent | Add-Member -MemberType NoteProperty -Name "ScriptBlockId" -Value $ScriptBlockId
                    $ScriptBlockEvent | Add-Member -MemberType NoteProperty -Name "ScriptBlockPath" -Value $ScriptBlockPath
                    $ScriptBlockEvent | Add-Member -MemberType NoteProperty -Name "MessageNumber" -Value $MessageNumber
                    $ScriptBlockEvent | Add-Member -MemberType NoteProperty -Name "MessageTotal" -Value $MessageTotal
                    $ScriptBlockEvent | Add-Member -MemberType NoteProperty -Name "ScriptBlockText" -Value $ScriptBlockText
                    $ScriptBlockEvent | Add-Member -MemberType NoteProperty -Name "ExecutionDate" -Value $_.TimeCreated
                    $ScriptBlocks += $ScriptBlockEvent
                }
            }
        }
    }
}
End {
    Write-Output $ScriptBlocks
}