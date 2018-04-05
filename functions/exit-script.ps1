function exit-script {
    <#
    .DESCRIPTION
        Clean up actions before we exit the script.
    .PARAMETER defaultcleanupcode
        [scriptblock] Unique code to invoke when exiting script.
    #>
    [CmdletBinding()]
    Param(
          [scriptblock]$defaultcleanupcode)

    if ($NormalExit) {
        $msg= "Hooray.... finished without any bugs....."
        if ($log) {$log.verbose($msg)} else {Write-Verbose $msg}
    } else {
        $msg= "(1) Script ended with errors."
        if ($log) {$log.error($msg)} else {Write-Error $msg}
    }

    #-- General cleanup actions
    #-- disconnect vCenter connections if they exist
    if (Get-Variable -Scope global -Name DefaultVIServers -ErrorAction SilentlyContinue ) {
        Disconnect-VIServer -server * -Confirm:$false
    }
    #-- run unique code 
    if ($defaultcleanupcode) {
        $defaultcleanupcode.Invoke()
    }
    
    #-- Output runtime and say greetings
    $ts_end=get-date
    $msg="Runtime script: {0:hh}:{0:mm}:{0:ss}" -f ($ts_end- $ts_start)  
    if ($log) { $log.msg($msg)  } else {write-host $msg}
    read-host "The End <press Enter to close window>."
    exit
    }