<#
    File Name          : CC-functions.psm1
    Author             : Bart Lievers
    Prerequisite       : PowerShell version : 2.0 - x
                         PS Modules and version : 
                            PowerCLI - 6.0 R2
    Version/GIT Tag    : v0.10.5
    Last Edit          : BL - 20-12-2015
    Copyright 2015 - CAM IT Solutions
#>    

#region defining custom types
#endregion
    
#region initialize functions for third party modules/snappins


    function import-PowerCLI {
        <#
        .SYNOPSIS
           Loading of all VMware modules and power snapins
        .DESCRIPTION
  
        .EXAMPLE
            One or more examples for how to use this script
        .NOTES
            File Name          : import-PowerCLI.ps1
            Author             : Bart Lievers
            Prerequisite       : <Preruiqisites like
                                 Min. PowerShell version : 2.0
                                 PS Modules and version : 
                                    PowerCLI - 6.0 R2
            Version/GIT Tag    : 1.0.0
            Last Edit          : BL - 3-1-2016
            CC-release         : 
            Copyright 2016 - CAM IT Solutions
        #>
        [CmdletBinding()]

        Param(
        )

        Begin{
 
        }

        Process{
            #-- make up inventory and check PowerCLI installation
            $RegisteredModules=Get-Module -Name vmware* -ListAvailable -ErrorAction ignore | % {$_.Name}
            $RegisteredSnapins=get-pssnapin -Registered vmware* -ErrorAction Ignore | %{$_.name}
            if (($RegisteredModules.Count -eq 0 ) -and ($RegisteredSnapins.count -eq 0 )) {
                #-- PowerCLI is not installed
                if ($log) {$log.warning("Cannot load PowerCLI, no VMware Powercli Modules and/or Snapins found.")}
                else {
                write-warning "Cannot load PowerCLI, no VMware Powercli Modules and/or Snapins found."}
                #-- exit function
                return $false
            }

            #-- load modules
            if ($RegisteredModules) {
                #-- make inventory of already loaded VMware modules
                $loaded = Get-Module -Name vmware* -ErrorAction Ignore | % {$_.Name}
                #-- make inventory of available VMware modules
                $registered = Get-Module -Name vmware* -ListAvailable -ErrorAction Ignore | % {$_.Name}
                #-- determine which modules needs to be loaded, and import them.
                $notLoaded = $registered | ? {$loaded -notcontains $_}

                foreach ($module in $registered) {
                    if ($loaded -notcontains $module) {
                        Import-Module $module -Global
                    }
                }
            }

            #-- load Snapins
            if ($RegisteredSnapins) {      
                #-- Exlude loaded modules from additional snappins to load
                $snapinList=Compare-Object -ReferenceObject $RegisteredModules -DifferenceObject $RegisteredSnapins | ?{$_.sideindicator -eq "=>"} | %{$_.inputobject}
                #-- Make inventory of loaded VMware Snapins
                $loaded = Get-PSSnapin -Name $snapinList -ErrorAction Ignore | % {$_.Name}
                #-- Make inventory of VMware Snapins that are registered
                $registered = Get-PSSnapin -Name $snapinList -Registered -ErrorAction Ignore  | % {$_.Name}
                #-- determine which snapins needs to loaded, and import them.
                $notLoaded = $registered | ? {$loaded -notcontains $_}

                foreach ($snapin in $registered) {
                    if ($loaded -notcontains $snapin) {
                        Add-PSSnapin $snapin
                    }
                }
            }
            #-- show loaded vmware modules and snapins
            if ($RegisteredModules) {get-module -Name vmware* | select name,version,@{N="type";E={"module"}} | ft -AutoSize}
              if ($RegisteredSnapins) {get-pssnapin -Name vmware* | select name,version,@{N="type";E={"snapin"}} | ft -AutoSize}

        }


        End{

        }



    #endregion
    }

    function remove-PowerCLI(){
        get-module vmware* | Remove-Module -Force -Confirm:$false
        get-pssnapin vmware* | Remove-PSSnapin -force -Confirm:$false
    }

#endregion

#region re-write global PowerShell functions
    function global:prompt{

        # change prompt text
        Write-Host "CAMCube " -NoNewLine -ForegroundColor Magenta
        Write-Host ((Get-location).Path + ">") -NoNewLine
        return " "
    }
#endregion

#region general script functions
    function exit-script {
    <#
    .DESCRIPTION
        Clean up actions before we exit the script.
    .PARAMETER unloadCcModule
        [switch] Unload the CC-function module
    .PARAMETER defaultcleanupcode
        [scriptblock] Unique code to invoke when exiting script.
    #>
    [CmdletBinding()]
    Param([switch]$unloadCCmodule,
          [scriptblock]$defaultcleanupcode)

    if ($finished_normal) {
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
    #-- unload CC-functions module from session
    if ($unloadCCmodule) { Get-Module -name cc-functions | Remove-Module}
    #-- Output runtime and say greetings
    $ts_end=get-date
    $msg="Runtime script: {0:hh}:{0:mm}:{0:ss}" -f ($ts_end- $ts_start)  
    if ($log) { $log.msg($msg)  } else {write-host $msg}
    read-host "The End <press Enter to close window>."
    exit
    }
#endregion

#region log funstions


 
#endregion

New-Alias  -name write-syslog -value Send-syslog -Description "write syslog message"

Export-ModuleMember -Function * -Alias *
