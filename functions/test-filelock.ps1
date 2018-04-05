function Test-FileLock {
    <#
    .SYNOPSIS
        Test if file is locked by other process
    .DESCRIPTION
        Boolean function to test if file is locked.
        Returns true if file is locked, false if it isn't locked.
    .PARAMETER path
        Full path of file to test
    .EXAMPLE
        >test-filelock -path c:\test.txt

        true
    .EXAMPLE
        if !(test-filelock -path c:\test.txt) {write-host "File is not locked"} 
    #>

    [CmdletBinding()]

    param (
        [parameter(Mandatory=$true, helpmessage="Full path of file to be tested (including file name)")]
        [string]$Path
    )


    if ((Test-Path -Path $Path) -eq $false)
    { #-- file isn't found, answer of test is false
    $false
    return
    }

    $oFile = New-Object System.IO.FileInfo $Path
    try #-- test if file is locked, when locked error will be caught
    {
        $oStream = $oFile.Open([System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None) #-- try accessing the file
        if ($oStream)
        {
        $oStream.Close() #-- close the file, if possible)
        }
        $false #-- file is not being locked.
    }
    catch
    { #-- there was an exeption triggered while trying to acces the file, so it is being used.
    # file is locked by a process.
    $true
    }
}