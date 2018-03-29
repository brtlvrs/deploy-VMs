
function test-Elevated {
    [CmdletBinding()]
    param()
    <#
    .SYNOPSIS
        Test if script is running in elevated runspace
    .NOTES
        Author: Bart Lievers
        Date:   30 October 2013    
#>	

    # Get the ID and security principal of the current user account
    $myWindowsID=[System.Security.Principal.WindowsIdentity]::GetCurrent()
    $myWindowsPrincipal=new-object System.Security.Principal.WindowsPrincipal($myWindowsID)

    # Get the security principal for the Administrator role
    $adminRole=[System.Security.Principal.WindowsBuiltInRole]::Administrator

    # Check to see if we are currently running "as Administrator"
        return ($myWindowsPrincipal.IsInRole($adminRole))

}

function invoke-Elevated {
    [CmdletBinding()]
    param()
    <#
    .SYNOPSIS
        Run current script in a new powershell runspace with elevated privileges.
    .NOTES
        Author: Bart Lievers
        Date:   30 October 2013    
#>
    
    # Get the ID and security principal of the current user account
    $myWindowsID=[System.Security.Principal.WindowsIdentity]::GetCurrent()
    $myWindowsPrincipal=new-object System.Security.Principal.WindowsPrincipal($myWindowsID)

    # Get the security principal for the Administrator role
    $adminRole=[System.Security.Principal.WindowsBuiltInRole]::Administrator

    # Check to see if we are currently running "as Administrator"
    if ($myWindowsPrincipal.IsInRole($adminRole))
        {
        # We are running "as Administrator" - so change the title and background color to indicate this
        $Host.UI.RawUI.WindowTitle = (split-path $myInvocation.scriptname -Leaf) + " (Elevated)"
        clear-host
        }  
}