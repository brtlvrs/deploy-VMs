#-- Type Syslog_Facility for function send-syslogmessage
Add-Type -TypeDefinition @"
	    public enum Syslog_Facility
	    {
		    kern,
		    user,
		    mail,
		    daemon,
		    auth,
		    syslog,
		    lpr,
		    news,
		    uucp,
		    clock,
		    authpriv,
		    ftp,
		    ntp,
		    logaudit,
		    logalert,
		    cron, 
		    local0,
		    local1,
		    local2,
		    local3,
		    local4,
		    local5,
		    local6,
		    local7
	    }
"@

#-- Type Syslog_Severity for function send-syslogmessage
Add-Type -TypeDefinition @"
	    public enum Syslog_Severity
	    {
		    Emergency,
		    Alert,
		    Critical,
		    Error,
		    Warning,
		    Notice,
		    Informational,
		    Debug
	    }
"@

function init-SysLogclient {
    <#
    .SYNOPSIS
        Copying syslog parameters from parameter object to global scope
    .EXAMPLE
        init-syslogclient
    #>
    param(
        [parameter(mandatory=$false)]$p=$p
    )

    $ParTable=@{}
    $partable["SysLog_Hostname"]=$P.SysLog_Hostname
    $partable["Syslog_Server"]=$P.Syslog_Server
    $partable["Syslog_default_Facility"]=$P.Syslog_default_Facility
    $partable["Syslog_Default_Severity"]=$P.Syslog_Default_Severity
    $partable["Syslog_Default_minSeverity"]=$P.Syslog_Default_minSeverity
    $partable["SysLog_default_UDPPort"]=$P.SysLog_default_UDPPort
    $partable["Syslog_default_ApplicationName"]=$P.Syslog_default_ApplicationName
    $partable["Log2Syslog"]=$P.Log2Syslog

    $partable.GetEnumerator() | %{
        $rcd=$_
    if (Get-Variable -Name $rcd.name -ErrorAction SilentlyContinue) {Get-Variable -Name $rcd.name | Remove-Variable -Confirm:$false }
        New-Variable -Name $rcd.name -Scope global -Value $rcd.Value
    }
}

function set-SysLogclient {
    <#
    .SYNOPSIS
        Define some default parameters for the send-syslog function
    .EXAMPLE
        set-SysLogclient -Hostname pietje -Server syslog.shire.lan -ApplicationName linux -DefaultFacility local3 -DefaultSeverity Informational 
    #>
    param(
        [parameter(mandatory=$true)][string]$Hostname,
        [parameter(mandatory=$true)][string]$Server,
        [string]$ApplicationName="-",
        [Syslog_Facility]$DefaultFacility="local7",
        [Syslog_Severity]$DefaultSeverity="Informational",
        [Syslog_Severity]$minSeverity="Informational",
        [int]$UDPPort=514
    )

    New-Variable -Name SysLog_Hostname -Scope global -Value $Hostname -Force
    New-Variable -Name Syslog_Server -Scope global -Value $Server -Force
    New-Variable -Name Syslog_default_Facility -Scope global -Value $DefaultFacility -Force
    New-Variable -Name Syslog_Default_Severity -Scope global -Value $DefaultSeverity -force
    New-Variable -Name Syslog_Default_minSeverity -Scope global -Value $minSeverity -force
    New-Variable -Name SysLog_default_UDPPort -Scope global -Value $UDPPort -Force
    New-Variable -Name Syslog_default_ApplicationName -Scope global -Value $ApplicationName -Force
}

function send-syslog{
    <#
    .SYNOPSIS
    Sends a SYSLOG message to a server running the SYSLOG daemon

    Use set-SysLogClient to set default parameters like server,facility,severity,udpport,hostname and applicationname
    .DESCRIPTION
    Sends a message to a SYSLOG server as defined in RFC 5424 and RFC 3164. 
    .PARAMETER Server
    Destination SYSLOG server that message is to be sent to.
    .PARAMETER Message
    Our message or content that we want to send to the server. This is option in RFC 5424, the CMDLet still has this as a madatory parameter, to send no message, simply specifiy '-' (as per RFC).
    .PARAMETER Severity
    Severity level as defined in SYSLOG specification, must be of ENUM type Syslog_Severity
    .PARAMETER Facility
    Facility of message as defined in SYSLOG specification, must be of ENUM type Syslog_Facility
    .PARAMETER Hostname
    Hostname of machine the mssage is about, if not specified, RFC 5425 selection rules will be followed.
    .PARAMETER ApplicationName
    Specify the name of the application or script that is sending the mesage. If not specified, will select the ScriptName, or if empty, powershell.exe will be sent. To send Null, specify '-' to meet RFC 5424. 
    .PARAMETER ProcessID
    ProcessID or PID of generator of message. Will automatically use $PID global variable. If you want to override this and send null, specify '-' to meet RFC 5424 rquirements. This is only sent for RFC 5424 messages.
    .PARAMETER MessageID
    Error message or troubleshooting number associated with the message being sent. If you want to override this and send null, specify '-' to meet RFC 5424 rquirements. This is only sent for RFC 5424 messages.
    .PARAMETER StructuredData
    Key Pairs of structured data as a string as defined in RFC5424. Default will be '-' which means null. This is only sent for RFC 5424 messages.
    .PARAMETER Timestamp
    Time and date of the message, must be of type DateTime. Correct format will be selected depending on RFC requested. If not specified, will call get-date to get appropriate date time.
    .PARAMETER UDPPort
    SYSLOG UDP port to send message to. Defaults to 514 if not specified.
    .PARAMETER RFC3164
    Send an RFC3164 fomatted message instead of RFC5424.
    .INPUTS
    Nothing can be piped directly into this function
    .OUTPUTS
    Nothing is output
    .EXAMPLE
    Send-SyslogMessage mySyslogserver "The server is down!" Emergency Mail
    Sends a syslog message to mysyslogserver, saying "server is down", severity emergency and facility is mail
    .NOTES
    NAME: Send-SyslogMessage
    AUTHOR: Kieran Jacobsen
    LASTEDIT: 2015 01 12
    KEYWORDS: syslog, messaging, notifications
    .LINK
    https://github.com/kjacobsen/PowershellSyslog
    .LINK
    http://poshsecurity.com
    #>
    [CMDLetBinding()]
    Param
    (
	    [Parameter(mandatory=$false)]
	    [ValidateNotNullOrEmpty()]
	    [String] 
	    $Server=$Syslog_Server,
	
	    [Parameter(
            Position=0,
            mandatory=$true,
            ValueFromPipeLine=$true,
            ValueFromPipeLineByPropertyName=$true)]
	    [ValidateNotNullOrEmpty()]
	    [String]
	    $Message,
	
	    [Parameter(mandatory=$false)]
	    [ValidateNotNullOrEmpty()]
	    [Syslog_Severity]
	    $Severity=$Syslog_Default_Severity,

	    [Parameter(mandatory=$false)]
	    [ValidateNotNullOrEmpty()]
	    [Syslog_Severity]
	    $minSeverity=$Syslog_Default_minSeverity,
	
	    [Parameter(mandatory=$false)]
	    [ValidateNotNullOrEmpty()]
	    [Syslog_Facility] 
	    $Facility=$Syslog_default_Facility,
	
	    [Parameter(mandatory=$false)]
	    [ValidateNotNullOrEmpty()]
	    [String]
	    $Hostname = $Syslog_Hostname,
	
	    [Parameter(mandatory=$false)]
	    [ValidateNotNullOrEmpty()]
	    [String]
	    $ApplicationName = $Syslog_default_ApplicationName,
	
	    [Parameter(mandatory=$false)]
	    [ValidateNotNullOrEmpty()]
	    [String]
	    $ProcessID = $PID,
	
	    [Parameter(mandatory=$false)]
	    [ValidateNotNullOrEmpty()]
	    [String]
	    $MessageID = '-',
	
	    [Parameter(mandatory=$false)]
	    [ValidateNotNullOrEmpty()]
	    [String]
	    $StructuredData = '-',
	
	    [Parameter(mandatory=$false)]
	    [ValidateNotNullOrEmpty()]
	    [DateTime] 
	    $Timestamp = [DateTime]::Now,
	
	    [Parameter(mandatory=$false)]
	    [ValidateNotNullOrEmpty()]
        [UInt16]
	    $UDPPort = 514,
	
	    [Parameter(mandatory=$false)]
	    [switch]
	    $RFC3164
    )
    if ($minSeverity -eq $null) {$minSeverity="informational"}
    if ($severity.value__ -gt $minSeverity.value__) {return}

    # Evaluate the facility and severity based on the enum types
    $Facility_Number = $Facility.value__
    $Severity_Number = $Severity.value__
    Write-Verbose "Syslog Facility, $Facility_Number, Severity is $Severity_Number"

    # Calculate the priority
    $Priority = ($Facility_Number * 8) + $Severity_Number
    Write-Verbose "Priority is $Priority"

    <#
    Application name or process name, simply find out if a script is calling the CMDLet, else use PowerShell
    #>
    if ($ApplicationName -eq '')
    {
        if ($scriptname -eq $null) {
            #-- no scriptname is defined, trying to deduct it.
            if (($myInvocation.ScriptName -ne $null) -and ($myInvocation.ScriptName -ne ''))
            {
                $ApplicationName = split-path -leaf $myInvocation.ScriptName
            }
        
            else
            {
                $ApplicationName = "PowerShell"
            }
        } else
        {
            $applicationName=$scriptname
        }
        Set-Variable -Name Syslog_default_ApplicationName -Scope global -Value $Applicationname
    }


    <#
    According to RFC 5424
    1.  FQDN
    2.  Static IP address
    3.  Hostname - Windows always has one of these
    4.  Dynamic IP address
    5.  the NILVALUE
    #>
    if ($hostname -eq '')
    {
	    if ($ENV:userdnsdomain -ne $null)
	    {
		    $hostname = $ENV:Computername + "." + $ENV:userdnsdomain
	    }
	    else
	    {
		    $hostname = $ENV:Computername
	    }
        Set-Variable -Name Syslog_hostname -Scope global -Value $hostname

    }

    if ($RFC3164)
    {
	    Write-Verbose 'Using RFC 3164 UNIX/BSD message format'
	    #Get the timestamp
	    $FormattedTimestamp = $Timestamp.ToString('MMM dd HH:mm:ss')
	    # Assemble the full syslog formatted Message
	    $FullSyslogMessage = "<{0}>{1} {2} {3} {4}" -f $Priority, $FormattedTimestamp, $Hostname, $ApplicationName, $Message

    }
    else
    {
	    Write-Verbose 'Using RFC 5424 IETF message format'
	    #Get the timestamp
	    $FormattedTimestamp = $Timestamp.ToString('yyyy-MM-ddTHH:mm:ss.ffffffzzz')
	    # Assemble the full syslog formatted Message
	    $FullSyslogMessage = "<{0}>1 {1} {2} {3} {4} {5} {6} {7}" -f $Priority, $FormattedTimestamp, $Hostname, $ApplicationName, $ProcessID, $MessageID, $StructuredData, $Message
    }

    Write-Verbose "Message to send will be $FullSyslogMessage"

    # create an ASCII Encoding object
    $Encoding = [System.Text.Encoding]::ASCII

    # Convert into byte array representation
    $ByteSyslogMessage = $Encoding.GetBytes($FullSyslogMessage)

    # If the message is too long, shorten it
    if ($ByteSyslogMessage.Length -gt 1024)
    {
        Write-Warning "Syslog Message too long, will be truncated."
        $ByteSyslogMessage = $ByteSyslogMessage.SubString(0, 1024)
    }

    # Create a UDP Client Object
    $UDPCLient = New-Object System.Net.Sockets.UdpClient
    $UDPCLient.Connect($Server, $UDPPort)

    # Send the Message
    $UDPCLient.Send($ByteSyslogMessage, $ByteSyslogMessage.Length) | Out-Null

    #Close the connection
    $UDPCLient.Close()
}