﻿# Script Parameters for deploy-VMs.ps1
<#
    Author             : Bart Lievers
    Last Edit          : BL - 13-6-2017
    Version            : 1.1.0
    Copyright 2015 - CAM IT Solutions
#>

@{

    #-- default script parameters
        LogPath="d:\beheer\logs\deploy-VMs"
        LogDays=1 #-- Logs older dan x days will be removed
        OpenLog=$true #-- openlog file in notepad on creation ?
        NotePad="D:\Beheer\Software\Notepad++\notepad++.exe" #-- full path to Notepad++

    #-- Deployment
        ShutDownAfterCust=$true #-- Shutdown deployed VMs after finishing OS customization ??
        SelectFirstHost=$true  #-- Deploy VMs on first host in Cluster
        Gateway= "10.0.10.250"
        dns = "10.0.10.161","10.0.10.162"
        SubNetMask = "255.255.255.0"
        TO_OSCustomization= 25 #-- [min] max doorlooptijd voor het wachten op OS Customization
        TO_waitAfterCust=3 #-- [min] wachtijd na Customization OS is uitgevoerd
        TO_ShutdownPeriod=6 #-- [min] wachttijd (timeout) voordat gecontroleerd wordt of VM incl. VMware tools gestart is.
       

    #-- vSphere vCenter FQDN
        vCenter="000-srv-vmvc-01.paas.camcube.nl" #-- vCenter FQDN
        Cluster="C03-OTA" #-- Host cluster to deploy VMs into

    #-- CSV
        CSVfile="serverlistA.csv"
        CSVDelimiter=","
        refHeader=(
            "Hard disk 1",
            "Hard disk 2",
            "datastore",
            "deploy",
            "Memory",
            "nic",
            "Notes",
            "OS",
            "OSCustomizationSpec",
            "Servername",
            "template",
            "ip",
            "vcpu"
        )

    #-- workflow
        idletime=15 #-- [s] time each loop will wait before it runs again
        MaxrunningHours= 6 #-- [hours] Max time the workflow loop wil run.

    #-- Syslog parameters
        Log2SysLog=$false #-- enable / disable sending log messages to syslog
        Syslog_Server= "000-srv-vlfi-01.paas.camcube.nl" #-- FQDN or IP of syslog server
        Syslog_default_Facility="local7" #-- default syslog facility for POSH logging
        Syslog_Default_Severity="informational" #-- default syslog severity. Options are : Emergency, Alert, Critical, Error, Warning, Notice, Informational, Debug
        Syslog_default_minSeverity="Informational" #-- minimal severity level to send
        SysLog_default_UDPPort =514 #-- Default Syslog UDP port to connect to
        #-- these parameters are normaly auto-generated by syslog function
        SysLog_Hostname = ""  #-- FQDN of host running script
        Syslog_default_ApplicationName=""  #-- name of script / application to use in syslog message 

    #-- 
}