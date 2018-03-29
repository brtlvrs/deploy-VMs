function global:prompt{

    # change prompt text
    Write-Host "brtlvrs " -NoNewLine -ForegroundColor orange
    Write-Host ((Get-location).Path + ">") -NoNewLine
    return " "
}