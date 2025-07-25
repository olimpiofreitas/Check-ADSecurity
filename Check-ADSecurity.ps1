# Script: Check-ADSecurityRisks.ps1
# Requer o módulo ActiveDirectory e permissões de administrador local/domain

# 0. Certificar módulo AD instalado
try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Write-Error "Módulo ActiveDirectory não está disponível. Instale RSAT e tente novamente."
    exit
}

Write-Output "=== Iniciando verificações de segurança do Active Directory ==="

# 1. Serviços executando de caminhos graváveis
Get-Service | ForEach-Object {
    $svc = $_
    $path = (Get-WmiObject Win32_Service -Filter "Name='$($svc.Name)'").PathName
    if ($path -match "C:\\Users\\") {
        Write-Warning "Serviço '$($svc.Name)' executa de caminho instável: $path"
    }
}

# 2. Permissões de escrita em pastas sensíveis
$folders = @("C:\Windows","C:\Program Files","C:\Program Files (x86)")
foreach ($f in $folders) {
    Get-Acl $f | Select-Object -Expand Access |
        Where-Object { $_.FileSystemRights -match "Write" -and $_.IdentityReference -notmatch "Administrators" } |
        ForEach-Object {
            Write-Warning "Permissão WRITE fora do Administrators em $f por $($_.IdentityReference)"
        }
}

# 3. Tarefas agendadas com privilégios elevados
Get-ScheduledTask | ForEach-Object {
    $task = $_
    if ($task.Principal.RunLevel -ne "LeastPrivilege") {
        Write-Warning "Tarefa '$($task.TaskPath)\$($task.TaskName)' com RunLevel=$($task.Principal.RunLevel) por '$($task.Principal.UserId)'"
    }
}

# 4. Checa AlwaysInstallElevated nas chaves de registro
$keys = @("HKLM:\Software\Policies\Microsoft\Windows\Installer","HKCU:\Software\Policies\Microsoft\Windows\Installer")
foreach ($k in $keys) {
    $val = (Get-ItemProperty -Path $k -Name AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated
    Write-Output "$k : $val"
    if ($val -eq 1) {
        Write-Warning "AlwaysInstallElevated habilitado em $k"
    }
}

# 5. Diretórios no PATH graváveis
$env:Path -split ";" | ForEach-Object {
    if (Test-Path $_) {
        $acl = Get-Acl $_
        if ($acl.Access | Where-Object { $_.FileSystemRights -match "Write" -and $_.IdentityReference -notmatch "Administrators" }) {
            Write-Warning "PATH gravável por não-admin: $_"
        }
    }
}

# 6. Políticas de auditoria AD — usando GPOs
Write-Output "`nAuditoria GPOs do domínio:"
Import-Module GroupPolicy -ErrorAction SilentlyContinue
if (Get-Command Get-GPOReport -ErrorAction SilentlyContinue) {
    $xml = Get-GPOReport -All -ReportType Xml
    $report = [xml]$xml
    # Exibe se logs de segurança estão configurados
    Write-Output "Logs básicos e script block logging habilitados conforme política? (via GPO)"
} else {
    Write-Warning "Módulo GroupPolicy não disponível para relatório GPO"
}

# 7. Checar logs de auditoria no DC — eventos de criação de contas por exemplo
$dc = (Get-ADDomainController -Discover -Service PrimaryDC).Name
Get-WinEvent -ComputerName $dc -FilterHashtable @{LogName="Security"; Id=4720,4726} |
    Select TimeCreated,
           @{n="TargetUser";e={([xml]$_.ToXml()).Event.EventData.Data | where Name -eq 'TargetUserName' |%{$_.'#text'}}},
           Id |
    Sort TimeCreated -Descending | Select -First 10 |
    ForEach-Object {
        Write-Output "Evento $_.Id em $($_.TimeCreated) para usuário $($_.TargetUser)"
    }

Write-Output "`n=== Verificações concluídas ==="
