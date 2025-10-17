#Requires -Version 5.1
#Requires -RunAsAdministrator

#ID 1000, SMBv1 Support
function Disable-SMBv1 {
    Write-Host "`n[INFO] Disable SMBv1..." -ForegroundColor Cyan

    try {
        if ((Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol).State -eq "Enabled") {
            Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol | Out-Null
            Write-Host "✅ SMBv1 is disabled" -ForegroundColor Green
        } else {
            Write-Host "⚠️ SMBv1 is already disabled" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "❌ Impossible to check the status of SMBv1" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor DarkRed
    }
}

#ID 1103, Store passwords using reversible encryption --> TODO
function StorePasswordUsingReversibleEncryption {
    Write-Host "Store password using reversible encryption"

}

#ID 1101, Account lockout duration
#ID 1100, Account lockout threshold
#ID 1102, Reset account lockout counter
function Set-AccountLockout {
    Write-Host "`n[INFO] Setup account lockout..." -ForegroundColor Cyan
    net accounts /lockoutthreshold:10 /lockoutduration:15 /lockoutwindow:15 | Out-Null
}

#ID 1200, Access this computer from the network
#ID 1201, Allow log on locally
#ID 1202, Debug programs
#ID 1203, Deny access to this computer from the network
#ID 1204, Deny log on as a batch job
#ID 1205, Deny log on as a service
#ID 1206, Deny log on through Remote Desktop Services
function Set-UserRightsRemove {
    [CmdletBinding()]
    param()

    Write-Host "`n[INFO] Remove the incorrect users to the 'Assignment of User Rights' section..." -ForegroundColor Cyan

    $RemoveRightParams = @(
        @{ Username = "S-1-1-0"; UserRight = "SeNetworkLogonRight" }, #Everyone
        @{ Username = "S-1-5-32-545"; UserRight = "SeNetworkLogonRight" }, #BUILTIN\Users
        @{ Username = "S-1-5-32-551"; UserRight = "SeNetworkLogonRight" }, #BUILTIN\Backup Operators
        @{ Username = "S-1-5-32-546"; UserRight = "SeInteractiveLogonRight" }, #BUILTIN\Guests
        @{ Username = "S-1-5-32-551"; UserRight = "SeInteractiveLogonRight"; }, #BUILTIN\Backup Operators
        @{ Username = "S-1-5-32-544"; UserRight = "SeDebugPrivilege"; }, #BUILTIN\Administrators
        @{ Username = "S-1-5-32-546"; UserRight = "SeDenyNetworkLogonRight"; } #BUILTIN\Guests
        #TODO : voir pour la partie 'SeDenyRemoteInteractiveLogonRight'
    )
    
    foreach ($RemoveRight in $RemoveRightParams) {
        $params = @{
            Username = $RemoveRight.Username
            UserRight = $RemoveRight.UserRight
        }

        try {
            & .\Tools\Set-UserRights.ps1 -RemoveRight @params
            Write-Host "✅ Delete user $($RemoveRight.Username) in $($RemoveRight.UserRight)" -ForegroundColor Green
        } catch {
            Write-Host "❌ Impossible to remove user : $($RemoveRight.Username) in $($RemoveRight.UserRight)" -ForegroundColor Red
            Write-Host $_.Exception.Message -ForegroundColor DarkRed
        }
    }
}

function Set-UserRightsAdd {
    [CmdletBinding()]
    param()

    Write-Host "`n[INFO] Add the correct users to the 'Assignment of User Rights' section..." -ForegroundColor Cyan

    $AddRightParams = @(
        @{ Username = "S-1-5-32-544"; UserRight = "SeNetworkLogonRight" }, #BUILTIN\Administrators
        @{ Username = "S-1-5-32-544"; UserRight = "SeInteractiveLogonRight" }, #BUILTIN\Administrators
        @{ Username = "S-1-5-32-545"; UserRight = "SeInteractiveLogonRight" }, #BUILTIN\Users
        @{ Username = "S-1-5-32-546"; UserRight = "SeDenyNetworkLogonRight"; }, #BUILTIN\Guests
        @{ Username = "S-1-5-113"; UserRight = "SeDenyNetworkLogonRight"; }, #NT AUTHORITY\Local account
        @{ Username = "S-1-5-32-546"; UserRight = "SeDenyBatchLogonRight"; }, #BUILTIN\Guests
        @{ Username = "S-1-5-32-546"; UserRight = "SeDenyServiceLogonRight"; }, #BUILTIN\Guests
        @{ Username = "S-1-5-32-546"; UserRight = "SeDenyRemoteInteractiveLogonRight"; }, #BUILTIN\Guests
        @{ Username = "S-1-5-113"; UserRight = "SeDenyRemoteInteractiveLogonRight"; } #NT AUTHORITY\Local account
    )
    
    foreach ($AddRight in $AddRightParams) {
        $params = @{
            Username = $AddRight.Username
            UserRight = $AddRight.UserRight
        }

        try {
            & .\Tools\Set-UserRights.ps1 -AddRight @params
            Write-Host "✅ Add user $($AddRight.Username) in $($AddRight.UserRight)" -ForegroundColor Green
        } catch {
            Write-Host "❌ Impossible to add user $($AddRight.Username) in $($AddRight.UserRight)" -ForegroundColor Red
            Write-Host $_.Exception.Message -ForegroundColor DarkRed
        }
    }    
}

function Set-CategorySecurityOptions {
    [CmdletBinding()]
    param()

    Write-Host "`n[INFO] Setup category Security Options..." -ForegroundColor Cyan

    $securityOptionsParams = @(
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"; Name = "AllowAdministratorLockout"; Type = "Dword"; Value = 1 }, #ID 1104, Allow Administrator account lockout
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "NoConnectedUser"; Type = "Dword"; Value = 3 }, #ID 1300, Accounts: Block Microsoft accounts
        @{ Path = "HKLM:\System\CurrentControlSet\Control\Lsa"; Name = "SCENoApplyLegacyAuditPolicy"; Type = "Dword"; Value = 1 }, #ID 1301, Audit: Force audit policy subcategory settings to override audit policy category settings
        @{ Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "DisableCAD"; Type = "Dword"; Value = 0 }, #ID 1302, Interactive logon: Do not require CTRL+ALT+DEL
        @{ Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "dontdisplaylastusername"; Type = "Dword"; Value = 1 }, #ID 1303, Interactive logon: Don't display last signed-in
        @{ Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "DontDisplayUserName"; Type = "Dword"; Value = 1 }, #ID 1304, Interactive logon: Don't display username at sign-in
        @{ Path = "HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters"; Name = "RequireSecuritySignature"; Type = "Dword"; Value = 1 }, #ID 1305, Microsoft network client: Digitally sign communications (always)
        @{ Path = "HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters"; Name = "EnableSecuritySignature"; Type = "Dword"; Value = 1 }, #ID 1306, Microsoft network client: Digitally sign communications (if server agrees)
        @{ Path = "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters"; Name = "RequireSecuritySignature"; Type = "Dword"; Value = 1 }, #ID 1307, Microsoft network server: Digitally sign communications (always)
        @{ Path = "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters"; Name = "EnableSecuritySignature"; Type = "Dword"; Value = 1 }, #ID 1308, Microsoft network server: Digitally sign communications (if client agrees)
        @{ Path = "HKLM:\System\CurrentControlSet\Control\Lsa"; Name = "RestrictAnonymousSAM"; Type = "Dword"; Value = 1 }, #ID 1309, Network access: Do not allow anonymous enumeration of SAM accounts
        @{ Path = "HKLM:\System\CurrentControlSet\Control\Lsa"; Name = "RestrictAnonymous"; Type = "Dword"; Value = 1 }, #ID 1310, Network access: Do not allow anonymous enumeration of SAM accounts and shares
        @{ Path = "HKLM:\System\CurrentControlSet\Control\Lsa"; Name = "DisableDomainCreds"; Type = "Dword"; Value = 1 }, #ID 1311, Network access: Do not allow storage of passwords and credentials for network authentication
        @{ Path = "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters"; Name = "RestrictNullSessAccess"; Type = "Dword"; Value = 1 }, #ID 1324, Network access: Restrict anonymous access to Named Pipes and Shares
        @{ Path = "HKLM:\System\CurrentControlSet\Control\Lsa"; Name = "RestrictRemoteSAM"; Type = "String"; Value = "O:BAG:BAD:(A;;RC;;;BA)" }, #ID 1325, Network access: Restrict clients allowed to make remote calls to SAM
        @{ Path = "HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0"; Name = "allownullsessionfallback"; Type = "Dword"; Value = 0 }, #ID 1312, Network security: Allow LocalSystem NULL session fallback
        @{ Path = "HKLM:\System\CurrentControlSet\Control\Lsa"; Name = "NoLMHash"; Type = "Dword"; Value = 1 }, #ID 1326, Network security: Do not store LAN Manager hash value on next password change
        @{ Path = "HKLM:\System\CurrentControlSet\Control\Lsa"; Name = "LmCompatibilityLevel"; Type = "Dword"; Value = 5 }, #ID 1313, Network security: LAN Manager authentication level
        @{ Path = "HKLM:\System\CurrentControlSet\Services\LDAP"; Name = "LDAPClientIntegrity"; Type = "Dword"; Value = 1 }, #ID 1314, Network security: LDAP client signing requirements
        @{ Path = "HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0"; Name = "NTLMMinClientSec"; Type = "Dword"; Value = 537395200 }, #ID 1315, Network security: Minimum session security for NTLM SSP based (including secure RPC) clients
        @{ Path = "HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0"; Name = "NTLMMinServerSec"; Type = "Dword"; Value = 537395200 }, #ID 1316, Network security: Minimum session security for NTLM SSP based (including secure RPC) servers
        @{ Path = "HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0"; Name = "AuditReceivingNTLMTraffic"; Type = "Dword"; Value = 2 }, #ID 1317, Network security: Restrict NTLM: Audit Incoming NTLM Traffic
        @{ Path = "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters"; Name = "AuditNTLMInDomain"; Type = "Dword"; Value = 7 }, #ID 1318, Network security: Restrict NTLM: Audit NTLM authentication in this domain
        @{ Path = "HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0"; Name = "RestrictSendingNTLMTraffic"; Type = "Dword"; Value = 1 }, #ID 1319, Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers
        @{ Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "ShutdownWithoutLogon"; Type = "Dword"; Value = 0 }, #ID 1320, Shutdown: Allow system to be shut down without having to log on
        @{ Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "FilterAdministratorToken"; Type = "Dword"; Value = 1 }, #ID 1321, User Account Control: Admin Approval Mode for the Built-in Administrator account
        @{ Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "ConsentPromptBehaviorAdmin"; Type = "Dword"; Value = 2 }, #ID 1322, User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode
        @{ Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"; Name = "ConsentPromptBehaviorUser"; Type = "Dword"; Value = 1 } #ID 1323, User Account Control: Behavior of the elevation prompt for standard users
    )

    foreach ($securityOptions in $securityOptionsParams) {
        $params = @{
            Path    = $securityOptions.Path
            Name    = $securityOptions.Name
            Type    = $securityOptions.Type
            Value   = $securityOptions.Value
        }

        try {
            if (!(Test-Path $securityOptions.Path)) {
                Write-Host "✅ Create key : $($securityOptions.Path)" -ForegroundColor Green
                New-Item $securityOptions.Path | Out-Null
            } else {
                Write-Host "⚠️ Key already exist : $($firewallParam.Path)" -ForegroundColor Yellow
            }

            if ((Get-ItemProperty -Path "$($securityOptions.Path)" -Name "$($securityOptions.Name)" -ErrorAction SilentlyContinue).$($securityOptions.Name) -notlike $($securityOptions.Value)) {
                Set-ItemProperty @params | Out-Null
                Write-Host "✅ Create/modify the value $($securityOptions.Name) with the value $($securityOptions.Value)" -ForegroundColor Green
            } else {
                Write-Host "⚠️ Value already exist and is set" -ForegroundColor Yellow
            }
        } catch {
            Write-Host "❌ Impossible to create the key $($securityOptions.Path) and to modify the value $($securityOptions.Type) '$($securityOptions.Name)'" -ForegroundColor Red
            Write-Host $_.Exception.Message -ForegroundColor DarkRed
        }
    }
}

Disable-SMBv1
#StorePasswordUsingReversibleEncryption
Set-AccountLockout
Set-UserRightsRemove
Set-UserRightsAdd
Set-CategorySecurityOptions