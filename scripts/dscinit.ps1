param(
    [Parameter(Mandatory=$false)]
    [string] $NodeName = "$env:COMPUTERNAME",

    [Parameter(Mandatory=$false)]
    [string] $NodeType = '0',

    [Parameter(Mandatory=$false)]
    [string] $HgsDomainName = 'contoso.hgs',

    [Parameter(Mandatory=$false)]
    [string] $SafeModeAdministratorPassword = 'Pa$$w0rd',

    [Parameter(Mandatory=$false)]
    [string] $HgsServiceName = 'TpmHgs01',

    [Parameter(Mandatory=$false)]
    [Uint16] $HttpPort = '80',

    [Parameter(Mandatory=$false)]
    [Uint16] $HttpsPort = '443',

    [Parameter(Mandatory=$false)]
    [string] $HttpsCertificateName = 'HGSHTTPSCert',

    [Parameter(Mandatory=$false)]
    [string] $EncryptionCertificateName = 'HGSEncryptionCert',

    [Parameter(Mandatory=$false)]
    [string] $SigningCertificateName = 'HGSSigningCert',

    [Parameter(Mandatory=$false)]
    [string] $HttpsCertificatePath = 'C:\HttpsCertificate.pfx',

    [Parameter(Mandatory=$false)]
    [string] $HttpsCertificatePassword = 'Pa$$w0rd',

    [Parameter(Mandatory=$false)]
    [string] $EncryptionCertificatePath = 'C:\encryptionCert.pfx',

    [Parameter(Mandatory=$false)]
    [string] $EncryptionCertificatePassword  = 'Pa$$w0rd',

    [Parameter(Mandatory=$false)]
    [string] $SigningCertificatePath = 'C:\signingCert.pfx',

    [Parameter(Mandatory=$false)]
    [string] $SigningCertificatePassword  = 'Pa$$w0rd',

    [Parameter(Mandatory=$false)]
    [string] $GenerateSelfSignedCertificate = "true",

    [Parameter(Mandatory=$false)]
    [ValidateSet ('TrustActiveDirectory', 'TrustTpm') ]
    [string] $AttestationMode = 'TrustTpm',

    [Parameter(Mandatory=$false)]
    [string] $HgsServerPrimaryIPAddress = "10.0.0.4",

    [Parameter(Mandatory=$false)]
    [string] $HgsServerPrimaryAdminUsername = "adminuser",

    [Parameter(Mandatory=$false)]
    [string] $HgsServerPrimaryAdminPassword = 'Pa$$w0rd12345'
)

### Install Windows Features and AutoReboot
Configuration xHGSCommon
{
        LocalConfigurationManager
        {
            RebootNodeIfNeeded = $true
            ConfigurationMode = "ApplyAndAutoCorrect";
        }

        WindowsFeature HostGuardianServiceRole
        {
            Name = "HostGuardianServiceRole";
            IncludeAllSubFeature =  $true;
        }
        WindowsFeature WebMGmtTools
        {
            Name = "Web-MGmt-Tools";
            IncludeAllSubFeature =  $true;
        }
        WindowsFeature RSATADTools
        {
            Name = "RSAT-AD-Tools";
            IncludeAllSubFeature =  $true;
        }

        WindowsFeature RSATClustering
        {
            Name = "RSAT-Clustering";
            IncludeAllSubFeature =  $true;
        }
} #End of xHGSCommon

Configuration xHGS
{
    Import-DscResource -ModuleName PSDesiredStateConfiguration

    ### Setup primary node
    Node $AllNodes.where{$_.Role -eq "FirstNode"}.NodeName
    {
            xHGSCommon CommonActivityFirstNode
            {
            }
			
			Log CreatingNewDomain
            {
                Message =  "Creating New Domain";
                DependsOn = '[xHGSCommon]CommonActivityFirstNode'
            }
			
			Script InstallHGSServer
            {
                SetScript = {
                     write-verbose "HgsDomainName: $($using:Node.HgsDomainName)";
                     Install-HgsServer -HgsDomainName  $($using:Node.HgsDomainName) -SafeModeAdministratorPassword (ConvertTo-SecureString $($using:Node.SafeModeAdministratorPassword) -AsPlainText -Force) 
                     ### request reboot machine
                     $global:DSCMachineStatus = 1
                 }

                TestScript = { 
                    $result = $null
                    try { 
                        $result = Get-ADDomain -Current LocalComputer -ErrorAction:SilentlyContinue
                        Write-Verbose "1st Get-ADDomain Result: $result"
                     } catch {}

                    if($result -eq $null) 
                    {
			            Write-Verbose "Machine may not ready. Wait for 300s, then retrying..."
	                    start-sleep -Seconds $($using:Node.SleepTime)
	                    try { 
         	                $result = Get-ADDomain -Current LocalComputer -ErrorAction:SilentlyContinue
                	        Write-Verbose "2nd Get-ADDomain Result: $result"
	                    } catch {}
	
			            if($result -eq $null)
			                {return $false}
		            }
                    return $true   
                }

                GetScript = { 
                        $result = (Get-ADDomain -Current LocalComputer)
                        return  @{ 
                                    Result = $result
                        }
                }
            } #End of Intall HgsServer

            Script InitializeHgsServer
            {
               DependsOn =  '[Script]InstallHGSServer'

               SetScript = {
                     write-verbose "Initializing HgsServer : $($using:Node.HgsDomainName)";

                     if(!(Get-PSDrive -Name AD -ErrorAction SilentlyContinue)){ New-PSDrive -Name AD -PSProvider ActiveDirectory -Root //RootDSE/ }                 
                     
                     $_HttpsCertificatePassword = ConvertTo-SecureString -AsPlainText "$($using:Node.HttpsCertificatePassword)" –Force
                     $_EncryptionCertificatePassword = ConvertTo-SecureString -AsPlainText "$($using:Node.EncryptionCertificatePassword)" –Force
                     $_SigningCertificatePassword = ConvertTo-SecureString -AsPlainText "$($using:Node.SigningCertificatePassword)" –Force

                     if([boolean]::Parse("$($using:Node.GenerateSelfSignedCertificate)"))
                     {
                        ### Generate self signed certificate and export to given path
                        $_Httpscertname = "$($using:Node.HttpsCertificateName)"
                        $_encryptioncertname = "$($using:Node.EncryptionCertificateName)"
                        $_signingcertname = "$($using:Node.SigningCertificateName)"
                        Write-verbose "Generating Certificate "
                        if (($httpsCert = Get-ChildItem  Cert:\LocalMachine\root | where {$_.Subject -eq ('CN=' + $_Httpscertname )}) -eq $null)
                        {                            
                            $httpsCert = New-SelfSignedCertificate -DnsName $_Httpscertname -CertStoreLocation Cert:\LocalMachine\my
                            Export-PfxCertificate -Cert $httpsCert -Password $_HttpsCertificatePassword -FilePath "$($using:Node.HttpsCertificatePath)" 
                            $httpsCert = Import-PfxCertificate -CertStoreLocation Cert:\LocalMachine\Root -FilePath "$($using:Node.HttpsCertificatePath)" -Password $_HttpsCertificatePassword
                        }

                        if (($encryptionCert = Get-ChildItem  Cert:\LocalMachine\my | where {$_.Subject -eq ('CN=' + $_encryptioncertname )}) -eq $null)
                        {                            
                            $encryptionCert = New-SelfSignedCertificate -DnsName $_encryptioncertname -CertStoreLocation Cert:\LocalMachine\my
                            Export-PfxCertificate -Cert $encryptionCert -Password $_EncryptionCertificatePassword -FilePath "$($using:Node.EncryptionCertificatePath)"
                        }

                        if (($signingCert = Get-ChildItem  Cert:\LocalMachine\my | where {$_.Subject -eq ('CN=' + $_signingcertname )}) -eq $null)
                        {                            
                            $signingCert = New-SelfSignedCertificate -DnsName $_signingcertname -CertStoreLocation Cert:\LocalMachine\my
                            Export-PfxCertificate -Cert $signingCert -Password $_SigningCertificatePassword -FilePath "$($using:Node.SigningCertificatePath)"
                        }
                     }
                     else
                     {
                        ### https cert need be imported to root store
                        if (($httpsCert = Get-ChildItem  Cert:\LocalMachine\root | where {$_.Subject -eq ('CN=' + $_Httpscertname )}) -eq $null)
                        {
                            
                            $httpsCert = Import-PfxCertificate -CertStoreLocation Cert:\LocalMachine\my -FilePath "$($using:Node.HttpsCertificatePath)" -Password $_HttpsCertificatePassword
                            $httpsCert = Import-PfxCertificate -CertStoreLocation Cert:\LocalMachine\Root -FilePath "$($using:Node.HttpsCertificatePath)" -Password $_HttpsCertificatePassword
                        }

                        if (($encryptionCert = Get-ChildItem  Cert:\LocalMachine\my | where {$_.Subject -eq ('CN=' + $_encryptioncertname )}) -eq $null)
                        {                            
                            $encryptionCert = Import-PfxCertificate -CertStoreLocation Cert:\LocalMachine\my -FilePath "$($using:Node.EncryptionCertificatePath)" -Password $_EncryptionCertificatePassword
                        }

                        if (($signingCert = Get-ChildItem  Cert:\LocalMachine\my | where {$_.Subject -eq ('CN=' + $_signingcertname )}) -eq $null)
                        {                            
                            $signingCert = Import-PfxCertificate -CertStoreLocation Cert:\LocalMachine\my -FilePath "$($using:Node.SigningCertificatePath)" -Password $_SigningCertificatePassword
                        }
                    }

                    [System.Security.Cryptography.RSACng] $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($httpsCert)
                    [System.Security.Cryptography.CngKey] $key = $rsa.Key
                    Write-Verbose "https Private key is located at $($key.UniqueName)"
                    $httpsCertPath = "C:\ProgramData\Microsoft\Crypto\Keys\$($key.UniqueName)"
                    $acl= Get-Acl -Path $httpsCertPath
                    $permission="Authenticated Users","FullControl","Allow"
                    $accessRule=new-object System.Security.AccessControl.FileSystemAccessRule $permission
                    $acl.AddAccessRule($accessRule)
                    Set-Acl $httpsCertPath $acl

                    [System.Security.Cryptography.RSACng] $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($encryptionCert)
                    [System.Security.Cryptography.CngKey] $key = $rsa.Key
                    Write-Verbose "encryptionCert Private key is located at $($key.UniqueName)"
                    $encryptionCertPath = "C:\ProgramData\Microsoft\Crypto\Keys\$($key.UniqueName)"
                    $acl= Get-Acl -Path $encryptionCertPath
                    $permission="Authenticated Users","FullControl","Allow"
                    $accessRule=new-object System.Security.AccessControl.FileSystemAccessRule $permission
                    $acl.AddAccessRule($accessRule)
                    Set-Acl $encryptionCertPath $acl  
                                    
                    [System.Security.Cryptography.RSACng] $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($SigningCert)
                    [System.Security.Cryptography.CngKey] $key = $rsa.Key
                    Write-Verbose "SigningCert Private key is located at $($key.UniqueName)"
                    $SigningCertPath = "C:\ProgramData\Microsoft\Crypto\Keys\$($key.UniqueName)"
                    $acl= Get-Acl -Path $SigningCertPath
                    $permission="Authenticated Users","FullControl","Allow"
                    $accessRule=new-object System.Security.AccessControl.FileSystemAccessRule $permission
                    $acl.AddAccessRule($accessRule)
                    Set-Acl $SigningCertPath $acl

                    if($using:Node.AttestationMode -eq 'TrustActiveDirectory')
                    {
                        Initialize-HgsServer -HgsServiceName $($using:Node.HgsServiceName) -Http -Https -TrustActiveDirectory `
                                            -HttpPort $($using:Node.HttpPort ) `
                                            -HttpsPort $($using:Node.HttpsPort ) `
                                            -HttpsCertificatePath $($using:Node.HttpsCertificatePath) `
                                            -HttpsCertificatePassword  $_HttpsCertificatePassword `
                                            -EncryptionCertificatePath  $($using:Node.EncryptionCertificatePath) `
                                            -EncryptionCertificatePassword  $_EncryptionCertificatePassword `
                                            -SigningCertificatePath  $($using:Node.SigningCertificatePath) `
                                            -SigningCertificatePassword  $_SigningCertificatePassword 
                    }

                    if($using:Node.AttestationMode -eq 'TrustTpm')
                    {
                        Initialize-HgsServer   -HgsServiceName  $($using:Node.HgsServiceName) -Http -Https -TrustTpm `
                                            -HttpPort $($using:Node.HttpPort ) `
                                            -HttpsPort $($using:Node.HttpsPort ) `
                                            -HttpsCertificatePath $($using:Node.HttpsCertificatePath) `
                                            -HttpsCertificatePassword  $_HttpsCertificatePassword `
                                            -EncryptionCertificatePath  $($using:Node.EncryptionCertificatePath) `
                                            -EncryptionCertificatePassword  $_EncryptionCertificatePassword `
                                            -SigningCertificatePath  $($using:Node.SigningCertificatePath) `
                                            -SigningCertificatePassword  $_SigningCertificatePassword 
                    }                       
                 }
 
                TestScript = { 
                    $result = $true                    
                    $Urls = @("http://localhost/Attestation/getinfo", "http://localhost/KeyProtection/service/metadata/2014-07/metadata.xml")
                    
                    foreach ($url in $Urls)
                    {
                        try  
                        {  
                            $response = [System.Net.WebRequest]::Create($url).GetResponse(); 
                            Write-verbose ($url + "Response Status Code: " + $response.StatusCode)    

                            if ($response.StatusCode -ne [System.Net.HttpStatusCode]::OK)
                            {  
                                $result = $false
                            }
                        }  
                        catch  
                        {  
                            $result = $false
                        }  
                    }

                    if ($result -eq $false)
                    {
                    	Write-Verbose "Machine may not ready. Wait for 300s, then retrying..."
	                    start-sleep -Seconds $($using:Node.SleepTime)
                        $result = $true
                        foreach ($url in $Urls)
                        {
                            try  
                            {  
                                $response = [System.Net.WebRequest]::Create($url).GetResponse(); 
                                Write-verbose ($url + "Response Status Code: " + $response.StatusCode)    

                                if ($response.StatusCode -ne [System.Net.HttpStatusCode]::OK)
                                {  
                                    $result = $false
                                }
                            }  
                            catch  
                            {  
                                $result = $false
                            }  
                        } 
                        if ($result -eq $false)
                        {
                            Write-verbose "Clearing HGS Server Configurtion from this node"
                            Clear-HgsServer -Force -Confirm:$false #-WarningAction:SilentlyContinue
                        }
                    }
                    return $result
                }

                GetScript = {
                    $result = $null
                    [System.Reflection.Assembly]::LoadWithPartialName("Microsoft.Windows.HgsStore")
                    $store = $null
                    $result = [Microsoft.Windows.HgsStore.HgsReplicatedStore]::TryOpenStore("Attestation", [ref]$store)
                    return  @{
                         Result = $result 
                    }
                 }

            } #End of Initialize-HgsServer
    } #End of Node

    ### Setup Additional Node
    Node $AllNodes.where{$_.Role -eq "SecondNode"}.NodeName
    {
            xHGSCommon CommonActivitySecondNode
            {
            }

            WaitForAny WaitForADOnPrimaryToReady 
            {
                   NodeName = $Node.HgsServerPrimaryIPAddress
                   ResourceName = "[Script]InitializeHgsServer"
                   RetryCount = 2*60
                   RetryIntervalSec = 30
                   DependsOn =  '[xHGSCommon]CommonActivitySecondNode'
            }

            Log ADOnPrimaryReady
            {
                DependsOn =  '[WaitForAny]WaitForADOnPrimaryToReady'
                Message =  "AD Ready on : $Node.HgsServerPrimaryIPAddress "  
            }

            script ChangeDNSAddress
            {
                DependsOn =  '[WaitForAny]WaitForADOnPrimaryToReady'
                SetScript = {
                    write-verbose "HgsServerPrimaryIPAddress: $($using:Node.HgsServerPrimaryIPAddress)"
                    $netipconfig = Get-NetIPConfiguration |? {$_.IPv4DefaultGateway -ne $null } | Select-Object -First 1 
                    $dnsclientAddress = get-DNSClientServerAddress -InterfaceIndex $netipconfig.InterfaceIndex |? {$_.AddressFamily -eq "2"}
                    Set-DnsClientServerAddress -InterfaceIndex $dnsclientAddress.InterfaceIndex -ServerAddresses "$($using:Node.HgsServerPrimaryIPAddress)"
                 }

                TestScript = { 
                    $netipconfig = Get-NetIPConfiguration |? {$_.IPv4DefaultGateway -ne $null } | Select-Object -First 1 
                    $dnsclientAddress = get-DNSClientServerAddress -InterfaceIndex $netipconfig.InterfaceIndex |? {$_.AddressFamily -eq "2"}
                    return  $dnsclientAddress.ServerAddresses.Contains("$($using:Node.HgsServerPrimaryIPAddress)")
                }

                GetScript = { 
                 $netipconfig = Get-NetIPConfiguration |? {$_.IPv4DefaultGateway -ne $null } | Select-Object -First 1 
                 Write-Verbose $netipconfig
                 $dnsclientAddress = get-DNSClientServerAddress -InterfaceIndex $($netipconfig.InterfaceIndex) |? {$_.AddressFamily -eq "2"}
                 return $dnsclientAddress
                }
            }

            Script InstallHGSServerSecondary
            {
               DependsOn = '[script]ChangeDNSAddress'

                SetScript = {
                     write-verbose "HgsDomainName: $($using:Node.HgsDomainName)";
                     Install-HgsServer  -HgsDomainName  $($using:Node.HgsDomainName)  `
                                        -SafeModeAdministratorPassword (ConvertTo-SecureString $($using:Node.SafeModeAdministratorPassword) -AsPlainText -Force) `
                                        -HgsDomainCredential (new-object -typename System.Management.Automation.PSCredential -argumentlist "$($using:Node.HgsDomainName)\$($using:Node.HgsServerPrimaryAdminUsername)", (ConvertTo-SecureString ($($using:Node.HgsServerPrimaryAdminPassword )) -AsPlainText -Force))
                     ### request reboot machine
                     $global:DSCMachineStatus = 1
                 }

                TestScript = { 
                    $result = $null
                    try { 
                        $result = Get-ADDomain -Current LocalComputer -ErrorAction:SilentlyContinue
                        Write-Verbose "1st Get-ADDomain Result: $result"
                     } catch {}

                    if ($result -eq $null) 
                    {
			            Write-Verbose "Machine may not ready. Wait for 300s, then retrying..."
	                    start-sleep -Seconds $($using:Node.SleepTime)
	                    try { 
         	                $result = Get-ADDomain -Current LocalComputer -ErrorAction:SilentlyContinue
                	        Write-Verbose "2nd Get-ADDomain Result: $result"
	                    } catch {}
	
			            if ($result -eq $null)
			                {return $false}
		            }
                    return $true 
                }

                GetScript = { 
                    $result = (Get-ADDomain -Current LocalComputer)
                    return  @{ 
                                Result = $result
                    }
                }
            } #End of Intall HgsServer

            Script InitializeHgsServerSecondary
            {
                DependsOn =  '[Script]InstallHGSServerSecondary'
                SetScript = {
                       $cred = (new-object -typename System.Management.Automation.PSCredential -argumentlist "$($using:Node.HgsDomainName)\$($using:Node.HgsServerPrimaryAdminUsername)", (ConvertTo-SecureString ($($using:Node.HgsServerPrimaryAdminPassword )) -AsPlainText -Force))
                       $sig = @'
                                [DllImport("advapi32.dll", SetLastError = true)]
                                public static extern bool LogonUser(string lpszUsername, string lpszDomain, string lpszPassword, int dwLogonType, int dwLogonProvider, ref IntPtr phToken);
                                [DllImport("kernel32.dll")]
                                public static extern Boolean CloseHandle(IntPtr hObject); 
'@

                        $ImpersonateLib  = Add-Type -PassThru -Namespace 'Lib.Impersonation' -Name ImpersonationLib -MemberDefinition $sig 
                        [IntPtr] $userToken = [Security.Principal.WindowsIdentity]::GetCurrent().Token
                        $userToken
                        $bLogin = $ImpersonateLib::LogonUser($cred.GetNetworkCredential().UserName, $cred.GetNetworkCredential().Domain, $cred.GetNetworkCredential().Password, 9, 0, [ref]$userToken)

                        if ($bLogin)
                        {
                            $Identity = New-Object Security.Principal.WindowsIdentity $userToken
                            $context = $Identity.Impersonate()
                        }
                        else
                        {
                            throw "Can't get Impersonate Token from DSC toLogon as User $cred.GetNetworkCredential().UserName."
                        }
                        
                        $_HttpsCertificatePassword = ConvertTo-SecureString -AsPlainText "$($using:Node.HttpsCertificatePassword)" –Force
                        $_EncryptionCertificatePassword = ConvertTo-SecureString -AsPlainText "$($using:Node.EncryptionCertificatePassword)" –Force 
                        $_SigningCertificatePassword = ConvertTo-SecureString -AsPlainText "$($using:Node.SigningCertificatePassword)" –Force
                        if ([boolean]::Parse("$($using:Node.GenerateSelfSignedCertificate)"))
                        {
                            if (($httpsCert = Get-ChildItem  Cert:\LocalMachine\root | where {$_.Subject -eq ('CN=' + $_Httpscertname )}) -eq $null)
                            {         
                                ### https cert need be imported to root store                    
                                $httpsCert = Import-PfxCertificate -CertStoreLocation Cert:\LocalMachine\my -FilePath (([string]::Format('\\{0}\{1}', $($using:Node.HgsServerPrimaryIPAddress), $($using:Node.HttpsCertificatePath))).replace(":","$")) -Password $_HttpsCertificatePassword               
                                $httpsCert = Import-PfxCertificate -CertStoreLocation Cert:\LocalMachine\root -FilePath (([string]::Format('\\{0}\{1}', $($using:Node.HgsServerPrimaryIPAddress), $($using:Node.HttpsCertificatePath))).replace(":","$")) -Password $_HttpsCertificatePassword               
                            }                    
                        }
                        else
                        { 
                            if (($httpsCert = Get-ChildItem  Cert:\LocalMachine\root | where {$_.Subject -eq ('CN=' + $_Httpscertname )}) -eq $null)
                            {  
                                ### https cert need be imported to root store
                                $httpsCert = Import-PfxCertificate -CertStoreLocation Cert:\LocalMachine\my -FilePath $($using:Node.HttpsCertificatePath) -Password $_HttpsCertificatePassword               
                                $httpsCert = Import-PfxCertificate -CertStoreLocation Cert:\LocalMachine\root -FilePath $($using:Node.HttpsCertificatePath) -Password $_HttpsCertificatePassword               
                            }
                        }
                        
                        [System.Security.Cryptography.RSACng] $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($httpsCert)
                        [System.Security.Cryptography.CngKey] $key = $rsa.Key
                        Write-Verbose "https Private key is located at $($key.UniqueName)"
                        $httpsCertPath = "C:\ProgramData\Microsoft\Crypto\Keys\$($key.UniqueName)"
                        $acl= Get-Acl -Path $httpsCertPath
                        $permission="Authenticated Users","FullControl","Allow"
                        $accessRule=new-object System.Security.AccessControl.FileSystemAccessRule $permission
                        $acl.AddAccessRule($accessRule)
                        Set-Acl $httpsCertPath $acl

                        Initialize-HgsServer -force -Confirm:$false -Http -Https -HgsServerIPAddress $($using:Node.HgsServerPrimaryIPAddress) `
                                                -HttpPort $($using:Node.HttpPort ) `
                                                -HttpsPort $($using:Node.HttpsPort ) `
                                                -HttpsCertificateThumbprint $httpsCert.thumbprint
 
						if ([boolean]::Parse("$($using:Node.GenerateSelfSignedCertificate)"))
                        {
                            if (($encryptionCert = Get-ChildItem  Cert:\LocalMachine\my | where {$_.Subject -eq ('CN=' + $_encryptioncertname )}) -eq $null)
                            {                            
                                $encryptionCert = Import-PfxCertificate -CertStoreLocation Cert:\LocalMachine\My -FilePath (([string]::Format('\\{0}\{1}', $($using:Node.HgsServerPrimaryIPAddress), $($using:Node.EncryptionCertificatePath))).replace(":","$")) -Password $_EncryptionCertificatePassword 
                            }

                            if (($signingCert = Get-ChildItem  Cert:\LocalMachine\my | where {$_.Subject -eq ('CN=' + $_signingcertname )}) -eq $null)
                            {                            
						        $signingCert = Import-PfxCertificate -CertStoreLocation Cert:\LocalMachine\My -FilePath (([string]::Format('\\{0}\{1}', $($using:Node.HgsServerPrimaryIPAddress), $($using:Node.SigningCertificatePath))).replace(":","$")) -Password $_SigningCertificatePassword 
                            }
                        }
                        else
                        {
                            if (($encryptionCert = Get-ChildItem  Cert:\LocalMachine\my | where {$_.Subject -eq ('CN=' + $_encryptioncertname )}) -eq $null)
                            {                            
                                $encryptionCert = Import-PfxCertificate -CertStoreLocation Cert:\LocalMachine\my -FilePath "$($using:Node.EncryptionCertificatePath)" -Password $_EncryptionCertificatePassword
                            }

                            if (($signingCert = Get-ChildItem  Cert:\LocalMachine\my | where {$_.Subject -eq ('CN=' + $_signingcertname )}) -eq $null)
                            {                            
                                $signingCert = Import-PfxCertificate -CertStoreLocation Cert:\LocalMachine\my -FilePath "$($using:Node.SigningCertificatePath)" -Password $_SigningCertificatePassword
                            }
                        }

                        [System.Security.Cryptography.RSACng] $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($encryptionCert)
                        [System.Security.Cryptography.CngKey] $key = $rsa.Key
                        Write-Verbose "encryptionCert Private key is located at $($key.UniqueName)"
                        $encryptionCertPath = "C:\ProgramData\Microsoft\Crypto\Keys\$($key.UniqueName)"
                        $acl= Get-Acl -Path $encryptionCertPath
                        $permission="Authenticated Users","FullControl","Allow"
                        $accessRule=new-object System.Security.AccessControl.FileSystemAccessRule $permission
                        $acl.AddAccessRule($accessRule)
                        Set-Acl $encryptionCertPath $acl  
                                    
                        [System.Security.Cryptography.RSACng] $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($SigningCert)
                        [System.Security.Cryptography.CngKey] $key = $rsa.Key
                        Write-Verbose "SigningCert Private key is located at $($key.UniqueName)"
                        $SigningCertPath = "C:\ProgramData\Microsoft\Crypto\Keys\$($key.UniqueName)"
                        $acl= Get-Acl -Path $SigningCertPath
                        $permission="Authenticated Users","FullControl","Allow"
                        $accessRule=new-object System.Security.AccessControl.FileSystemAccessRule $permission
                        $acl.AddAccessRule($accessRule)
                        Set-Acl $SigningCertPath $acl
                }
                 
                TestScript = { 
                    $result = $true                    
                    $Urls = @("http://localhost/Attestation/getinfo", "http://localhost/KeyProtection/service/metadata/2014-07/metadata.xml")
                    
                    foreach ($url in $Urls)
                    {
                        try  
                        {  
                            $response = [System.Net.WebRequest]::Create($url).GetResponse(); 
                            Write-verbose ($url + "Response Status Code: " + $response.StatusCode)    

                            if ($response.StatusCode -ne [System.Net.HttpStatusCode]::OK)
                            {  
                                $result = $false
                            }
                        }  
                        catch  
                        {  
                            $result = $false
                        }  
                    }

                    if ($result -eq $false)
                    {
                    	Write-Verbose "Machine may not ready. Wait for 300s, then retrying..."
	                    start-sleep -Seconds $($using:Node.SleepTime)
                        $result = $true
                        foreach ($url in $Urls)
                        {
                            try  
                            {  
                                $response = [System.Net.WebRequest]::Create($url).GetResponse(); 
                                Write-verbose ($url + "Response Status Code: " + $response.StatusCode)    

                                if ($response.StatusCode -ne [System.Net.HttpStatusCode]::OK)
                                {  
                                    $result = $false
                                }
                            }  
                            catch  
                            {  
                                $result = $false
                            }  
                        } 
                        if ($result -eq $false)
                        {
                            Write-verbose "Clearing HGS Server Configurtion from this node"
                            Clear-HgsServer -Force -Confirm:$false #-WarningAction:SilentlyContinue
                        }
                    }
                    return $result
                }

                GetScript = {
                    $result = $true                    
                    $Urls = @("http://localhost/Attestation/getinfo", "http://localhost/KeyProtection/service/metadata/2014-07/metadata.xml")
                    
                    foreach ($url in $Urls)
                    {
                        try  
                        {  
                            $response = [System.Net.WebRequest]::Create($url).GetResponse(); 
                            Write-verbose ($url + "Response Status Code: " + $response.StatusCode)    

                            if ($response.StatusCode -ne [System.Net.HttpStatusCode]::OK)
                            {  
                                $result = $false
                            }
                        }  
                        catch  
                        {  
                            $result = $false
                        }  
                    }
                    return $result
                 }
            } #End of Initialize-HgsServer
    }#End of Node   
} #End of Configuration

$ConfigData = @{
    AllNodes = 
    @(
        @{
            NodeName = '*';
            PSDscAllowPlainTextPassword = $true ;
            DebugMode = $true;          
            HgsDomainName = $HgsDomainName;
            SafeModeAdministratorPassword = $SafeModeAdministratorPassword;
            HgsServiceName = $HgsServiceName;
            HttpPort = $HttpPort;
            HttpsPort = $HttpsPort ;
			HttpsCertificateName = $HttpsCertificateName;
            EncryptionCertificateName = $EncryptionCertificateName;
            SigningCertificateName = $SigningCertificateName;
			GenerateSelfSignedCertificate = $GenerateSelfSignedCertificate;        
            HttpsCertificatePath = $HttpsCertificatePath;
            HttpsCertificatePassword= $HttpsCertificatePassword;
            EncryptionCertificatePath = $EncryptionCertificatePath;
            EncryptionCertificatePassword = $EncryptionCertificatePassword;
            SigningCertificatePath = $SigningCertificatePath;
            SigningCertificatePassword = $SigningCertificatePassword;
            AttestationMode = $AttestationMode;
            HgsServerPrimaryIPAddress = $HgsServerPrimaryIPAddress;
            HgsServerPrimaryAdminUsername = $HgsServerPrimaryAdminUsername ;
            HgsServerPrimaryAdminPassword = $HgsServerPrimaryAdminPassword ;
            SleepTime = 300
        }
    );
    NonNodeData = ""   
}

if($NodeType -eq '0')
{
    $_firstnode =   @{
            NodeName = "$NodeName";
            Role = "FirstNode" ;
        }
    $ConfigData.AllNodes += $_firstnode
}

if ($NodeType -ne '0')
{
    $_secondnode = @{
            NodeName = $NodeName;
            Role = "SecondNode" ;
        }
    $ConfigData.AllNodes += $_secondnode
}

xHGS -ConfigurationData $ConfigData 

### Force refresh local machine configuration
Set-DscLocalConfigurationManager -Path .\xHGS  -Force -Verbose -ComputerName $NodeName

Start-DscConfiguration -Verbose -wait -Path .\xHGS -Force -ComputerName $NodeName