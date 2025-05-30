function ArtifactCollector {

    <#
    .SYNOPSIS
        Collects artifacts for cyber assessments.
    .DESCRIPTION
        Collects artifacts for cyber assessments.
            - Active Directory: Domain Controllers, DHCP Servers, Subnets,
              Computers, Users, Groups, Group Policies, OUs, and Event Logs
            - PDQ Inventory database
            - Spiceworks Inventory database
            - Endpoint Security logs
            - Wi-Fi Profiles
            - Time Settings
            - Windows Event Collector (WEC) Configuration
            - Mapped Drives
            - Network Shares
            - Access Control Lists
            - DNS Client Cache
            - Network Neighbors (ARP, ND, etc.)
            - AppLocker Policy
            - Scheduled Tasks
    .EXAMPLE
        ArtifactCollector
        Collects all artifacts and zips them into an archive for transport.
    .INPUTS
        None
    .OUTPUTS
        System.Object
    .NOTES
        #######################################################################################
        Author:     Jason Adsit
        #######################################################################################
        License:    The Unlicence

                    This is free and unencumbered software released into the public domain.

                    Anyone is free to copy, modify, publish, use, compile, sell, or
                    distribute this software, either in source code form or as a compiled
                    binary, for any purpose, commercial or non-commercial, and by any
                    means.

                    In jurisdictions that recognize copyright laws, the author or authors
                    of this software dedicate any and all copyright interest in the
                    software to the public domain. We make this dedication for the benefit
                    of the public at large and to the detriment of our heirs and
                    successors. We intend this dedication to be an overt act of
                    relinquishment in perpetuity of all present and future rights to this
                    software under copyright law.

                    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
                    EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
                    MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
                    IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
                    OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
                    ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
                    OTHER DEALINGS IN THE SOFTWARE.

                    For more information, please refer to <http://unlicense.org>
        #######################################################################################
    .LINK
        https://github.com/stateoforegon-eis-css/ArtifactCollector
    .LINK
        https://security.oregon.gov
    .FUNCTIONALITY
        Collects artifacts for cyber assessments using native tools.
        No out-of-box PowerShell modules are required.
            - Active Directory: Domain Controllers, DHCP Servers, Subnets,
              Computers, Users, Groups, Group Policies, OUs, and Event Logs
            - PDQ Inventory database
            - Spiceworks Inventory database
            - Endpoint Security logs
            - Wi-Fi Profiles
            - Time Settings
            - Windows Event Collector (WEC) Configuration
            - Mapped Drives
            - Network Shares
            - Access Control Lists
            - DNS Client Cache
            - Network Neighbors (ARP, ND, etc.)
            - AppLocker Policy
            - Scheduled Tasks
    #>

    [CmdletBinding()]

    param () #param

    begin {

        Write-Verbose -Message 'Start a stopwatch so we know how long the script takes to run'
        $StartTime = Get-Date

        Write-Verbose -Message 'Determine the PowerShell Version'
        $PowVer = $PSVersionTable.PSVersion.Major

        #$Wmic = "$env:windir\System32\Wbem\WMIC.exe"

        $EventFilterXml = [xml]@'
<QueryList>
  <Query Id='0' Path='Security'>
    <Select Path='Security'>
      *[System[
        Provider[@Name='Microsoft-Windows-Security-Auditing']
        and
        (Level=4 or Level=0)
        and
        (
          EventID=4720 or
          EventID=4722 or
          (EventID &gt;= 4724 and EventID &lt;= 4729) or
          EventID=4732 or
          EventID=4733 or
          EventID=4740 or
          EventID=4741 or
          EventID=4743 or
          EventID=4756 or
          EventID=4757
        )
      ]]
    </Select>
  </Query>
</QueryList>
'@
    } #begin

    process {

        ### region Prep ###

        $acy = Read-Host -Prompt "Agency acronym: "

        #Write-Verbose -Message 'Set dotnet to use TLS 1.2'
        #[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

        Write-Verbose -Message 'Generate a unique name for ArtifactCollector output'
        $ArtifactDir = "$env:USERPROFILE\Downloads\"+$acy+"_Artifacts_$(Get-Date -Format yyyyMMdd_HHmm)"
        $ArtifactFile = "$ArtifactDir.zip"

        Write-Verbose -Message 'Create output directory'
        New-Item -Path $ArtifactDir -ItemType Directory -Force | Out-Null
        Push-Location -Path $ArtifactDir

        $ComputerSystem = Get-CimInstance -ClassName CIM_ComputerSystem
        $DomainJoined = $ComputerSystem.PartOfDomain
        ### endregion Prep ###

  ### region AD ###

      if ($DomainJoined) {

      $ConfigRoot = ([adsi]"LDAP://RootDSE").configurationNamingContext
    $DefaultNC = ([adsi]"LDAP://RootDSE").defaultNamingContext

    Write-Verbose -Message 'Get a list of domain controllers'
    $DcSearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher
    $DcSearcher.SearchRoot = "LDAP://$DefaultNC"
    $DcSearcher.Filter = "(primaryGroupID=516)"
    $DcSearcher.PropertiesToLoad.Add("dnshostname") | Out-Null
    $DcSearcher.PropertiesToLoad.Add("name") | Out-Null

    $DomainControllers = $DcSearcher.FindAll() | ForEach-Object {

        $HostName = $_.Properties["dnshostname"] | Select-Object -First 1
        $Name     = $_.Properties["name"] | Select-Object -First 1

        $IP = $null
        if ($HostName) {
            try {
                $IP = [System.Net.Dns]::GetHostAddresses($HostName) |
                      Where-Object { $_.AddressFamily -eq 'InterNetwork' } |
                      Select-Object -First 1
            } catch {
                Write-Warning "Failed to resolve IP for $HostName"
            }
        }

        # Show progress
        $Params = @{
            Activity = 'Active Directory: Enumerating Domain Controllers'
            Status   = "Now Processing: $Name ($HostName)"
        }
        Write-Progress @Params

        # Output as object for collection
        [PSCustomObject]@{
            Name       = $Name
            DNSHost    = $HostName
            IPAddress  = $IP.IPAddressToString
        }

    } # $DomainControllers


# Step 1: Getting all servers from AD 
Write-Host 'Searching for Web Hosting Services'
$WHSearcher = New-Object System.DirectoryServices.DirectorySearcher
$WHSearcher.Filter = "(&(objectClass=computer)(operatingSystem=*server*))"
$WHSearcher.PropertiesToLoad.Add("dnshostname") | Out-Null
$WHSearcher.SearchScope = "Subtree"

$Servers = $WHSearcher.FindAll() | ForEach-Object {
    $_.Properties["dnshostname"][0]
}

# Step 2: Check remotely for known web services (IIS, Apache, Tomcat, etc.)
$WebHosting = foreach ($Server in $Servers) {
    try {
        $Services = Get-WmiObject -Class Win32_Service -ComputerName $Server -ErrorAction Stop |
                    Where-Object { $_.Name -match "IIS|Apache|Tomcat|HTTPD|nginx|wamp|xampp|glassfish|jetty|resin|coldfusion|websphere|jboss|wildfly" }

        if ($Services) {
            [PSCustomObject]@{
                Server   = $Server
                Services = $Services.DisplayName -join ", "
            }
        }
    } catch {
        $ErrorMessage = $_.Exception.Message
        Write-Warning "Could not query ${Server}: $ErrorMessage"
    }
}

# $WebHosting


            Write-Verbose -Message 'Get a list of DHCP servers from ActiveDirectory'
            $DhcpSearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher
            $DhcpSearcher.Filter = "(&(objectClass=dhcpclass)(!(name=DhcpRoot)))"
            $DhcpSearcher.SearchRoot = [adsi]"LDAP://CN=NetServices,CN=Services,$ConfigRoot"

            $DhcpServers = $DhcpSearcher.FindAll() | ForEach-Object {

                [string]$_.Properties.name

                $Params = @{
                    Activity = 'Active Directory: Enumerating DHCP Servers'
                    Status = "Now Processing: $($_.Properties.name)"
                }

                Write-Progress @Params

            } # $DhcpServers

            Write-Verbose -Message 'Get domain name'
            $DomainName = $ComputerSystem.Domain
            $DomainName = $DomainName.ToUpper()

            Write-Verbose -Message 'Start gathering subnets'
            $SubnetSearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher
            $SubnetSearcher.Filter = "(objectCategory=subnet)"
            $SubnetSearcher.SearchRoot = [adsi]"LDAP://CN=Subnets,CN=Sites,$ConfigRoot"
            $Subnets = $SubnetSearcher.FindAll() | ForEach-Object {

                New-Object -TypeName psobject -Property @{
                    Subnet = [string]$_.Properties.name
                    Site = ([string]$_.Properties.siteobject).Split(',')[0] -replace 'CN='
                    Description = [string]$_.Properties.description
                }

                $Params = @{
                    Activity = 'Active Directory: Enumerating Subnets'
                    Status = "Now Processing: $([string]$_.Properties.name)"
                }

                Write-Progress @Params

            } # $Subnets

Write-Verbose -Message 'Start gathering computers'

$ComputerSearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher
$ComputerSearcher.Filter = "(objectClass=computer)"
$ComputerSearcher.PropertiesToLoad.AddRange(@(
    "name", "distinguishedName", "description", "servicePrincipalName", "memberOf",
    "operatingSystem", "operatingSystemHotfix", "operatingSystemServicePack",
    "operatingSystemVersion", "whenCreated", "modifyTimestamp", "whenChanged", "lastLogonTimestamp", "lastLogon", "userAccountControl"
))

$Computers = $ComputerSearcher.FindAll() | ForEach-Object {
    $props = $_.Properties

    New-Object -TypeName psobject -Property @{
        ComputerName       = [string]$props.name
        OperatingSystem    = [string]$props.operatingsystem
        DistinguishedName  = [string]$props.distinguishedname
        Description        = [string]$props.description
        ServicePrincipalName = $props.serviceprincipalname
        MemberOf           = $props.memberof
        whenCreated        = [string]$props.whencreated
        LastLogon          = [string]$props.lastlogon
        whenChanged        = [string]$props.whenChanged
        modifyTimestamp    = [string]$props.modifyTimestamp
        LastLogonTimestamp = [string]$props.lastlogontimestamp
        Enabled            = if ($props.useraccountcontrol) {
                                -not ([bool]($props.useraccountcontrol[0] -band 0x2))
                             } else { $null }
        OS                 = [string]$props.operatingsystem
        OSHotFix           = [string]$props.operatingsystemhotfix
        OSServicePack      = [string]$props.operatingsystemservicepack
        OSVersion          = [string]$props.operatingsystemversion        
    }

    $Params = @{
        Activity = 'Active Directory: Enumerating Computers'
        Status   = "Now Processing: $([string]$props.name)"
    }
    Write-Progress @Params
}

Write-Verbose -Message 'Start gathering users'
# Create Directory Entry for LDAP root
$Root = New-Object DirectoryServices.DirectoryEntry("LDAP://RootDSE")
$SearchBase = "LDAP://" + $Root.defaultNamingContext

# Set up Directory Searcher
$Searcher = New-Object DirectoryServices.DirectorySearcher([ADSI]$SearchBase)
$Searcher.Filter = "(&(objectCategory=person)(objectClass=user))"
$Searcher.PageSize = 1000

# Define properties to load
$Properties = @(
    "sAMAccountName", "whenCreated", "memberOf", "name", "userPrincipalName",
    "description", "createTimeStamp", "distinguishedName", "pwdLastSet",
    "whenChanged", "lastLogonTimestamp", "userAccountControl"
)
foreach ($prop in $Properties) { $Searcher.PropertiesToLoad.Add($prop) | Out-Null }

# Collect users
$Users = @()
$Results = $Searcher.FindAll()

foreach ($Result in $Results) {
    $User = $Result.Properties
    $Users += [PSCustomObject]@{
        SamAccountName        = $User["samaccountname"] | Select-Object -First 1
        whenCreated           = $User["whencreated"] | Select-Object -First 1
        MemberOf              = $User["memberof"]
        Name                  = $User["name"] | Select-Object -First 1
        UserPrincipalName     = $User["userprincipalname"] | Select-Object -First 1
        Description           = $User["description"] | Select-Object -First 1
        createTimeStamp       = $User["createtimestamp"] | Select-Object -First 1
        DistinguishedName     = $User["distinguishedname"] | Select-Object -First 1
        Created               = $User["whencreated"] | Select-Object -First 1
        pwdLastSet            = ([datetime]::FromFileTimeUTC($User["pwdlastset"][0])) 
        whenChanged           = $User["whenchanged"] | Select-Object -First 1
        LastLogonDate         = if ($User["lastlogontimestamp"]) { [datetime]::FromFileTimeUTC($User["lastlogontimestamp"][0]) } else { $null }
        PasswordNotRequired   = ([bool]($User["useraccountcontrol"][0] -band 0x20))
        PasswordNeverExpires  = ([bool]($User["useraccountcontrol"][0] -band 0x10000))
        PasswordLastSet       = ([datetime]::FromFileTimeUTC($User["pwdlastset"][0]))
    }
}

            Write-Verbose -Message 'Start gathering groups'
            $GroupSearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher
            $GroupSearcher.Filter = "(objectCategory=group)"
            $Groups = $GroupSearcher.FindAll() | ForEach-Object {

                $Member = $_.Properties.member | ForEach-Object {
                    $EachMember = $_
                    if ($EachMember -match 'LDAP://') {
                        $EachMember = $EachMember.Replace('LDAP://','')
                    }
                    $EachMember
                }

                $MemberOf = $_.Properties.memberof | ForEach-Object {
                    $EachMember = $_
                    if ($EachMember -match 'LDAP://') {
                        $EachMember = $EachMember.Replace('LDAP://','')
                    }
                    $EachMember
                }

                $GroupTypeRaw = $_.Properties.grouptype

                $GroupType = switch -Exact ($GroupTypeRaw) {
                    2 {'Global Distribution Group'}
                    4 {'Domain Local Distribution Group'}
                    8 {'Universal Distribution Group'}
                    -2147483646 {'Global Security Group'}
                    -2147483644 {'Domain Local Security Group'}
                    -2147483643 {'Built-In Group'}
                    -2147483640 {'Universal Security Group'}
                }

                New-Object -TypeName psobject -Property @{
                    SamAccountName = [string]$_.Properties.samaccountname
                    GroupType = $GroupType
                    Description = [string]$_.Properties.description
                    DistinguishedName = [string]$_.Properties.distinguishedname
                    Member = $Member
                    MemberOf = $MemberOf
                }

                $Params = @{
                    Activity = 'Active Directory: Enumerating Groups'
                    Status = "Now Processing: $([string]$_.Properties.samaccountname)"
                }

                Write-Progress @Params

            } # $Groups

            Write-Verbose -Message 'Start gathering GPOs'
            $GpoSearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher
            $GpoSearcher.Filter = "(objectCategory=groupPolicyContainer)"
            $GroupPolicies = $GpoSearcher.FindAll() | ForEach-Object {

                $GpFsPath = [string]$_.Properties.gpcfilesyspath
                $GpGuid = [string](Split-Path -Path $GpFsPath -Leaf)

                New-Object -TypeName psobject -Property @{
                    Name = [string]$_.Properties.displayname
                    DistinguishedName = [string]$_.Properties.distinguishedname
                    Path = $GpFsPath
                    Guid = $GpGuid
                }

                $Params = @{
                    Activity = 'Active Directory: Enumerating Group Policies'
                    Status = "Now Processing: $([string]$_.Properties.displayname)"
                }

                Write-Progress @Params

            } # $GroupPolicies

            Write-Verbose -Message 'Create a hashtable to translate GPO GUIDs to names'
            if ($PowVer -ge 5) {

                $GpHt = $GroupPolicies | Group-Object -Property Guid -AsHashTable

            } elseif ($PowVer -lt 5) {

                $GpHt = $GroupPolicies |
                Group-Object -Property Guid |
                ForEach-Object { @{ $_.Name = $_.Group.Name } }

            } # $PowVer

            Write-Verbose -Message 'Start gathering OUs'
            $OuSearcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher
            $OuSearcher.Filter = "(objectCategory=organizationalUnit)"
            $OUs = $OuSearcher.FindAll() | ForEach-Object {

                $GpLink = [string]$_.Properties.gplink

                Write-Verbose -Message 'Checking for linked GPOs'
                if ($GpLink -imatch 'LDAP://cn=') {

                    Write-Verbose -Message 'Linked GPOs detected'

                    Write-Verbose -Message 'Parsing gplink [string] into [psobject[]]'
                    $LinkedGPOs = $GpLink.Split('][') | Where-Object { $_ -imatch 'cn=' } | ForEach-Object {

                        $Guid = $_.Split(';')[0].Trim('[').Split(',')[0] -ireplace 'LDAP://cn='
                        $Name = $GpHt[$Guid].Name
                        $EnforcedString = [string]$_.Split(';')[-1].Trim(']')
                        $EnforcedInt = [int]$EnforcedString

                        if ($EnforcedInt -eq 0) {

                            $Enforced = $false

                        } elseif ($EnforcedInt -eq 1) {

                            $Enforced = $true

                        }

                        New-Object -TypeName psobject -Property @{
                            Name = $Name
                            Guid = $Guid
                            Enforced = $Enforced
                        }

                    } # $LinkedGPOs

                } elseif (-not $GpLink) {

                    $LinkedGPOs = $null

                } # if ($GpLink -match 'LDAP://cn=')

                $BlockedInheritanceString = [string]$_.Properties.gpoptions
                $BlockedInheritanceInt = [int]$BlockedInheritanceString

                if ($BlockedInheritanceInt -eq 0) {

                    $BlockedInheritance = $false

                } elseif ($BlockedInheritanceInt -eq 1) {

                    $BlockedInheritance = $true

                }

                New-Object -TypeName psobject -Property @{
                    Name = [string]$_.Properties.name
                    DistinguishedName = [string]$_.Properties.distinguishedname
                    Description = [string]$_.Properties.description
                    LinkedGPOs = $LinkedGPOs
                    BlockedInheritance = $BlockedInheritance
                }

                $Params = @{
                    Activity = 'Active Directory: Enumerating OUs'
                    Status = "Now Processing: $([string]$_.Properties.name)"
                }

                Write-Progress @Params

            } # $OUs

            $AdInfo = New-Object -TypeName psobject -Property @{
                Domain = $DomainName
                DomainControllers = $DomainControllers
                DhcpServers = $DhcpServers
                Subnets = $Subnets
                Computers = $Computers
                Users = $Users
                Groups = $Groups
                GroupPolicies = $GroupPolicies
                OUs = $OUs
                WebHosting = $WebHosting
            }

            $AdInfo | Export-Clixml -Path .\ActiveDirectory.xml

            Write-Verbose -Message 'Gather logs from DCs'
            $DCs = $AdInfo.DomainControllers.Name

            if ($DCs) {

                $DirName = 'EventLogs'

                New-Item -Path .\$DirName -ItemType Directory | Out-Null

                $DCs | ForEach-Object {

                    $EachDc = $_

                    $ErrorActionPreferenceBak = $ErrorActionPreference
                    $ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop

                    try {

                        $Params = @{
                            Activity = 'Active Directory: Gathering Event Logs'
                            Status = "Now Processing: Logs from $EachDc"
                        }

                        Write-Progress @Params

                        $Params = @{
                            ComputerName = $EachDc
                            FilterXml = $EventFilterXml
                            Oldest = $true
                            MaxEvents = 1000
                        }

                        Get-WinEvent @Params

                    } catch {

                        Write-Verbose -Message "Error gathering logs from $EachDc"

                    }

                    $ErrorActionPreference = $ErrorActionPreferenceBak

                } | Export-Clixml -Path .\$DirName\DcLogs.xml

            } #if ($DCs)
            ### endregion AD ###

            ### region GPO ###
            $DirName = 'GPO'
            New-Item -Path .\$DirName -ItemType Directory | Out-Null

            $GroupPolicies | Get-Item | ForEach-Object {

                $_ | Copy-Item -Recurse -Destination .\$DirName\ -ErrorAction SilentlyContinue

                $Params = @{
                    Activity = 'Active Directory: Copying GPOs'
                    Status = "Now Processing: $($GpHt[$($_.Name)].Name)"
                }

                Write-Progress @Params

            } # $GroupPolicies
            ### endregion GPO ###

        } #if ($DomainJoined)

        ### region PDQ ###
        $DirName = 'PDQ'

        $PdqDb = "$env:ProgramData\Admin Arsenal\PDQ Inventory\Database.db"
        $PdqPath = Resolve-Path -Path $PdqDb -ErrorAction SilentlyContinue

        if ($PdqPath) {

            New-Item -Path .\$DirName -ItemType Directory | Out-Null

            $ErrorActionPreferenceBak = $ErrorActionPreference
            $ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop

            try {

                Write-Verbose -Message 'Copying PDQ Inventory database'
                $PdqPath | Get-Item | Copy-Item -Destination .\$DirName\

            } catch {

                Write-Verbose -Message 'Failed to copy primary PDQ Inventory database'

                try {

                    $PdqDbBackup = "$env:ProgramData\Admin Arsenal\PDQ Inventory\Backups\Database.*.db.cab"

                    Write-Verbose -Message 'Copying latest backup of PDQ Inventory database'
                    Resolve-Path -Path $PdqDbBackup -ErrorAction SilentlyContinue |
                    Get-Item | Sort-Object -Property LastWriteTime | Select-Object -Last 1 |
                    Copy-Item -Destination .\$DirName\

                } catch {}

            }

            $ErrorActionPreference = $ErrorActionPreferenceBak

        } #if ($PdqPath)
        ### endregion PDQ ###

        ### region Spiceworks ###
        $DirName = 'Spiceworks'

        $SpiceworksDb = "${env:ProgramFiles(x86)}\Spiceworks\db\spiceworks_prod.db"
        $SpiceworksPath = Resolve-Path -Path $SpiceworksDb -ErrorAction SilentlyContinue

        if ($SpiceworksPath) {

            New-Item -Path .\$DirName -ItemType Directory | Out-Null

            $ErrorActionPreferenceBak = $ErrorActionPreference
            $ErrorActionPreference = [System.Management.Automation.ActionPreference]::Stop

            try {

                Write-Verbose -Message 'Copying Spiceworks Inventory database'
                $SpiceworksPath | Get-Item | Copy-Item -Destination .\$DirName\

            } catch {

                Write-Verbose -Message 'Failed to copy Spiceworks Inventory database'

            }

            $ErrorActionPreference = $ErrorActionPreferenceBak

        } #if ($SpiceworksPath)
        ### endregion Spiceworks ###

        ### region Sophos ###
        $DirName = 'Sophos'

        $SophosPath = "$env:ProgramData\Sophos"
        $SophosNtp = "$SophosPath\Sophos Network Threat Protection\Logs\SntpService.log"
        $SophosAv = "$SophosPath\Sophos Anti-Virus\Logs\SAV.txt"

        $Params = @{
            Path = $SophosNtp,$SophosAv
            ErrorAction = 'SilentlyContinue'
        }

        $Sophos = Resolve-Path @Params

        if ($Sophos) {

            Write-Verbose -Message "$DirName logs detected"
            New-Item -Path .\$DirName -ItemType Directory | Out-Null

            Write-Verbose -Message "Copying $DirName logs"
            $Sophos | Get-Item | ForEach-Object {

                $_ | Copy-Item -Destination .\$DirName\

                $Params = @{
                    Activity = 'Sophos: Gathering Logs'
                    Status = "Now Processing: $($_.Name)"
                }

                Write-Progress @Params

            } # $Sophos

        } #if ($Sophos)
        ### endregion Sophos ###

        ### region Symantec ###
        $DirName = 'Symantec'

        $SepLogPath = "$env:ProgramData\Symantec\Symantec Endpoint Protection\CurrentVersion\Data\Logs"
        $SepSecLog = "$SepLogPath\seclog.log"
        $SepTraLog = "$SepLogPath\tralog.log"
        $Symantec = Resolve-Path -Path $SepSecLog,$SepTraLog -ErrorAction SilentlyContinue

        if ($Symantec) {

            Write-Verbose -Message "$DirName logs detected"
            New-Item -Path .\$DirName -ItemType Directory | Out-Null

            Write-Verbose -Message "Copying $DirName logs"
            $Symantec | Get-Item | ForEach-Object {

                $_ | Copy-Item -Destination .\$DirName\
                Write-Progress -Activity 'Symantec: Gathering Logs' -Status "Now Processing: $($_.Name)"

            } # $Symantec

        } #if ($Symantec)
        ### region Symantec ###

        ### region McAfee ###
        $DirName = 'McAfee'

        $Params = @{
            Path = "$env:ProgramData\McAfee\Host Intrusion Prevention\HipShield.log*"
            ErrorAction = 'SilentlyContinue'
        }

        $McAfee = Resolve-Path @Params

        if ($McAfee) {

            Write-Verbose -Message "$DirName logs detected"
            New-Item -Path .\$DirName -ItemType Directory | Out-Null

            Write-Verbose -Message "Copying $DirName logs"
            $McAfee | Get-Item | ForEach-Object {

                $_ | Copy-Item -Destination .\$DirName\
                Write-Progress -Activity 'McAfee: Gathering Logs' -Status "Now Processing: $($_.Name)"

            } # $McAfee

        } #if ($McAfee)
        ### endregion McAfee ###

        ### region Trend Micro ###
        $DirName = 'Trend Micro'

        $TrendProgFiles = "$env:ProgramFiles*\$DirName"
        $TrendProgData = "$env:ProgramData\$DirName"
        $TrendPaths = (
            "$TrendProgFiles\*.log",
            "$TrendProgFiles\*\*.log",
            "$TrendProgData\*.log",
            "$TrendProgData\*\*.log"
        )

        $Params = @{
            Path = $TrendPaths
            ErrorAction = 'SilentlyContinue'
        }

        $TrendMicro = Resolve-Path @Params

        if ($TrendMicro) {

            Write-Verbose -Message "$DirName logs detected"
            New-Item -Path .\$DirName -ItemType Directory | Out-Null

            Write-Verbose -Message "Copying $DirName logs"
            $TrendMicro | Get-Item | ForEach-Object {

                $_ | Copy-Item -Destination .\$DirName\
                Write-Progress -Activity 'Trend Micro: Gathering Logs' -Status "Now Processing: $($_.Name)"

            } # $TrendMicro

        } #if ($TrendMicro)
        ### endregion Trend Micro ###

        ### region WiFi ###
        $DirName = 'WiFi'

        Write-Verbose -Message 'Using netsh to enumerate WiFi profiles'
        $WiFiProfiles = netsh wlan show profiles | Select-String -Pattern '\ :\ '

        if ($WiFiProfiles) {

            Write-Verbose -Message 'WiFi profiles found'
            New-Item -Path .\$DirName -ItemType Directory | Out-Null

            $WiFiProfiles = $WiFiProfiles | ForEach-Object {
                $_.ToString().Split(':')[-1].Trim()
            }

            Write-Verbose -Message 'Exporting the WiFi profiles to XML files'
            $WiFiProfiles | ForEach-Object {

                Write-Progress -Activity 'Gathering WiFi Profiles' -Status "Now Processing: $_"
                netsh wlan export profile name="$_" folder=".\$DirName" key=clear
                Clear-Host

            } # $WiFiProfiles

        } #if ($WiFiProfiles)
        ### endregion WiFi ###

        ### region Hyper-V ###
        $DirName = 'Hyper-V'

        Write-Verbose -Message 'Searching for Hyper-V Hosts'
        $HypervHosts = $AdInfo.Computers |
            Where-Object {
                'Microsoft Virtual Console Service' -in
                (
                    $_ | Select-Object -ExpandProperty ServicePrincipalName | ForEach-Object {
                        $_.Split('/')[0]
                    }
                )
            } | ForEach-Object {

                $CompName = $_.ComputerName
                Write-Progress -Activity 'Gathering Hyper-V Hosts' -Status "Now Processing: $CompName"

            }
        if ($HypervHosts) {

            Write-Verbose -Message 'Hyper-V hosts found'
            New-Item -Path .\$DirName -ItemType Directory | Out-Null

            Write-Verbose -Message 'Exporting the Hyper-V Hosts'
            $HypervHosts | Out-File .\$DirName\Hyper-V_Hosts.txt

        } #if ($HypervHosts)
        ### endregion Hyper-V ###

        ### region NTP ###
        $DirName = 'NTP'

        Write-Verbose -Message 'Gathering Time Servers to Check'
        $NtpServersToCheck = @()
        $HypervHosts | ForEach-Object { $NtpServersToCheck += $_ }
        $AdInfo.DomainControllers.Name | ForEach-Object { $NtpServersToCheck += $_ }

        Write-Verbose -Message 'Gathering Time Configuration From the Registry'
        $W32tmRegistry = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters |
            Select-Object -Property Type,ServiceDll,NtpServer
        $W32tmService = Get-Service -Name W32Time | Select-Object -Property Name,Status,StartType

        $NtpServersChecked = $NtpServersToCheck | ForEach-Object {

            $W32tmMonitorOutput = (w32tm /monitor /computers:$_ /nowarn) |
                Select-String -Pattern ':' |
                ForEach-Object { $_.ToString() }

            Write-Progress -Activity 'Gathering Time Settings' -Status "Now Processing: $_"
            New-Object -TypeName psobject -Property @{
                ComputerName = $_
                W32tmMonitorOutput = $W32tmMonitorOutput
            }

        } #$NtpServersChecked

        $W32tmMonitorOutput = (w32tm /monitor /nowarn) |
            Select-String -Pattern ':' |
            Select-Object -Skip 1 |
            ForEach-Object { $_.ToString() }

        $TimeConfig = New-Object -TypeName psobject -Property @{
            ComputerName = $env:COMPUTERNAME
            RegType = $W32tmRegistry.Type
            RegServiceDll = $W32tmRegistry.ServiceDll
            RegNtpServer = $W32tmRegistry.NtpServer
            ServiceName = $W32tmService.Name
            ServiceStatus = $W32tmService.Status
            ServiceStartType = $W32tmService.StartType
            W32tmMonitorOutput = (w32tm /monitor /nowarn)
            W32tmQueryConfigOutput = (w32tm /query /configuration)
            W32tmQueryPeersOutput = (w32tm /query /peers)
            W32tmQuerySourceOutput = (w32tm /query /source)
            NtpServersChecked = $NtpServersChecked
        }

        Write-Verbose -Message 'Exporting Time Settings'
        New-Item -Path .\$DirName -ItemType Directory | Out-Null

        $TimeConfig | Export-Clixml -Path .\$DirName\NtpConfig.xml
        ### endregion NTP ###

        ### region WEC ###
        $DirName = 'WEC'

        Write-Verbose -Message 'Gathering WEC Configuration From the Registry'
        $SubManPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\EventForwarding\SubscriptionManager'
        $HasWecPolicy = Get-ItemPropertyValue -Path $SubManPath -Name '1' -ErrorAction SilentlyContinue
        $WefLogName = 'Microsoft-Windows-Forwarding/Operational'

        if ($HasWecPolicy) {

            New-Item -Path .\$DirName -ItemType Directory | Out-Null
            $HasWecPolicy = $HasWecPolicy.Split('=')[-1].Trim()
            $HasWecPolicy | Out-File -FilePath .\$DirName\WecServer.txt
            Get-WinEvent -LogName $WefLogName | Export-Clixml -Path .\$DirName\WefEvents.xml

        } #if
        ### endregion WEC ###

        ### region Baseline ###
        Write-Verbose -Message 'Collecting Mapped Drives'
        $SmbDriveMaps = Get-CimInstance -Namespace root/Microsoft/Windows/SMB -ClassName MSFT_SmbMapping |
            Select-Object -Property @{Name='DriveLetter';Expression={$_.LocalPath}},
                                    @{Name='Path';Expression={$_.RemotePath}},
                                    RequireIntegrity,
                                    RequirePrivacy

        Write-Verbose -Message 'Collecting Local Network Shares'
        $SmbShares = Get-CimInstance -Namespace root/Microsoft/Windows/SMB -ClassName MSFT_SmbShare |
            Select-Object -Property Name,Path,Description

        Write-Verbose -Message 'Collecting DNS Client Cache'
        $DnsCache = Get-CimInstance -Namespace root/StandardCimv2 -ClassName MSFT_DNSClientCache |
            Select-Object -Property Data,Entry,Name,TimeToLive

        $v6LLMcast = 'NOT IPAddress LIKE "ff02%"'
        $v4Bcast = 'NOT IPAddress LIKE "255%"'
        $v4LLMcast = 'NOT IPAddress LIKE "224%"'
        $v4Mcast = 'NOT IPAddress LIKE "239%"'
        $EtherBcast = 'NOT LinkLayerAddress LIKE "FF-FF-FF-FF-FF-FF"'
        $ArpFailure = 'NOT LinkLayerAddress LIKE "00-00-00-00-00-00"'
        $NeighborFilter = "$v6LLMcast AND $v4Bcast AND $v4LLMcast AND $v4Mcast AND $EtherBcast AND $ArpFailure"

        $Params = @{
            Namespace = 'root/StandardCimv2'
            ClassName = 'MSFT_NetNeighbor'
            Property = 'IPAddress','LinkLayerAddress','InterfaceAlias'
            Filter = $NeighborFilter
        }

        Write-Verbose -Message 'Collecting Network Neighbors'
        $NetNeighbors = Get-CimInstance @Params |
            Select-Object -Property IPAddress,LinkLayerAddress,InterfaceAlias

        Write-Verbose -Message 'Determining Share Drive Access'
        $ShareDriveAccess = $SmbDriveMaps | Get-ChildItem -Directory | ForEach-Object {
            $Params = @{
                Activity = 'Baseline: Determining Share Drive Access'
                Status = "Now Processing: $($_.Name)"
            }
            Write-Progress @Params
            $Acl = $_ | Get-Acl
            $_ | Add-Member -MemberType NoteProperty -Name Owner -Value $Acl.Owner -PassThru |
            Add-Member -MemberType NoteProperty -Name Access -Value $Acl.Access -PassThru
        } | Select-Object -Property Name,@{Name='Path';Expression={$_.FullName}},Owner,Access

        Write-Verbose -Message 'Exporting AppLocker Policy'
        $AppLockerPolicy = Get-AppLockerPolicy -Effective -Xml

        Write-Verbose -Message 'Collecting Scheduled Tasks'
        $Params = @{
            Namespace = 'root/Microsoft/Windows/TaskScheduler'
            ClassName = 'MSFT_ScheduledTask'
        }

        $ScheduledTasks = Get-CimInstance @Params |
        Select-Object -Property TaskName,
                                TaskPath,
                                @{n='Execute';e={[string]$_.Actions.Execute}},
                                @{n='Arguments';e={[string]$_.Actions.Arguments}} |
        Where-Object { $_.Execute } | ForEach-Object {
            $Params = @{
                Activity = 'Baseline: Collecting Scheduled Tasks'
                Status = "Now Processing: $($_.TaskName)"
            }
            Write-Progress @Params
            $_
        }

        Write-Verbose -Message 'Exporting the Baseline to XML'
        New-Object -TypeName psobject -Property @{
            SmbDriveMaps = $SmbDriveMaps
            ShareDriveAccess = $ShareDriveAccess
            SmbShares = $SmbShares
            DnsCache = $DnsCache
            NetNeighbors = $NetNeighbors
            AppLockerPolicy = [string]$AppLockerPolicy
            ScheduledTasks = $ScheduledTasks
        } | Export-Clixml -Path .\Baseline.xml
        ### endregion Baseline ###

        ### region ZIP ###
        if ($PowVer -ge 5) {

            Write-Verbose -Message 'PowerShell 5 detected, using built-in cmdlets to zip the files'
            Compress-Archive -Path $ArtifactDir -DestinationPath $ArtifactDir

        } elseif (($PowVer -lt 5) -and ($PowVer -gt 2)) {

            Write-Verbose -Message 'PowerShell 3 or 4 detected, using dotnet to zip the files'
            Add-Type -AssemblyName System.IO.Compression.FileSystem

            $Compression = [System.IO.Compression.CompressionLevel]::Optimal
            $Archive = [System.IO.Compression.ZipFile]::Open($ArtifactFile,"Update")

            Get-ChildItem -Path .\ -Recurse -File -Force |
            Select-Object -ExpandProperty FullName | ForEach-Object {

                $RelPath = (Resolve-Path -Path $_ -Relative).TrimStart(".\")

                $null = [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
                    $Archive,
                    $_,
                    $RelPath,
                    $Compression
                )

                $EachFile = Split-Path -Path $_ -Leaf

                $Params = @{
                    Activity = 'Archive: Zipping Artifact Folder'
                    Status = "Now Processing: $EachFile"
                }

                Write-Progress @Params

            } #ForEach File

            $Archive.Dispose()

        } elseif ($PowVer -le 2) {

            Write-Verbose -Message 'PowerShell 2 detected, using a COM object to zip the files'
            Write-Verbose -Message 'Creating an empty ZIP file'
            Set-Content -Path $ArtifactFile -Value ("PK" + [char]5 + [char]6 + ("$([char]0)" * 18))

            $ShellApp = New-Object -ComObject Shell.Application
            $ArtifactZip = Get-Item -Path $ArtifactFile
            $ArtifactZip.IsReadOnly = $false
            $ShellZip = $ShellApp.NameSpace($ArtifactZip.FullName)

            Write-Verbose -Message 'Copy all files into the ZIP'
            $ShellZip.CopyHere($ArtifactDir)
            Start-Sleep -Seconds 2

        } #if $PowVer
        ### endregion ZIP ###

        # Change directory back to wherever we started
        Pop-Location

    } #process

    end {

        $EndTime = Get-Date
        $Seconds = [int](([string]((New-TimeSpan -Start $StartTime -End $EndTime).TotalSeconds)).Split('.')[0])
        $ArtifactZip = Get-Item -Path $ArtifactFile

        New-Object -TypeName psobject -Property @{
            Name = (Split-Path -Path $ArtifactZip.FullName -Leaf)
            Size = "$($(($ArtifactZip.Length)/1MB)) MB"
            Time = "$Seconds sec"
            Path = $ArtifactZip.FullName
            Comment = "Please arrange to get the '$($ArtifactZip.Name)' file to the assessment team."
        }

    } #end

} #ArtifactCollector

# Execute the ArtifactCollector function
ArtifactCollector
