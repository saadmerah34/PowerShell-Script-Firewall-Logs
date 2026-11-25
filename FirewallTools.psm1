

# ==========================================
# MODULE : Firewalltools
# COURS  : CR431 - Introduction à PowerShell
# ==========================================


# ------------------------------------------
# FONCTION 1 : Lire les journaux Firewall ou Pihol
# ------------------------------------------
function Import-FWLog  {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    try {
        # Verifie si le fichier existe.
        if (-not (Test-Path $Path)) {
            throw "File not found: $Path"
        }

        # Lit la premiere ligne pour detecter le type de log.
        $firstLine = Get-Content -Path $Path -TotalCount 1

        if ($firstLine -match 'log_type="Firewall"') {
            $logType = "Firewall"
        }
        elseif ($firstLine -match "dnsmasq") {
            $logType = "PiHole"
        }
        else {
            $logType = "Unknown"
        }

        if ($logType -eq "Firewall") {

            $logs = Get-Content -Path $Path | ForEach-Object {

                $line = $_
                $data = @{}

                # Extrait les champs du format cle="valeur" ou cle=valeur.
                $keyValuePairs = [regex]::Matches($line, '(\w+)=("[^"]*"|\S+)')

                foreach ($pair in $keyValuePairs) {
                    $key = $pair.Groups[1].Value
                    $value = $pair.Groups[2].Value.Trim('"')
                    $data[$key] = $value
                }

                [PSCustomObject]@{
                    LogType         = "Firewall"
                    Time            = $data["timestamp"]
                    SourceIP        = $data["src_ip"]
                    DestinationIP   = $data["dst_ip"]
                    DestinationPort = $data["dst_port"]
                    User            = $data["user_name"]
                    RuleName        = $data["fw_rule_name"]
                    Action          = $data["log_subtype"]
                    Protocol        = $data["protocol"]
                    Application     = $data["app_name"]
                    RawLine         = $line
                }
            }

            return $logs
        }

        elseif ($logType -eq "PiHole") {

            $logs = Get-Content -Path $Path | ForEach-Object {

                $line = $_

                if ($line -match 'query\[(.*?)\]\s+(\S+)\s+from\s+(\d+\.\d+\.\d+\.\d+)') {
                    [PSCustomObject]@{
                        LogType  = "PiHole"
                        Event    = "Query"
                        Query    = $matches[1]
                        Domain   = $matches[2]
                        ClientIP = $matches[3]
                        Answer   = $null
                        RawLine  = $line
                    }
                }
                elseif ($line -match 'reply\s+(\S+)\s+is\s+(\S+)') {
                    [PSCustomObject]@{
                        LogType  = "PiHole"
                        Event    = "Reply"
                        Query    = $null
                        Domain   = $matches[1]
                        ClientIP = $null
                        Answer   = $matches[2]
                        RawLine  = $line
                    }
                }
                elseif ($line -match '(\d+\.\d+\.\d+\.\d+)\s+is\s+(\S+)') {
                    [PSCustomObject]@{
                        LogType  = "PiHole"
                        Event    = "HostName"
                        Query    = $null
                        Domain   = $matches[2]
                        ClientIP = $matches[1]
                        Answer   = $matches[2]
                        RawLine  = $line
                    }
                }
                else {
                    [PSCustomObject]@{
                        LogType  = "PiHole"
                        Event    = "Other"
                        Query    = $null
                        Domain   = $null
                        ClientIP = $null
                        Answer   = $null
                        RawLine  = $line
                    }
                }
            }

            return $logs
        }

        else {
            throw "Unknown log type. This function only supports the provided Firewall and Pi-hole logs."
        }
    }
    catch {
        Write-Error "Import-FWLog failed: $_"
    }
}
# --------------------------------------------
# FUNCTION : Filtre les logs du pare-feu selon plusieurs criteres.
# ---------------------------------------------------------------------

function Search-FWLog {
   <#
.SYNOPSIS
Recherche les entrées d’un journal de pare-feu qui correspondent aux filtres indiqués.

.DESCRIPTION
Lit le fichier indiqué par -Path avec Import-FWLog et conserve uniquement
les entrées du pare-feu. Les adresses IP source et destination ainsi que
le port de destination doivent correspondre exactement aux valeurs indiquées.
Le nom d’utilisateur et le nom de règle acceptent les correspondances partielles.

Si plusieurs filtres sont fournis, chaque entrée doit satisfaire tous les filtres.
Sans filtre, la fonction retourne toutes les entrées du pare-feu.
Les résultats sont retournés sous forme d’objets utilisables dans le pipeline.

.EXAMPLE
Search-FWLog -Path $Path -SourceIP '10.1.20.33' -DestinationPort 443

Retourne les entrées dont l’adresse IP source est 10.1.20.33 et le port
de destination est 443.
#>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [string]$SourceIP,
        [string]$DestinationIP,
        [int]$DestinationPort,
        [string]$User,
        [string]$RuleName
    )

    try {
        # Importe les logs avec la premiere fonction.
        $logs = Import-FWLog -Path $Path

        # Garde seulement les logs de type Firewall.
        $logs = $logs | Where-Object { $_.LogType -eq "Firewall" }

        if ($SourceIP) {
            $logs = $logs | Where-Object { $_.SourceIP -eq $SourceIP }
        }

        if ($DestinationIP) {
            $logs = $logs | Where-Object { $_.DestinationIP -eq $DestinationIP }
        }

        if ($DestinationPort) {
            $logs = $logs | Where-Object { [int]$_.DestinationPort -eq $DestinationPort }
        }

        if ($User) {
            $logs = $logs | Where-Object { $_.User -like "*$User*" }
        }

        if ($RuleName) {
            $logs = $logs | Where-Object { $_.RuleName -like "*$RuleName*" }
        }

        return $logs
    }
    catch {
        Write-Error "Search-FirewallLog failed: $_"
    }
}



function Get-FWSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [ValidateRange(1, 50)]
        [int]$Top = 5
    )

    try {
        # Importe les logs et garde seulement les entrées Firewall.
        $logs = Import-FWLog -Path $Path |
                Where-Object { $_.LogType -eq "Firewall" }

        if (-not $logs) {
            throw "No firewall entries found in: $Path"
        }

        # Petite fonction interne pour transformer un regroupement en texte lisible.
        # Exemple : "Allowed (120), Denied (30)"
        function Format-Group($Items, $Property, $Limit = 0) {
            $groups = $Items |
                      Where-Object { $_.$Property } |
                      Group-Object -Property $Property |
                      Sort-Object Count -Descending
            if ($Limit -gt 0) { $groups = $groups | Select-Object -First $Limit }
            ($groups | ForEach-Object { "$($_.Name) ($($_.Count))" }) -join ", "
        }

        # Période couverte par le journal.
        $times = $logs | Where-Object { $_.Time } | Sort-Object Time

        # Nombre de connexions permises et bloquées.
        $allowed = ($logs | Where-Object { $_.Action -match "allow" }).Count
        $denied  = ($logs | Where-Object { $_.Action -match "den|drop|block" }).Count

        [PSCustomObject]@{
            File                 = (Resolve-Path $Path).Path
            TotalEvents          = $logs.Count
            FirstEvent           = $times[0].Time
            LastEvent            = $times[-1].Time
            UniqueSourceIPs      = ($logs.SourceIP      | Where-Object { $_ } | Sort-Object -Unique).Count
            UniqueDestinationIPs = ($logs.DestinationIP | Where-Object { $_ } | Sort-Object -Unique).Count
            UniqueUsers          = ($logs.User          | Where-Object { $_ } | Sort-Object -Unique).Count
            Allowed              = $allowed
            Denied               = $denied
            ByAction             = Format-Group $logs "Action"
            ByProtocol           = Format-Group $logs "Protocol"
            TopRules             = Format-Group $logs "RuleName" $Top
        }
    }
    catch {
        Write-Error "Get-FWSummary failed: $_"
    }
}
# --------------------------------------------
# FUNCTION : Affiche les adresses IP sources les plus actives.
# ---------------------------------------------------------------------

function Get-FWTopSourceIP {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [int]$Top = 10
    )

    try {
        # Importe les logs avec la premiere fonction.
        $logs = Import-FWLog -Path $Path

        # Garde seulement les logs Firewall qui ont une IP source.
        $logs = $logs | Where-Object { $_.LogType -eq "Firewall" -and $_.SourceIP }

        # Regroupe par IP source, trie du plus grand au plus petit et garde les premiers.
        $topIPs = $logs |
            Group-Object -Property SourceIP |
            Sort-Object -Property Count -Descending |
            Select-Object -First $Top |
            ForEach-Object {
                [PSCustomObject]@{
                    SourceIP = $_.Name
                    Count    = $_.Count
                }
            }

        return $topIPs
    }
    catch {
        Write-Error "Get-FWTopSourceIP failed: $_"
    }
}
function Resolve-FWFQDN {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$IPAddress
    )

    process {
        $address = $null
        $fqdn = $null

        if (-not [System.Net.IPAddress]::TryParse($IPAddress, [ref]$address)) {
            $status = 'Invalid IP address'
        }
        else {
            try {
                $fqdn = [System.Net.Dns]::GetHostEntry($address).HostName
                $status = 'Resolved'
            }
            catch {
                $status = 'Reverse lookup failed'
            }
        }

        [PSCustomObject]@{
            IPAddress = $IPAddress
            FQDN      = $fqdn
            Status    = $status
        }
    }
}

function Export-FWReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$Path,

        [Parameter(Mandatory)]
        [string]$OutputPath
    )

    $logs = @(
        foreach ($file in $Path) {
            Import-FWLog -Path $file -ErrorAction Stop
        }
    )

    if ($logs.Count -eq 0) {
        Write-Warning 'No log entries to export.'
        return
    }

    $columns = @('LogType')
    if ($logs.LogType -contains 'Firewall') {
        $columns += 'Time', 'SourceIP', 'DestinationIP', 'DestinationPort',
                    'User', 'RuleName', 'Action', 'Protocol', 'Application'
    }
    if ($logs.LogType -contains 'PiHole') {
        $columns += 'Event', 'Query', 'Domain', 'ClientIP', 'Answer'
    }
    $columns += 'RawLine'

    # Cree le dossier de sortie s'il n'existe pas.
    $outputDir = Split-Path -Path $OutputPath -Parent
    if ($outputDir -and -not (Test-Path -LiteralPath $outputDir)) {
        New-Item -ItemType Directory -Path $outputDir -Force -ErrorAction Stop | Out-Null
    }

        # -Force remplace un rapport existant.
    $logs |
        Select-Object -Property $columns |
        Export-Csv -LiteralPath $OutputPath -NoTypeInformation -Encoding UTF8 -Force -ErrorAction Stop

    Get-Item -LiteralPath $OutputPath
}
