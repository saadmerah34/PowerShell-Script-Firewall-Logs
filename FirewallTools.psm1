

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

        if ($firstLine -match "cr431-firewall") {
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
        Write-Error "Import-FirewallLog failed: $_"
    }
}
# Cette fonction filtre les logs du pare-feu selon plusieurs criteres.
function Search-FWLog {
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


function Get-FWSummary {}
function Get-FWTopSourceIP {}
function Resolve-FWFQDN {}
function Export-FWReport {}
