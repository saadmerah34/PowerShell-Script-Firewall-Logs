
@{
    # Fichier principal du module
    RootModule = 'Firewalltools.psm1'

    # Version du module
    ModuleVersion = '1.0.0'

    # Identifiant unique du module
    GUID = '8a8b946a-923a-4ce8-812b-cc26b3f54298'

    # Auteur
    Author = 'Saad MERAH , Virginia Moussa Yaya , Loïs Oulassié'

    # Description du module
    Description = 'Module PowerShell pour analyser les journaux Firewall et Pi-hole'

    # Version minimale de PowerShell
    PowerShellVersion = '5.1'

    # Fonctions disponibles pour les utilisateurs
    FunctionsToExport = @(
        'Import-FirewallLog' #Importer les journaux Firewall et Pi-hole
        'Search-FirewallLog' #Filtrer les journaux selon les 5 critères
        'Get-FWSummary'      #Afficher les statistiques des événements
        'Get-FWTopSourceIP'  #Identifier les IP sources les plus fréquentes
        'Resolve-FWFQDN'     #Associer les IP de destination aux FQDN
        'Export-FWReport'    #Exporter un rapport CSV
    )

    # Aucun cmdlet, alias ou variable exporté
    CmdletsToExport = @()
    AliasesToExport = @()
    VariablesToExport = @()
}
