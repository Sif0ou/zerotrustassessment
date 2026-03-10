# Zero Trust Security Assessment - Audit Kit

## Contenu

| Fichier | Description |
|---------|-------------|
| `ZeroTrust-SecurityControls.csv` | **Fichier Excel/CSV** avec les 237 contrôles de sécurité |
| `Generate-AuditScripts.ps1` | Générateur : crée un script d'audit `.ps1` par contrôle |
| `Run-AllAudits.ps1` | Exécute tous les scripts et génère un rapport consolidé |

## Démarrage rapide

### 1. Prérequis

```powershell
# Microsoft Graph SDK (obligatoire pour Identity / Devices)
Install-Module Microsoft.Graph -Scope CurrentUser

# Module Excel (optionnel, pour export .xlsx)
Install-Module ImportExcel -Scope CurrentUser

# Modules additionnels selon les piliers audités
Install-Module Az.Network -Scope CurrentUser           # Network (Azure Firewall, WAF, DDoS)
Install-Module ExchangeOnlineManagement -Scope CurrentUser  # Data (DLP, Labels, Retention)
Install-Module AIPService -Scope CurrentUser            # Data (Rights Management)
```

### 2. Générer les scripts d'audit

```powershell
cd audit
.\Generate-AuditScripts.ps1
```

Résultat : **237 scripts** créés dans `scripts/<Pillar>/Audit-<ID>.ps1`

```
scripts/
├── Identity/    → 132 scripts
├── Devices/     → 35 scripts
├── Network/     → 57 scripts
└── Data/        → 40 scripts
```

### 3. Se connecter

```powershell
# Microsoft Graph (Identity + Devices)
Connect-MgGraph -Scopes 'Directory.Read.All','Policy.Read.All',
    'DeviceManagementConfiguration.Read.All','RoleManagement.Read.All',
    'AuditLog.Read.All','IdentityRiskyUser.Read.All'

# Azure (Network)
Connect-AzAccount

# Security & Compliance (Data)
Connect-IPPSSession
```

### 4. Exécuter les audits

```powershell
# Tous les contrôles → rapport CSV
.\Run-AllAudits.ps1

# Tous les contrôles → rapport Excel coloré
.\Run-AllAudits.ps1 -ExportExcel

# Uniquement les contrôles Identity à haut risque
.\Run-AllAudits.ps1 -Pillar Identity -RiskLevel High

# Un contrôle spécifique
.\scripts\Identity\Audit-21771.ps1
.\scripts\Identity\Audit-21771.ps1 -OutputFormat JSON
```

### 5. Lire le rapport

Le rapport contient pour chaque contrôle :

| Colonne | Description |
|---------|-------------|
| TestId | Identifiant unique du contrôle |
| Title | Description du contrôle |
| Pillar | Identity / Devices / Network / Data |
| Category | Sous-catégorie |
| RiskLevel | High / Medium / Low |
| **Status** | **Pass** ✅ / **Fail** ❌ / **Review** ⚠️ / **ManualCheck** 🔍 / **Error** |
| Details | Résultat détaillé |

## Statuts d'audit

| Statut | Signification |
|--------|--------------|
| `Pass` | Le contrôle est conforme |
| `Fail` | Le contrôle n'est pas conforme — action requise |
| `Review` | Données récupérées, vérification manuelle nécessaire |
| `ManualCheck` | Vérification manuelle via le portail admin requise |
| `Error` | Erreur d'exécution (permissions, module manquant...) |
| `NotRun` | Le script n'a pas été exécuté |
