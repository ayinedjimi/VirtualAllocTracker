# 🚀 VirtualAllocTracker


**Tracker Forensics d'Allocations Mémoire Suspectes**
*Ayi NEDJIMI Consultants - WinToolsSuite Série 3*

---

## Vue d'ensemble

**VirtualAllocTracker** surveille en temps réel les allocations et modifications de protection mémoire dans un processus cible. Il détecte les comportements suspects caractéristiques d'injection de code malveillant.

**Détections** :
- **Allocations RWX** : Pages avec permissions Read-Write-Execute (hautement suspect)
- **Changements protection** : Régions modifiées de RW → RWX (shellcode activation)
- **Timeline forensics** : Horodatage précis de chaque événement
- **Alertes temps réel** : Notification sonore sur détections

- --


## ✨ Fonctionnalités Clés

### 1. Monitoring Polling (VirtualQueryEx)

**Méthode** : Scan périodique (1 seconde) de l'espace d'adressage du processus cible via `VirtualQueryEx`.

**Avantages** :
- Simple à implémenter
- Pas de hooks nécessaires
- Fonctionne sans droits kernel

**Limitations** :
- Peut manquer allocations éphémères (<1 seconde)
- Overhead CPU si processus volumineux

**Alternative ETW** (non implémentée ici) :
- Provider : `Microsoft-Windows-Kernel-Memory`
- Event ID 101 : VirtualAlloc
- Event ID 102 : VirtualProtect
- Avantage : Zero overhead, capture temps réel

- --

### 2. Détection Allocations RWX

**Principe** : Les pages RWX permettent d'écrire shellcode puis l'exécuter sans changer protection. C'est un indicateur fort de malware.

**Cas légitimes rares** :
- JIT compilers (Java, .NET) → Utilisent RW puis RX
- Debuggers
- Sandboxes

**Pattern malveillant typique** :
```
1. VirtualAlloc(NULL, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE)
2. WriteProcessMemory(hProcess, addr, shellcode, size, ...)
3. CreateRemoteThread(hProcess, NULL, 0, addr, NULL, 0, NULL)
```

**Détection** :
```cpp
if (mbi.State == MEM_COMMIT &&
    (mbi.Protect & PAGE_EXECUTE_READWRITE)) {
    → Alerte: "Allocation RWX hautement suspecte!"
}
```

- --

### 3. Détection Changements Protection

**Principe** : Technique furtive où malware alloue RW (pas suspect), écrit shellcode, puis change en RX/RWX.

**Pattern** :
```
1. VirtualAlloc(NULL, 4096, MEM_COMMIT, PAGE_READWRITE)  → RW
2. WriteProcessMemory(..., shellcode, ...)
3. VirtualProtect(addr, 4096, PAGE_EXECUTE_READ, &old)   → RX
4. CreateThread(NULL, 0, addr, NULL, 0, NULL)
```

**Détection** :
```cpp
DWORD oldProtect = g_previousProtections[addr];
DWORD newProtect = mbi.Protect;

if (!(oldProtect & PAGE_EXECUTE) &&  // Pas EXECUTE avant
    (newProtect & PAGE_EXECUTE)) {   // EXECUTE maintenant
    → Alerte: "Changement vers EXECUTE détecté!"
}
```

- --

### 4. Timeline Forensics

**Format timestamp** : `YYYY-MM-DD HH:MM:SS`

**Utilité** :
- Corrélation avec logs réseau (connexion C2)
- Identifier séquence d'attaque :
  ```
  14:32:01 - Allocation RW (préparation)
  14:32:02 - Changement → RX (activation)
  14:32:03 - Connexion réseau vers C2 IP (logs firewall)
  ```

- --


## Architecture Technique

### Structure `AllocationEvent`

```cpp
struct AllocationEvent {
    std::wstring timestamp;       // YYYY-MM-DD HH:MM:SS
    DWORD pid;                    // Process ID
    std::wstring processName;     // Nom exécutable
    PVOID address;                // Adresse base région
    SIZE_T size;                  // Taille région
    DWORD protection;             // PAGE_EXECUTE_READWRITE, etc.
    std::wstring eventType;       // "Allocation" ou "Protection Change"
    std::wstring alert;           // Message alerte
};
```

### Thread de Monitoring

```cpp
void MonitoringThread() {
    while (g_monitoring) {
        // 1. VirtualQueryEx scan complet
        // 2. Comparer avec snapshot précédent (g_previousProtections)
        // 3. Détecter nouvelles allocations + changements
        // 4. Ajouter à ListView + Log
        // 5. Sleep(1000)  // 1 seconde
    }
}
```

- --


## 🚀 Utilisation

### Compilation

```batch
go.bat
```

### Interface

1. **Sélectionner processus** : Liste déroulante
2. **Démarrer Monitoring** : Lance surveillance temps réel
3. **Filtrer RWX uniquement** : Affiche seulement allocations RWX
4. **Arrêter** : Stop monitoring
5. **Exporter CSV** : Génère timeline forensics

### Interprétation Alertes

**Alerte 1 : Allocation RWX**
```
Timestamp: 2025-10-20 14:32:01
Type: Allocation
Protection: RWX
Alerte: Allocation RWX hautement suspecte!
```

**Actions** :
1. Dumper région avec MemoryArtifactExtractor
2. Analyser shellcode avec scdbg
3. Identifier processus parent (chaîne d'injection)

**Alerte 2 : Changement Protection**
```
Timestamp: 2025-10-20 14:32:02
Type: Protection Change
Protection: RX
Alerte: Changement vers EXECUTE détecté!
```

**Actions** :
1. Vérifier si légitime (JIT compiler)
2. Si suspect, suspendre processus
3. Dump mémoire complète pour analyse

- --


## Scénarios Forensics

### Scénario 1 : Détection Process Injection

**Contexte** : EDR alerte sur activité suspecte

**Workflow** :
1. Identifier processus victime (ex: explorer.exe)
2. Lancer VirtualAllocTracker sur ce PID
3. Observer séquence :
   ```
   14:32:00 - Allocation RW 4096 bytes
   14:32:01 - Changement → RWX
   14:32:02 - Nouvelle allocation RWX 200KB
   ```
4. Corrélation : Processus injecteur visible dans logs
5. Dump régions + analyse shellcode

### Scénario 2 : Monitoring Malware Actif

**Contexte** : Sample malware en VM isolée

**Workflow** :
1. Exécuter malware
2. Démarrer VirtualAllocTracker après 5 secondes
3. Observer patterns :
   - Allocations multiples RWX (heap spraying ?)
   - Changements protection fréquents (unpacking ?)
4. Exporter timeline CSV
5. Corrélation avec captures réseau (Wireshark)

- --


## Références

### Techniques

- **Process Injection** : [MITRE ATT&CK T1055](https://attack.mitre.org/techniques/T1055/)
- **VirtualProtect Abuse** : [MITRE ATT&CK T1055.002](https://attack.mitre.org/techniques/T1055/002/)

### APIs

- [VirtualQueryEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualqueryex)
- [VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)

- --


## Support

**Développé par** : Ayi NEDJIMI Consultants
**Série** : WinToolsSuite - Forensics Mémoire & Processus (5/6)

- --

*Dernière mise à jour : 2025-10-20*


- --

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>

- --

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>

- --

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>

- --

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>

---

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>