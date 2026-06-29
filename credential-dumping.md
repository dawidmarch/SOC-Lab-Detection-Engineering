# Case Study: Detekcja Credential Dumpingu (T1003.001)

## Cel projektu
Celem projektu było przeprowadzenie symulowanego ataku typu "credential dumping" (zrzut poświadczeń) na proces `lsass.exe` oraz implementacja mechanizmu detekcji w środowisku Wazuh SIEM z wykorzystaniem telemetrii Sysmon. Projekt demonstruje pełen cykl życia incydentu: od eksploatacji po wykrywanie i analizę w centrum SOC.

## Środowisko laboratoryjne
* **Target:** Windows 10 (z zainstalowanym Sysmonem i Wazuh Agentem).
* **Attacker:** Kali Linux (`impacket-psexec`, `mimikatz`).
* **SIEM:** Wazuh Manager (do korelacji logów i alertowania).

## MITRE ATT&CK Mapowanie

| Taktyka | Technika | ID | Opis |
| :--- | :--- | :--- | :--- |
| Credential Access | OS Credential Dumping | T1003.001 | Uzyskanie dostępu do pamięci LSASS w celu ekstrakcji poświadczeń. |

## Metodologia ataku

### 1. Lateral Movement (PsExec)
Atak rozpoczęto od nawiązania zdalnej sesji z wykorzystaniem `impacket-psexec`. Narzędzie to wykorzystuje protokół SMB do wgrania usługi serwisowej, co pozwoliło na uzyskanie powłoki z uprawnieniami `SYSTEM`.

<img width="749" height="455" alt="kali" src="https://github.com/user-attachments/assets/f7ae3f03-d750-46c2-935c-1f50dbfcfb7a" />

<img width="743" height="781" alt="mimikatz" src="https://github.com/user-attachments/assets/d0d917bc-f306-4081-aed4-5a3f3bb8d8b8" />

### 2. Credential Dumping
Po uzyskaniu uprawnień `SYSTEM`, wykonano polecenie `sekurlsa::logonpasswords` w procesie `mimikatz.exe`. Proces ten otworzył uchwyt (handle) do `lsass.exe` w celu odczytu pamięci zawierającej hashe NTLM oraz bilety Kerberos.

## Analiza logów (Wazuh/Sysmon)
Monitorowanie procesów przez Sysmon (Event ID 10) pozwoliło na rejestrację krytycznego zdarzenia.

<img width="1499" height="841" alt="mimikatzexe" src="https://github.com/user-attachments/assets/aefc0682-df76-4f6d-afb9-d149f078b65c" />

**Kluczowe artefakty w JSON:**

```json
{
  "event_id": 10,
  "win.eventdata.targetImage": "C:\\Windows\\system32\\lsass.exe",
  "win.eventdata.sourceImage": "C:\\Temp\\x64\\mimikatz.exe",
  "win.eventdata.grantedAccess": "0x1010"
}
