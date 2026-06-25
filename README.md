# 🛡️ Home SOC Lab - Threat Detection & Log Analysis

Projekt stworzyłem w celu praktycznego przetestowania mechanizmów detekcji zagrożeń w odizolowanym środowisku sieciowym. Skupiłem się na analizie telemetrii systemowej, korelacji logów w systemie SIEM oraz inspekcji surowych pakietów sieciowych. Całość opiera się na symulacji realnych technik hakerskich i mapowaniu ich do matrycy MITRE ATT&CK.

---

## 💻 Hardware & Host OS (Platforma sprzętowa)
Całe laboratorium zostało uruchomione lokalnie na moim fizycznym komputerze. Odpowiednie zarządzanie zasobami było kluczowe, aby zapewnić stabilne działanie systemu SIEM oraz maszyn klienckich.

* **System operacyjny hosta:** Windows 11 Pro [Zmień jeśli masz inny, np. Windows 10]
* **Procesor (CPU):** [Wpisz swój procesor, np. Intel Core i5-11400F / AMD Ryzen 5]
* **Pamięć RAM:** [Wpisz swój RAM, np. 16 GB / 32 GB]
* **Dysk:** SSD NVMe

---

## 💾 Oprogramowanie i Wirtualizacja (Software Stack)
* **Hiperwzorzec:** Oracle VirtualBox (wersja 7.x) – posłużył do stworzenia izolowanej sieci typu Host-Only (`10.0.2.0/24`), całkowicie bezpiecznej dla systemu operacyjnego hosta.
* **SIEM / XDR:** Wazuh Manager (Virtual Appliance oparty na Ubuntu) – `10.0.2.3` (Centralny punkt zbierania i analizy logów).
* **Endpoint (Ofiara):** Windows 10 Pro – `10.0.2.4` (Zainstalowany agent Wazuh oraz sensor Microsoft Sysmon z konfiguracją SwiftOnSecurity).
* **System Atakującego:** Kali Linux – `10.0.2.5` (Platforma do generowania ruchu i symulacji ataków).
* **Analiza Sieciowa:** Wireshark – narzędzie do przechwytywania i analizy surowych pakietów (PCAP).

---

## ⚔️ Case Study 1: SMB Reconnaissance & Brute-Force

### 1. Przebieg ataku (Red Team)
Z poziomu maszyny Kali Linux przeprowadziłem szybkie skanowanie portów w poszukiwaniu otwartych usług, a następnie uruchomiłem próbę automatycznego logowania (brute-force) do usługi SMB na maszynie z systemem Windows, celując w lokalne konto Administratora.

* **Skanowanie portów (Nmap):**
    ```bash
    nmap -F 10.0.2.4
    ```
* **Próba uwierzytelnienia SMB (SMBClient):**
    ```bash
    smbclient -L //10.0.2.4 -U administrator%BledneHaslo123!
    ```

### 2. Mapowanie do MITRE ATT&CK
* **Taktyka:** Reconnaissance ([TA0043](https://attack.mitre.org/tactics/TA0043/)) $\rightarrow$ **Technika:** Active Scanning ([T1595](https://attack.mitre.org/techniques/T1595/))
* **Taktyka:** Credential Access ([TA0006](https://attack.mitre.org/tactics/TA0006/)) $\rightarrow$ **Technika:** Brute Force ([T1110](https://attack.mitre.org/techniques/T1110/))

### 3. Detekcja i analiza logów (Blue Team)

#### 🔴 Logi systemowe: Windows Security Event ID 4625
Agent Wazuh pomyślnie przechwycił i przesłał do bazy log dotyczący nieudanego uwierzytelnienia. W procesie analizy kluczowe były następujące zmienne:
* **Logon Type:** `3` (Network Logon) – potwierdza, że próba logowania nastąpiła przez sieć, a nie lokalnie z konsoli.
* **Source IP:** `10.0.2.5` – wskazuje bezpośrednio na maszynę Kali Linux jako źródło ataku.
* **Target Account:** `administrator`

<p align="center">
  <img src="wazuh-event-4625-logon-failure.png" width="75%" alt="Wazuh Event ID 4625">
</p>

*Wnioski z wdrożenia:* Podczas pierwszej próby Windows Defender Firewall całkowicie dropował pakiety sieciowe, przez co system nie generował logów audytowych. Dopiero po odpowiedniej rekonfiguracji profili zapory sieciowej telemetria zaczęła poprawnie spływać do SIEM-a.

#### 🛜 Analiza ruchu sieciowego: Wireshark PCAP
Równolegle z analizą logów systemowych, zweryfikowałem ruch na poziomie pakietów. 

<p align="center">
  <img src="wireshark-pcap-smb-failure.png" width="75%" alt="Wireshark SMB Failure">
</p>

Filtrowanie protokołu `smb` wykazało sekwencję pakietów negocjacji sesji, która zakończyła się jednoznacznym komunikatem ze strony serwera Windows: `STATUS_LOGON_FAILURE`. To bezpośredni, sieciowy dowód korelujący z Event ID 4625 z logów hosta.

---

## ⚔️ Case Study 2: PowerShell Reverse Shell & Execution Detection

### 1. Przebieg ataku (Red Team)
W celu zsymulowania fazy poeksploatacyjnej (Post-Exploitation), na maszynie ofiary uruchomiłem skrypt mapujący surowe gniazdo TCP z powrotem do maszyny atakującego, co pozwala na zdalne wykonywanie komend w systemie operacyjnym (Reverse Shell).

* **Nasłuch na Kali (Netcat):**
    ```bash
    nc -lvnp 4444
    ```
* **Komenda uruchomiona na Windowsie:**
    Wykorzystałem jednolinijkowy skrypt PowerShell tworzący obiekt `System.Net.Sockets.TCPClient` kierujący ruch na adres `10.0.2.5:4444`.

### 2. Mapowanie do MITRE ATT&CK
* **Taktyka:** Execution ([TA0002](https://attack.mitre.org/tactics/TA0002/)) $\rightarrow$ **Technika:** Command and Scripting Interpreter: PowerShell ([T1059.001](https://attack.mitre.org/techniques/T1059/001/))
* **Taktyka:** Command and Control ([TA0011](https://attack.mitre.org/tactics/TA0011/)) $\rightarrow$ **Technika:** Application Layer Protocol ([T1071](https://attack.mitre.org/techniques/T1071/))

### 3. Detekcja i analiza logów (Blue Team)

#### 🔴 Logi systemowe: Sysmon Event ID 1 (Process Creation)
Podczas testów napotkałem mechanizm ochronny Windows Defender (AMSI), który blokował wykonanie skryptu bezpośrednio w konsoli PowerShell. Po tymczasowym wyłączeniu ochrony w czasie rzeczywistym w celu dokończenia symulacji, sensor Sysmon zarejestrował zdarzenie utworzenia procesu.

<p align="center">
  <img src="wazuh-sysmon-event1-powershell-execution.png" width="75%" alt="Sysmon Event ID 1 CommandLine">
</p>

*Analiza mechanizmu Sysmon:* Wklejenie złośliwego kodu bezpośrednio do otwartej wcześniej konsoli PowerShell nie generuje nowego Event ID 1 (ponieważ nie powstaje nowy proces, kod wykonuje się wewnątrz istniejącego PID). Aby poprawnie udokumentować to zdarzenie w SIEM, wywołałem skrypt z poziomu klasycznego Wiersza poleceń (`cmd.exe`), wymuszając flagę `-Command`. Dzięki temu pole `data.win.eventdata.commandLine` w pełni ujawniło cały złośliwy payload sieciowy wraz z zakodowanym adresem IP atakującego.

---

## 🚀 Główne wnioski z projektu
* **Korelacja źródeł:** Projekt udowodnił, jak ważne jest łączenie telemetrii z hosta (Sysmon/Event Viewer) z dowodami z warstwy sieciowej (Wireshark). Dopiero zestawienie tych danych daje pełny obraz incydentu.
* **Tuning sensorów:** Domyślna konfiguracja systemów Windows pomija wiele kluczowych zdarzeń (np. szczegóły CommandLine czy monitorowanie połączeń sieciowych przez PowerShell). Wdrożenie Sysmona z odpowiednimi filtrami drastycznie zwiększa widoczność (visibility) analityka SOC.
