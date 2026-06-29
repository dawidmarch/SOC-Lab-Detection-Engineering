# Case Study: Wykrywanie Lateral Movement (WMIExec)

## 1. Cel projektu
Demonstracja techniki Lateral Movement z wykorzystaniem WMI (Windows Management Instrumentation) oraz jej wykrywanie za pomocą SIEM (Wazuh) i Sysmon.

## 2. Metodologia ataku
Wykorzystałem narzędzie `impacket-wmiexec` do zdalnego wykonania kodu na hoście docelowym `Windows10-Target`.

* **Komenda:** `impacket-wmiexec './Administrator:Haslo123!@10.0.2.4'`
* **Cel:** Uzyskanie zdalnej powłoki (shell) poprzez usługi WMI.

<img width="765" height="423" alt="Kali" src="https://github.com/user-attachments/assets/4843a381-7473-4b9b-bad4-7a0fdecb0b3f" />

## 3. Analiza logów (Threat Hunting)
Po wykonaniu ataku, przeprowadziłem analizę logów w platformie Wazuh. Zidentyfikowałem zdarzenie `Event ID 1` (Process Create), które jest kluczowe dla wykrycia tego ataku.

### Znalezione dowody (Smoking Gun):
Analiza pliku JSON z logu `whoami.exe` (zgodnie z załączonym **image_be7d42.jpg**) wykazała następujące parametry:
- **Proces:** `whoami.exe`
- **Rodzic (ParentImage):** `C:\Windows\System32\cmd.exe`
- **ParentCommandLine:** `cmd.exe /Q /c whoami 1> \\127.0.0.1\ADMIN$\__1782736377.295496 2>&1`

<img width="1505" height="843" alt="Wazuh" src="https://github.com/user-attachments/assets/8fad5906-0cea-4c95-b3ee-516e61db27df" />

## 4. Wnioski techniczne
* **Dlaczego nie było logu "Process Create" dla wmiprvse.exe?** 
  Usługa `wmiprvse.exe` jest usługą systemową działającą w tle. W momencie ataku nie powstaje nowy proces `wmiprvse.exe`, lecz uruchamia on proces potomny (`cmd.exe`). Sysmon poprawnie zalogował proces potomny, co pozwoliło na identyfikację podejrzanej ścieżki w `parentCommandLine`.
* **Wskaźnik ataku:** Obecność udziału `ADMIN$` oraz unikalnej struktury polecenia w `parentCommandLine` jest wysoce niestandardowa i stanowi silny wskaźnik użycia techniki `WMIExec`.

## 5. Rekomendacja (Detection Logic)
Aby wykryć ten atak w przyszłości, zaleca się implementację reguły w Wazuh:
```xml
<rule id="100002" level="12">
  <if_sid>61603</if_sid>
  <field name="data.win.eventdata.parentCommandLine">.*ADMIN\\$.*</field>
  <description>Lateral Movement - WMIExec Detected</description>
</rule>
