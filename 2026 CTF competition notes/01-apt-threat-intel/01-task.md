# Задача 1: APT / Threat Intelligence

> Навчальний конспект за матеріалами змагання 18.09.2026.  
> Мова оригінальних умов і команд — англійська; пояснення — українською.

## 1. Загальна умова задачі

### Original task

> Your organization has become one of the targets of the APT group. You, as a Threat Intelligence analyst should study the TTP of this APT so that the Security team can develop strategies to protect against malicious attacks based on your research. You need to analyze the reports, open sources, some dumps related to APT and any resources that you can find useful in analyzing TTP.
>
> Your organization's forensics team managed to obtain some files related to the work of APT. All files are located on the system in the appropriate folders. It is known that the APT group is connected with the power structures of the russian federation and is focused on the state institutions of our country. Its main purpose is to steal confidential user data.
>
> All necessary files can be found in the user's documents folder.
>
> **Don't forget to use "Google Dorks"** - this technique allows you to find information more precisely and narrow down your search results.

### Environment

RDP credentials used during the competition:

```text
Host: 10.0.27.53
Username: analyst
Password: P@ssw0rd!
```

> Це були credentials до ізольованої CTF-машини. Не переносимо такі дії на сторонні системи без дозволу.

Підключення у Windows:

```text
Win + R
mstsc
```

`mstsc` — стандартний Remote Desktop Client у Windows.

## 2. Суть задачі простими словами

Це була не задача на «злам 10.0.27.53». Віддалена Windows-машина була **forensic / analysis VM**, де організатори вже розклали артефакти атаки.

Треба було працювати як **Threat Intelligence Analyst**:

1. знайти артефакти атаки;
2. визначити APT-групу;
3. знайти її альтернативні назви та атрибуцію;
4. проаналізувати phishing-email;
5. витягнути IoC;
6. проаналізувати VBScript/HTA без запуску;
7. зіставити поведінку malware з MITRE ATT&CK;
8. знайти C2, User-Agent, persistence та інші TTP;
9. перевіряти інформацію через CERT-UA, CrowdStrike та інші відкриті джерела.

Типи навичок:

- **CTI / Threat Intelligence**
- **OSINT**
- **Email forensics**
- **Static malware analysis**
- **MITRE ATT&CK**
- **IoC analysis**

## 3. Головні поняття

### APT — Advanced Persistent Threat

Організована група, яка проводить цілеспрямовані атаки протягом тривалого часу. Часто такі групи пов'язують з державними структурами.

У цій задачі:

```text
CERT-UA: UAC-0010
CrowdStrike: Primitive Bear
Common aliases: Gamaredon / Armageddon
```

### CTI — Cyber Threat Intelligence

Збір та аналіз інформації про кібератаки, атакувальників, їх інфраструктуру й методи.

### TTP — Tactics, Techniques, Procedures

Простими словами — **як працює атакувальник**.

- **Tactic** — мета етапу атаки.
- **Technique** — спосіб досягнення мети.
- **Procedure** — конкретна реалізація.

Приклад:

```text
Tactic: Initial Access
Technique: T1566.002 Spearphishing Link
Procedure: email із посиланням на malicious RAR archive
```

### IoC — Indicator of Compromise

Ознака компрометації:

- domain;
- IP;
- file hash;
- filename;
- URL;
- registry key;
- User-Agent;
- email address.

### C2 — Command and Control

Сервер або інфраструктура, через яку malware отримує команди та передає дані.

### OSINT — Open Source Intelligence

Пошук інформації у відкритих джерелах: CERT-UA, MITRE ATT&CK, CrowdStrike, Google, security blogs тощо.

### Google Dorks

Точні Google-запити:

```text
site:cert.gov.ua "UAC-0010"
site:crowdstrike.com "UAC-0010"
"UAC-0010" "FSB"
"Gamaredon" "Chernykh"
filetype:pdf "UAC-0010"
```

### MITRE ATT&CK

База знань про поведінку атакувальників.

Приклади із задачі:

```text
T1566.002 — Spearphishing Link
T1547.001 — Registry Run Keys / Startup Folder
```

## 4. Pyramid of Pain

Від простішого до складнішого для атакувальника:

```text
Hash Values              — Trivial
IP Addresses             — Easy
Domain Names             — Simple
Network / Host Artifacts — Annoying
Tools                    — Challenging
TTPs                     — Tough
```

У підзадачі №7 підказка `third level (Simple)` означала **Domain Name**.

## 5. Карта підзадач

> Повний оригінальний текст усіх 25 підзадач у чаті не зберігся. Якщо нижче написано **reconstructed**, зміст відновлено з відповіді та Discord-нотаток, а не дослівно.

### 1. Identify APT group

**Original:**

> Analyze the email received from the victim host and attribute it to a specific APT using CERT-UA stats.  
> Hint: Check @StrikeReadyLabs on X.  
> Flag format: `UR{UAC-XXXX}`

**Тип:** CTI + email analysis + OSINT  
**Підтверджена відповідь:**

```text
UR{UAC-0010}
```

### 2. Alternative name of the group

**Original:**

> Specify an alternative name of the group referring to the CrowdStrike vendor.  
> Flag format: `UR{Alternative Name}`

**Тип:** OSINT / vendor naming  
**Підтверджена відповідь:**

```text
UR{Primitive Bear}
```

### 3. Attribution to a Russian structure — reconstructed

Оригінальна умова не збереглася. З Discord:

```text
UR{FSB}
```

Суть: визначити, з якою державною структурою РФ пов'язують UAC-0010.

### 4. Location / unit — reconstructed

З Discord:

```text
UR{Sevastopol}
```

Суть: OSINT по підрозділу / місцю діяльності групи.

### 5–6. Commander information

У Discord були зафіксовані варіанти:

```text
UR{Черних|1978}
UR{Chernykh|1978}
```

Для №6 оригінальна умова збереглась:

> Through the pipe, indicate the name and year of birth of the APT commander.  
> Flag format: `UR{last_name|yyyy}`

**Тип:** OSINT / attribution.

### 7. IoC

**Original:**

> Using the "Pyramid of Pain" model, specify the IoC that points to the resource to download the payload by mail, and belongs to the third level (Simple) of this model.  
> Flag format: `UR{ioc.example.com}`

**Тип:** email forensics + IoC + Pyramid of Pain

З `.eml` було знайдено URL на RAR-архів:

```text
https://dealer-dans-told-words.trycloudflare.com/...1337.rar
```

**Підтверджена відповідь:**

```text
UR{dealer-dans-told-words.trycloudflare.com}
```

### 8. MITRE ATT&CK phishing technique — reconstructed

Discord:

```text
UR{T1566.002}
```

Це:

```text
T1566.002 — Spearphishing Link
```

### 9/10. Script language — номер не підтверджено

Discord:

```text
UR{VBScript}
```

Ознаки у коді:

```html
<script type="text/vbscript">
```

та:

```text
WScript
CreateObject
On Error Resume Next
End Function
```

### 11. User-Agent (Sample_1)

**Original:**

> Analyze the script, specify the user-agent that was used when connecting to the C2 server.  
> Flag format: `UR{user-agent}`

Зі скрипта:

```text
Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.135 Safari/537.36
```

### 12. Full URL (Sample_1)

**Original:**

> The script has a function of generating a random URL to the next payload of the attacker. Enter the full URL.  
> Flag format: `UR{proto://example.com/file}`

Структура URL:

```text
https://executable-configuration-metadata-config.trycloudflare.com/comanda?=<random 1..100>/upload.bat
```

**Статус:** правильний final flag у чаті не був підтверджений.

### 13. Full URL of legitimate resource (Sample_1)

**Original:**

> Specify the full URL of the legitimate resource mentioned in the script and used to hide the malicious activity.

Відповідь:

```text
UR{https://t.me/s/fenok}
```

### 14. Full path to generated key (Sample_1)

**Original:**

> One of the script's functionalities is tracked under sub-technique T1547.001. Specify the full path to the generated key along with the arguments.

Registry path:

```text
HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\FinalCutPro
```

Command:

```text
wscript.exe //e:vbscript /cdt /mp3 /asf //b info.bmp
```

**Підтверджений flag:**

```text
UR{HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\FinalCutPro| wscript.exe //e:vbscript /cdt /mp3 /asf //b info.bmp}
```

### 15. Word template path — reconstructed

Discord:

```text
UR{C:\Users\Dwight\AppData\Roaming\Microsoft\Templates\Normal.dotm}
```

### 16. No data

У наданих матеріалах умова та відповідь не збереглися.

### 17. Screenshot staging folder — reconstructed

З Discord: malware зберігав screenshot у `%TEMP%` перед відправкою.

```text
UR{Temp}
```

### 18. Malware / tool name — reconstructed

Discord:

```text
UR{Pteranodon}
```

### 19. HTTP header name — reconstructed

Discord:

```text
UR{User-Agent}
```

### 20. Full value of "user-agent" header (Sample_2)

**Original:**

> Analyze the following script, specify the full value of the "user-agent" header, which contains sensitive information about the infected host.

Given:

```text
Time: 03.10.2024 UTC
Hostname: komputer_oleg
OS: Windows 11
Volume serial number (hex):
6f692eb94a4dad4d9ce0c6a0e268ae75d56c0195
```

Скрипт формував:

```text
[browser User-Agent]::[hostname]_[volume serial]::/.jessamy/.
```

**Статус:** derived candidate був отриманий зі скрипта, але підтвердження платформи у чаті не збереглось.

### 21. Malware families / tools — reconstructed

Discord:

```text
UR{GammaDrop|GammaLoad|GammaSteel|LakeFlash|Pterodo}
```

### 22. Number of network IoCs

**Original:**

> Using the article at the following link:  
> https://cert.gov.ua/article/5160737  
> Specify the number of network IoCs located on the site and owned by "GLOBAL INTERNET SOLUTIONS LLC".  
> Flag format: `UR{number}`

**Підтверджена відповідь:**

```text
UR{102}
```

### 23. Threat intelligence platform — reconstructed

Discord:

```text
UR{MISP}
```

### 24. Domain name of legitimate tunneling resource

**Original:**

> Recently, attackers started using a legitimate resource and performs the function of traffic tunneling. Specify the domain name of the legitimate resource.  
> Flag format: `UR{example.com}`

Відповідь:

```text
UR{trycloudflare.com}
```

### 25. Hash algorithm — reconstructed

Discord:

```text
UR{MD5}
```

## 6. Корисні зовнішні джерела

CERT-UA UAC-0010:

```text
https://cert.gov.ua/article/5160737
```

CrowdStrike Primitive Bear:

```text
https://www.crowdstrike.com/en-us/adversaries/primitive-bear/
```

MITRE T1566.002:

```text
https://attack.mitre.org/techniques/T1566/002/
```

MITRE T1547.001:

```text
https://attack.mitre.org/techniques/T1547/001/
```

HarfangLab — Gamaredon / PteroLNK:

```text
https://harfanglab.io/insidethelab/gamaredons-pterolnk-analysis/
```

CERT-UA / Держспецзв'язку overview:

```text
https://cip.gov.ua/en/faqs/cyber-threat-overview-and-defense-strategies-in-2025-cert-ua-s-experience
```

## 7. Що варто вивчити після цієї задачі

1. структура `.eml`;
2. Base64;
3. HTML `href`;
4. PowerShell `Get-ChildItem`, `Get-Content`, `Select-String`;
5. основи VBScript;
6. HTTP headers;
7. Windows Registry;
8. MITRE ATT&CK;
9. IoC та Pyramid of Pain;
10. Google Dorks;
11. CERT-UA / vendor naming;
12. MISP;
13. C2 та tunneling services.

Для beginner CTF важливіше не запам'ятовувати назви malware, а навчитися **бачити підказки, розкладати обфускований рядок на частини і правильно шукати інформацію**.
