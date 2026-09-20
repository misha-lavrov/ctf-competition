# Задача 1: APT / Threat Intelligence — рішення покроково

> Практичний навчальний розбір.  
> Команди наведено для Windows / PowerShell.  
> Пояснення розраховані на студентів з базовими ІТ-знаннями.

## 0. Головне правило безпеки

Якщо в CTF видано підозрілий файл:

```text
.exe .dll .hta .vbs .js .ps1 .lnk .docm
```

**не запускаємо його**, якщо умова прямо цього не вимагає.

Спочатку робимо **static analysis**:

- читаємо текст;
- дивимось metadata;
- шукаємо strings, URL, domains;
- дивимось registry paths, User-Agent, hashes.

---

## 1. Підключення до analysis VM

У Windows:

```text
Win + R
mstsc
```

`mstsc` — Remote Desktop Client.

У CTF використовували видані організатором credentials до `10.0.27.53`.

---

## 2. Початкова інвентаризація файлів

```powershell
Get-ChildItem "$env:USERPROFILE\Documents" -Recurse -File |
Select-Object FullName, Extension, Length
```

`Get-ChildItem` — аналог `ls` / `dir`.

- `-Recurse` — заходить у вкладені папки;
- `-File` — тільки файли;
- `Select-Object` — показує потрібні поля.

Корисно шукати:

```text
.eml .html .hta .zip .rar .ps1 .vbs
```

---

## 3. №1 — Identify APT group

Знайшли email:

```text
C:\Users\user\Documents\mail\протокол_тцк.eml
```

`.eml` — файл збереженого email.

Прочитати без запуску:

```powershell
Get-Content -Raw ".\протокол_тцк.eml"
```

`Get-Content` читає файл як текст. `-Raw` повертає його одним блоком.

У phishing-email дивимось:

```text
From:
To:
Subject:
Date:
Content-Type:
Content-Transfer-Encoding:
href=
filename=
http
https
.rar
.zip
.hta
```

Далі OSINT:

```text
site:cert.gov.ua "UAC-0010"
"UAC-0010" Gamaredon
"UAC-0010" FSB
```

Результат:

```text
UR{UAC-0010}
```

---

## 4. №2 — CrowdStrike alternative name

Коли вже маємо `UAC-0010`, шукаємо назву саме у потрібного vendor:

```text
site:crowdstrike.com "UAC-0010"
```

CrowdStrike:

```text
Primitive Bear
```

Flag:

```text
UR{Primitive Bear}
```

Одна APT може мати різні aliases:

```text
CERT-UA     → UAC-0010
CrowdStrike → Primitive Bear
Common      → Gamaredon / Armageddon
Unit 42     → Trident Ursa
Microsoft   → Aqua Blizzard
```

---

## 5. №3–6 — Attribution / FSB / Sevastopol / commander

Основний інструмент — OSINT.

```text
"UAC-0010" FSB
"Gamaredon" FSB Sevastopol
"Gamaredon" Chernykh
"UAC-0010" Chernykh 1978
```

З командних нотаток:

```text
UR{FSB}
UR{Sevastopol}
UR{Черних|1978}
```

Також зустрічався:

```text
UR{Chernykh|1978}
```

Головний принцип:

```text
APT identifier
→ aliases
→ official reports
→ attribution
→ unit/location
→ people
```

---

## 6. №7 — IoC + Pyramid of Pain

Умова сказала `third level (Simple)`.

Pyramid of Pain:

```text
Hash Values              — Trivial
IP Addresses             — Easy
Domain Names             — Simple
Network / Host Artifacts — Annoying
Tools                    — Challenging
TTPs                     — Tough
```

Отже треба знайти **domain**.

### Аналіз `.eml`

```powershell
Get-Content -Raw ".\протокол_тцк.eml"
```

Email містив:

```text
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: base64
```

Base64 — це encoding, не encryption.

Якщо Base64 скопійовано в `$b64`:

```powershell
$bytes = [Convert]::FromBase64String(($b64 -replace '\s',''))
[Text.Encoding]::UTF8.GetString($bytes)
```

У декодованому HTML було:

```html
href="https://dealer-dans-told-words.trycloudflare.com/...1337.rar"
```

Domain:

```text
dealer-dans-told-words.trycloudflare.com
```

Flag:

```text
UR{dealer-dans-told-words.trycloudflare.com}
```

---

## 7. №8 — MITRE T1566.002

Email містив malicious link, який вів на archive.

MITRE ATT&CK:

```text
T1566 — Phishing
T1566.002 — Spearphishing Link
```

Flag:

```text
UR{T1566.002}
```

Пошук:

```text
site:attack.mitre.org spearphishing link
```

---

## 8. Визначення VBScript

Ознаки:

```html
<script type="text/vbscript">
```

```vbscript
On Error Resume Next
CreateObject(...)
WScript.Shell
End Function
```

Відповідь з Discord:

```text
UR{VBScript}
```

---

## 9. Як читати обфускований VBScript

Malware часто склеює strings:

```vbscript
a = "user-a"
a = a + "gent"
```

Результат:

```text
user-agent
```

Так само відновлюємо domains, registry keys і commands.

---

## 10. №11 — User-Agent (Sample_1)

У коді:

```vbscript
userrequest = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.135 Safari/537.36"
```

User-Agent — HTTP header, яким client представляється server.

Відповідь:

```text
Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.135 Safari/537.36
```

---

## 11. №12 — Generated full URL (Sample_1)

Код:

```vbscript
allfYB = "https://executable-configuration-metadata-config.trycloudflare.com"
aseww = "comanda"
allfYB = allfYB & "/" & aseww
allfYB = allfYB & "?="
microscopeJN7 = int((100 * rnd)+1)
allfYB = allfYB & microscopeJN7 & "/upload.bat"
```

Структура:

```text
https://executable-configuration-metadata-config.trycloudflare.com/comanda?=<random 1..100>/upload.bat
```

Якщо бачимо `Rnd()`, статичний код може не давати конкретного runtime value. Тоді шукаємо logs, network capture, execution artifacts або seed.

Правильний final flag у наших нотатках не зберігся.

---

## 12. №13 — Legitimate URL in Sample_1

У коді:

```vbscript
libudias = "https://t.me/s/fenok"
```

Flag:

```text
UR{https://t.me/s/fenok}
```

APT часто використовують legitimate services, щоб traffic виглядав нормальним.

---

## 13. №14 — T1547.001 / Registry Run Key

MITRE:

```text
T1547.001 — Registry Run Keys / Startup Folder
```

Це **persistence** — спосіб пережити reboot/login.

Відновлений path:

```text
HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\FinalCutPro
```

Command:

```text
wscript.exe //e:vbscript /cdt /mp3 /asf //b info.bmp
```

Flag:

```text
UR{HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\FinalCutPro| wscript.exe //e:vbscript /cdt /mp3 /asf //b info.bmp}
```

`wscript.exe` — стандартний Windows Script Host.

---

## 14. №15 — Normal.dotm

Discord:

```text
UR{C:\Users\Dwight\AppData\Roaming\Microsoft\Templates\Normal.dotm}
```

`Normal.dotm` — глобальний шаблон Microsoft Word. У security варто знати про Office templates, macros і template injection.

---

## 15. №17 — Screenshots / TEMP

З нотаток:

```powershell
$Path = "$env:TEMP"
```

Malware робив screenshot, зберігав `.png` у temp directory, а потім готував до відправки.

Flag:

```text
UR{Temp}
```

`$env:TEMP` зазвичай веде на щось на кшталт:

```text
C:\Users\user\AppData\Local\Temp
```

---

## 16. №18 — Pteranodon

Discord:

```text
UR{Pteranodon}
```

Для пошуку malware family:

```text
"UAC-0010" malware
"Gamaredon" Pteranodon
site:cert.gov.ua Gamaredon Pteranodon
```

---

## 17. №19 — User-Agent header

Discord:

```text
UR{User-Agent}
```

Шукаємо щось типу:

```vbscript
setRequestHeader "user-agent", value
```

---

## 18. №20 — Full User-Agent (Sample_2)

У Sample_2 базовий UA:

```text
Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 YaBrowser/20.4.2.197 Yowser/2.5 Safari/537.36
```

Далі код додавав:

```text
::
%computername%
_
volume serial
::/.jessamy/.
```

Схема:

```text
[browser UA]::[hostname]_[serial]::/.jessamy/.
```

Для заданого host:

```text
komputer_oleg
```

та serial:

```text
6f692eb94a4dad4d9ce0c6a0e268ae75d56c0195
```

було отримано derived candidate:

```text
Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 YaBrowser/20.4.2.197 Yowser/2.5 Safari/537.36::komputer_oleg_6F692EB94A4DAD4D9CE0C6A0E268AE75D56C0195::/.jessamy/.
```

> У чаті не збереглося підтвердження платформи після submit, тому це candidate, а не гарантовано підтверджений flag.

Головна ідея: malware використовує User-Agent ще й для **host fingerprinting**.

---

## 19. №21 — Malware families

Discord:

```text
UR{GammaDrop|GammaLoad|GammaSteel|LakeFlash|Pterodo}
```

Корисні поняття:

- **dropper** — розміщує наступний malware;
- **loader** — завантажує/запускає наступний stage;
- **stealer** — краде інформацію.

---

## 20. №22 — 102 network IoCs

Source:

```text
https://cert.gov.ua/article/5160737
```

Потрібно було порахувати network IoCs, owned by:

```text
GLOBAL INTERNET SOLUTIONS LLC
```

Підтверджена відповідь:

```text
UR{102}
```

Для подібних задач:

1. беремо IoC list;
2. виділяємо IP/domains;
3. перевіряємо ownership через WHOIS/RDAP/ASN;
4. групуємо за organization;
5. рахуємо.

**WHOIS/RDAP** — дані про реєстрацію network resources.  
**ASN** — Autonomous System Number.

---

## 21. №23 — MISP

Discord:

```text
UR{MISP}
```

**MISP — Malware Information Sharing Platform**.

Використовується для:

- IoC;
- threat intelligence;
- events;
- hashes;
- domains;
- IP;
- обміну даними між командами.

---

## 22. №24 — trycloudflare.com

Відповідь:

```text
UR{trycloudflare.com}
```

Cloudflare Quick Tunnel може створити public URL:

```text
something-random.trycloudflare.com
```

Схема abuse:

```text
victim
  ↓
*.trycloudflare.com
  ↓
hidden attacker backend
```

Це legitimate service, який attacker використовує для приховування C2.

---

## 23. №25 — MD5

Discord:

```text
UR{MD5}
```

MD5 — hash algorithm.

Приклад:

```text
98cf1a959f11af59bd5ac2c2d746541f
```

MD5 має 32 hex characters.

Як file IoC він досі зустрічається, але для cryptographic security вважається застарілим.

У Pyramid of Pain hash — найнижчий рівень (`Trivial`), бо навіть маленька зміна файла дає новий hash.

---

## 24. Корисні PowerShell-команди

### Де я зараз?

```powershell
Get-Location
```

або:

```powershell
pwd
```

### Показати файли

```powershell
Get-ChildItem
```

скорочено:

```powershell
ls
```

### Рекурсивно всі файли

```powershell
Get-ChildItem -Recurse -File
```

### Пошук extension

```powershell
Get-ChildItem "$env:USERPROFILE\Documents" -Recurse -Filter *.hta
```

### Читання тексту

```powershell
Get-Content "file.txt"
```

### Читання одним блоком

```powershell
Get-Content -Raw "mail.eml"
```

### Пошук тексту

```powershell
Select-String -Path "file.txt" -Pattern "http"
```

### Пошук кількох ознак

```powershell
Select-String -Path "file.txt" -Pattern "http|https|href|src|download"
```

### Hash файла

```powershell
Get-FileHash "file.exe" -Algorithm SHA256
```

Команда тільки читає файл та рахує hash — вона його не запускає.

---

## 25. `__MACOSX` та `._` files

Під час задачі зустріли:

```text
__MACOSX
._Протокол....hta
```

Це macOS metadata / AppleDouble files.

Ознаки:

```text
Mac OS X
com.apple.quarantine
com.apple.provenance
```

Такий файл не був справжнім HTA payload.

---

## 26. Windows Defender і зниклий HTA

Справжній `.hta` зник з папки. Ймовірна причина — quarantine Windows Defender.

Перевірка:

```powershell
Get-MpThreatDetection | Format-List *
```

GUI:

```text
Windows Security
→ Virus & threat protection
→ Protection history
```

Не треба вимикати захист на власному основному ПК лише заради аналізу sample.

---

## 27. Як читати phishing email

Структура `.eml`:

```text
Headers
MIME boundaries
text/plain
text/html
attachments
```

Якщо бачимо:

```text
Content-Transfer-Encoding: base64
```

треба декодувати блок і вже потім шукати `href`, URL та інші IoC.

---

## 28. Типовий workflow для наступного CTF

```text
1. Read task carefully
2. Inventory files
3. Do NOT execute samples
4. Read email / logs / scripts
5. Extract IoCs
6. Decode Base64 if needed
7. Deobfuscate strings
8. Identify TTP
9. Map to MITRE ATT&CK
10. Search CERT-UA / vendors
11. Verify answer format
12. Submit flag
```

---

## 29. Мінімальний checklist перед submit

- [ ] Питають domain, URL, IP, hash чи technique?
- [ ] Не переплутав domain з full URL?
- [ ] Не переплутав vendor alias?
- [ ] Перевірив регістр символів?
- [ ] Перевірив пробіли?
- [ ] Якщо є pipe — правильно поставив `|`?
- [ ] Якщо MITRE — використав повний `Txxxx.xxx`?
- [ ] Якщо script obfuscated — склеїв усі частини?
- [ ] Якщо Base64 — декодував?
- [ ] Якщо відповідь з OSINT — маю нормальне джерело?

---

## 30. Джерела для повторення

CERT-UA:

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

HarfangLab Gamaredon / PteroLNK:

```text
https://harfanglab.io/insidethelab/gamaredons-pterolnk-analysis/
```

CERT-UA / Держспецзв'язку overview:

```text
https://cip.gov.ua/en/faqs/cyber-threat-overview-and-defense-strategies-in-2025-cert-ua-s-experience
```

---

## 31. Що потренувати окремо

Рекомендований порядок для beginner-групи:

1. **Email / EML**
2. **Base64**
3. **URL / domain / IP**
4. **PowerShell basics**
5. **HTTP headers**
6. **VBScript basics**
7. **Windows Registry**
8. **MITRE ATT&CK**
9. **Google Dorks**
10. **IoC / Pyramid of Pain**
11. **MISP**
12. **Static malware analysis**

Після цього подібну велику задачу вже можна буде розбити на маленькі незалежні кроки.
