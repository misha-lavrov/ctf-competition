# Задача 5: Malicious Document Forensics

**Категорії:** Phishing & Social Engineering, Malware & Exploitation, Data Leakage, Forensic
**Мова умови:** ENG · **Формат:** Group

## Умова (оригінал, ENG)

> A malicious document slipped past filters — and now the real work begins. Trace the infection from email to memory, uncover what was executed, and follow the data as it's quietly exfiltrated from the system. Dig into macros, dumps, and PCAPs to piece together how one file led to full compromise.
>
> Employee of the company noticed a suspicious behavior and immediately contacted a security team. Analyze a compromised system by investigating network traffic, email attachments, and memory dumps to uncover a malicious document with embedded VBA macros, track its execution, and identify stolen data exfiltrated via a PowerShell script.

## Суть задачі (пояснення)

Це **форензік-задача** (Digital Forensics), у якій потрібно відтворити повний ланцюжок атаки — від фішингового листа до крадіжки даних:

1. Зловмисник надсилає лист з "чистим" на вигляд Word/Excel-вкладенням (без явних макросів, щоб пройти антивірус/фільтри пошти).
2. Вкладення при відкритті підвантажує зовнішній шаблон з макросами (техніка **remote template injection**).
3. Макрос запускає PowerShell, який щось виконує на машині жертви.
4. PowerShell-скрипт краде якийсь файл і відправляє його зловмиснику через мережу.
5. Все це потрібно відновити, аналізуючи:
   - **email-вкладення** (`.eml` файли — фішингові листи);
   - **дамп оперативної пам'яті** (`memdump.raw` — знімок стану Windows-машини в момент компрометації);
   - (за умовою мала бути ще й) **мережевий трафік (PCAP)** — у наданих нам файлах його не було, лише emails + memdump.

## Надані файли

Шлях у завданні: `F:\memory_analysis`

- `emails.zip` — 10 фішингових листів (`.eml`)
- `emails/` — та сама розпакована папка (порожня до розпакування архіву)
- `memdump.raw` — дамп оперативної пам'яті Windows-машини (ELF core dump формат, типовий для QEMU `dump-guest-memory`)
- ⚠️ **`network_dump.pcap`** — за скріншотом файлового менеджера цей файл, схоже, таки існував (див. TODO нижче), хоча раніше вважалось, що PCAP серед наданих файлів не було. TODO: підтвердити й отримати — це прямо стосується непідтвердженої підзадачі 2 і незавершених 4–5.

Зі скріншота файлового менеджера (Dolphin, `Downloads/memory_analysis/emails`) відомі всі 10 назв листів — типові теми ділового фішингу (BEC-style, кожен ніби від іншого "партнера"/сервісу):

```text
Boost Your Sales with Expert Marketing...ies.eml
Build a High-Performing Team with Tale...orge.eml
Enhancing Employee Well-Being wit...ions.eml
Expanding Your Market Reach with GlobalTr...Hub.eml
Revolutionize Your Operations with AI-Driven So...ions.eml
Strategic Partnership Opportunit...rgy.eml
Streamline Your Operations with Custom S...ons.eml
Sustainable Packaging Solutions...ness.eml
Transform Your IT Infrastructure with CloudNexa.eml
Unlock Growth with Tailored Financing Solutions.eml
```

> Назви обрізані на скріншоті (вузька колонка файлового менеджера) — TODO:
> звірити повні назви, коли `emails.zip` буде в `files/05-malicious-document/`.
> Лист із шкідливим `.docx`-вкладенням (`Financely Business Proposal.docx`,
> див. `02-solution.md`) серед цих 10 імен файлів напряму не видно — імовірно,
> це вкладення одного з листів вище, а не назва самого `.eml`.

## Підзадачі

### 1. Find the link — 100 балів
> Find the link to malicious macros enabled template.
> Flag format: `UR{link}`

**Суть:** знайти URL, з якого підвантажується шкідливий macro-enabled template (`.dotm`) — це і є той самий remote template injection.

### 2. TCP connections — 100 балів
> How many TCP connections were established with found amazon S3?
> Flag format: `UR{number}`

**Суть:** порахувати кількість TCP-з'єднань до S3-бакета, знайденого в підзадачі 1.

### 3. Find the process Id — 100 балів
> Find the process Id of the opened .docx file.
> Flag format: `UR{PID}`

**Суть:** знайти PID процесу Word (WINWORD.EXE), який відкрив шкідливий `.docx`, у дампі пам'яті.

### 4. Which file was stollen from the machine? — 100 балів
> Which file was stollen from the machine?
> Flag format: `UR{full\path\to\the\file}`

**Суть:** визначити повний шлях до файлу на диску жертви, який був вкрадений (ексфільтрований) через PowerShell-скрипт.

**Відомі невдалі спроби** (зі скріншотів платформи, обидві ❌):
- Спроба 2/5: `UR{c:\users\public\vip4ymtqln}`
- Спроба 3/5: `UR{c:\users\public\vip4ymtqln\dzbiz1hrmj.rar}`

Обидві в патерні `C:\Users\Public\<щось>\...` — розумна здогадка (Public — типова
тека для стейджингу файлів шкідливим ПЗ, доступна всім користувачам), але
конкретні назви теки/файлу не підтвердились. Якщо продовжуєш цю підзадачу —
не повторюй ці два варіанти, спробуй знайти реальну назву в pslist/cmdline
дампу пам'яті, а не вгадувати.

### 5. Find the content of the stolen file — 100 балів
> Find the content of the stolen file
> Flag format: `UR{content}`

**Суть:** відновити сам вміст вкраденого файлу (не лише його шлях) з дампу пам'яті.

## Підсумкові прапори (з Discord, знайдені командою)

| # | Підзадача | Прапор |
|---|-----------|--------|
| 1 | Find the link | `UR{https://free-games-ua.s3.eu-central-1.amazonaws.com/mal_temp.dotm}` |
| 2 | TCP connections | `UR{4}` |
| 3 | Find the process Id | `UR{7140}` |
| 4 | Stolen file path | *(у цьому чаті не знайдено — дамп пам'яті виявився обрізаним, деталі в solution.md)* |
| 5 | Stolen file content | *(не розглядалось у цьому чаті)* |
