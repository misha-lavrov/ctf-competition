# Задача 4: Ransomware Attack (Memory Forensics)

> Офіційна назва задачі на платформі: **"4. Ransomware Attack"**. Це окрема,
> самостійна задача (не продовження задачі 3 про SSH — просто йшла в тому
> самому змаганні наступною).

## Тип задачі

**Memory Forensics + Reverse Engineering** (комп'ютерна криміналістика памʼяті та зворотна розробка).

Простими словами: у нас є "фотографія" оперативної памʼяті (RAM) компʼютера,
який зламали вірусом-шифрувальником (ransomware). Наше завдання — по цій
фотографії відновити, що робив вірус, знайти його ключ шифрування і
розшифрувати заблокований файл.

Це не про "зламати пароль" (як у мережевих задачах), а про **аналіз того, що
залишилось у памʼяті** після роботи шкідливої програми.

---

## Оригінальна умова (сценарій)

> An employee workstation in the finance department was hit by a rapidly
> spreading ransomware strain. All business-critical documents were encrypted
> and a memory snapshot was captured before the attacker's tooling wiped itself
> from disk. Management has given the incident-response team a strict deadline to
> restore operations and recover the encrypted data. Your mission is to triage
> the memory image, locate the ransomware binary, reverse-engineer its
> encryption routine, and decrypt the hostage file — before payroll processing
> grinds to a halt.

**Переклад суті:** робочу станцію фінвідділу вразив ransomware. Усі важливі
документи зашифровані. Перед тим як вірус стер себе з диска, встигли зробити
знімок памʼяті (memory dump). Треба: проаналізувати цей знімок, знайти
виконуваний файл вірусу, розібрати його алгоритм шифрування і розшифрувати
файл-заручник.

**Що нам дали (в архіві `ransomware_attack.zip`):**

| Файл | Розмір | Що це |
|---|---|---|
| `memory_dump.raw` | 2 ГБ | Знімок усієї оперативної памʼяті зараженого компʼютера |
| `top_secret_recover_at_all_cost.txt.enc` | 144 байти | Зашифрований файл, який треба розшифрувати |

**Статус проходження:** підзадачі 1–10 з 11 вирішені й підтверджені платформою
(скріншоти з зеленими "Спроби X/5" і збереженими відповідями). Підзадача 11
(фінальна розшифровка) лишилась незавершеною — код написаний, але результат не
перевірений.

---

## Підзадачі (11 штук по 100 балів)

Кожна підзадача — це окреме питання, відповідь на яке подається у форматі
`UR{...}`. Питання йдуть від простих (просто прочитати дані з дампу) до складних
(реверс алгоритму й розшифровка).

> ✅ = відповідь підтверджена платформою як правильна (перевірено скріншотами).
> Число спроб узяте з поля "Спроби: X/5" на скріншоті — це не завжди перша
> спроба, іноді доводилось пробувати кілька варіантів формату відповіді.

### 1. Memory dump — ✅ (3/5 спроб)
**When was the memory dump captured?**
Формат: `UR{YYYY-MM-DD HH:MM:SS}`
→ Знайти час, коли зробили знімок памʼяті. Це базова інформація про дамп.
**Відповідь:** `UR{2025-04-17 20:48:41}`

### 2. Hosting website — ✅ (1/5 спроб)
**From which file hosting website was the ransomware downloaded?**
Формат: `UR{website.com}`
→ Зʼясувати, з якого файлообмінника скачали вірус. Шукаємо сліди мережевої
активності / URL у памʼяті.
**Відповідь:** `UR{dropbox.com}`

### 3. Tool name — ✅ (1/5 спроб)
**Which tool was used to create the memory dump? (All lowercase letters)**
Формат: `UR{tool_name}`
→ Яка програма зробила сам знімок памʼяті. Видно зі списку процесів.
**Відповідь:** `UR{winpmem}`

### 4. Filename — ✅ (1/5 спроб)
**What is the filename of the ransomware that encrypted the files?**
Формат: `UR{filename.exe}`
→ Назва виконуваного файлу вірусу.
**Відповідь:** `UR{c7f_3ncrYp7.exe}`

### 5. Virtual address — ✅ (1/5 спроб)
**What is the virtual address offset of the ransomware process?**
Формат: `UR{0xoffset}`
→ Адреса процесу вірусу в памʼяті (технічна деталь зі списку процесів).
**Відповідь:** `UR{0xa787a81b5080}`

### 6. PID of the process — ✅ (1/5 спроб)
**What is the PID of the process that launched the ransomware?**
Формат: `UR{pid}`
→ Ідентифікатор процесу-батька, який запустив вірус (хто його стартував).
**Відповідь:** `UR{5192}` (це powershell.exe)

### 7. Encryption-related DLLs — ✅ (2/5 спроб)
**Which encryption-related DLLs were loaded by the ransomware process?
(In alphabetical order)**
Формат: `UR{dll1,dll2,…}`
→ Які бібліотеки для шифрування підвантажив вірус. Критерій добору — у назві є
слово "crypt". Перша спроба (без `CRYPTBASE.DLL`, з `ADVAPI32.dll`) була
неправильною — платформа рахує лише DLL зі словом "crypt" у назві.
**Відповідь:** `UR{bcrypt.dll,bcryptprimitives.dll,CRYPTBASE.DLL}`

### 8. Decoded value — ✅ (1/5 спроб)
**What is the decoded value of the hex-encoded flag found hardcoded in strings
in the ransomware?**
Формат: `UR{decoded_flag}`
→ У вірусі захований прапор у вигляді hex-рядка. Треба знайти його і
розкодувати з hex у звичайний текст.
**Відповідь:** `UR{T1m3_F0r_50m3_R3v3r53_3ng1n33r1ng}`

### 9. XOR mask value — ✅ (1/5 спроб)
**What XOR mask value was used for encryption in the ransomware?
(Uppercase letters if present)**
Формат: `UR{0xmask}`
→ Знайти байт-маску, якою вірус робить XOR-операцію (простий вид шифрування).
**Відповідь:** `UR{0xaa}`

### 10. First 8 bytes of encryption key — ✅ (1/5 спроб)
**What are the first 8 bytes (in hex format) of the encryption key used in the
ransomware's first-level encryption? (Uppercase letters if present)**
Формат: `UR{0x??,0x??,0x??,0x??,0x??,0x??,0x??,0x??}`
→ Знайти AES-ключ шифрування (32 байти) у памʼяті, взяти перші 8 байт.
**Відповідь:** `UR{0xA7,0xF3,0x4B,0x1D,0x9C,0x82,0x57,0xE1}`

### 11. Final decrypted flag — ⏳ не завершено
**What is the final decrypted flag found in the encrypted file?**
Формат: `UR{flag}`
→ Фінал: використати знайдений ключ, щоб розшифрувати файл-заручник і дістати
останній прапор. У цьому проходженні дійшли до написання скрипта розшифровки,
але фінальний прапор не був підтверджений (немає скріншота з результатом).
Дивись розділ "Що доробити" у файлі з розвʼязанням.

---

## Логіка задачі одним абзацом

Спочатку ми **збираємо базові факти** з дампу памʼяті стандартними інструментами
(підзадачі 1–7): коли, чим і що запускалось. Потім **дістаємо сам файл вірусу з
памʼяті** й розбираємо його (підзадачі 8–9): знаходимо захований прапор і
XOR-маску. Нарешті **знаходимо ключ шифрування** прямо в памʼяті спеціальним
інструментом (підзадача 10) і **розшифровуємо файл** (підзадача 11).

Ключова ідея memory forensics: коли програма працює, усі її секрети (ключі,
паролі, розкодовані рядки) живуть у RAM у відкритому вигляді. Навіть якщо вірус
стер себе з диска — його "відбитки" лишились у знімку памʼяті.
