# 5. Malicious Document Forensics

Ланцюжок атаки від фішингового листа з "чистим" вкладенням до крадіжки файлу:
remote template injection → VBA macro → PowerShell → data exfiltration.

**Тип:** Phishing & Social Engineering + Malware Analysis + Memory Forensics
**Інструменти:** oletools (`olevba`), volatility3, unzip (OOXML як ZIP)
**Статус:** ⚠️ підзадачі 1–3 вирішено (100/100), підзадачі 4–5 не завершені —
дамп памʼяті виявився обрізаним (~2.1 ГБ замість очікуваних ~10.5 ГБ), плюс
2 підтверджено невірні спроби на підзадачі 4 (див. нижче). Детальний
розбір причини і план дороблення — у `02-solution.md`.

## Файли
- [`01-task.md`](01-task.md) — умова задачі, всі 5 підзадач, підсумкові прапори
- [`02-solution.md`](02-solution.md) — покрокове розвʼязання з поясненням кожної команди
- [`../files/05-malicious-document/memory_analysis/`](../files/05-malicious-document/memory_analysis/) — оригінальні файли задачі (локально, не в git): `emails.zip`, `memdump.raw`

## Ключові навички
- Розбір `.eml` через Python `email` модуль (MIME, quoted-printable)
- OOXML (`.docx`/`.xlsx`) як ZIP-архів, аналіз `_rels/*.rels` на remote template injection (MITRE T1221)
- `olevba` — пошук VBA-макросів у Office-файлах
- Volatility 3: `windows.pslist`, `windows.pstree`, `windows.netscan`, `windows.psscan`
- Перевірка цілісності дампу памʼяті через `readelf` (ELF core dump)

## TODO
- [ ] Перезавантажити повний `memdump.raw` (~10.5 ГБ) і повторити підзадачі 4–5
- [ ] Знайти дочірній `powershell.exe`, запущений `WINWORD.EXE` (PID `7140`), і його командний рядок
- [ ] Розкодувати `-EncodedCommand`, якщо командний рядок закодований у base64/UTF-16LE
- [ ] Підтвердити підзадачу 2 (`TCP connections`) через `windows.netscan`, а не лише за словами команди
- [ ] **Знайти `network_dump.pcap`** — скріншот файлового менеджера показує цей
      файл поруч із `memdump.raw`, хоча раніше вважалось, що PCAP серед наданих
      файлів не було. Якщо він реально існує — це може напряму дати підзадачі
      2 (TCP-з'єднання) і, можливо, 4–5 (ексфільтрація), без потреби чекати
      повний memory dump.
- [ ] Підзадача 4: НЕ пробувати повторно `UR{c:\users\public\vip4ymtqln}` і
      `UR{c:\users\public\vip4ymtqln\dzbiz1hrmj.rar}` — обидва вже підтверджено невірні (див. `01-task.md`)
