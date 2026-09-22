# Тренувальні задачі під кожну задачу змагання

Підбірка практичних задач для повторення навичок, які реально знадобились
18.09.2026 — по 6–7 задач на кожну задачу змагання, різних рівнів складності
(від дуже простих до складніших).

---

## 1. APT / Threat Intelligence

→ [`01-apt-threat-intel/`](01-apt-threat-intel/) — email forensics, OSINT, static malware analysis, MITRE ATT&CK, IoC.

> Пряму "OSINT/APT-атрибуція" на picoCTF навряд чи знайдеш — там більше про
> технічний розбір файлів. Але саме ці навички (email headers, метадані,
> декодування, strings) — це якраз те, що реально знадобилось у підзадачах
> 1, 7, 9–14 нашої задачі 1.

- **Who is it?** (Forensics) — аналіз заголовків email: знайти реальний mail-сервер відправника через `Received from`. Прямий аналог розбору `.eml` з підзадачі №1.
- **Information** (Forensics) — прихований прапор у метаданих файлу (`exiftool`), декодування base64.
- **CanYouSee** (Forensics) — base64-дані, заховані в метаданих зображення.
- **Secret of the Polyglot** (Forensics) — файл маскується під інший тип/розширення. Той самий трюк, що з `.hta`/`._...` у нашій задачі.
- **Glory of the Garden** (Forensics) — `strings` на файлі, щоб знайти прапор у сирих даних.
- **Bases** (General Skills) — конвертація/декодування чисел і рядків (hex, base64 тощо) — пряма навичка деобфускації VBScript.
- **interencdec** (Cryptography) — ланцюжок із кількох кодувань підряд — тренує "розкладати обфускований рядок на частини", як у `01-apt-threat-intel/02-solution.md`.

---

## 2. Silent and Fast

→ [`02-silent-and-fast/`](02-silent-and-fast/) — DFIR: хронологія доступу зловмисника, SSH/сервіс, persistence, зашифрований файл.

> Задача ще не вирішена нами (див. TODO в папці), тому підбір тут — за
> темами підзадач (вхід на хост, розвідка, persistence, ключ шифрування), а
> не за конкретним інструментом `dump.scap`, аналогів якому на picoCTF немає.

- **Permissions** (General Skills) — SSH-вхід на сервер і розвідка через `sudo -l`. Аналог "зайти на хост і зрозуміти, хто є хто".
- **Absolute Nano** (General Skills) — пошук SUID/cron/sudoers-дір. Схожа розвідка на persistence-механізми.
- **Nice netcat** (General Skills) — базова робота з мережевими інструментами командного рядка.
- **Bitlocker-2** (Forensics) — Volatility, пошук ключа шифрування прямо в дампі пам'яті. Прямий аналог підзадач 9–11 (passphrase/encrypted file).
- **First Grep** (General Skills) — пошук патернів у файлах — стане в пригоді для аналізу логів/capture.
- **Wave a Flag** (General Skills) — читати `--help` перед тим, як гадати команди. Актуально після історії з `dump.scap`, якого "не було" в теці.
- **Big Zip** / **First Find** (General Skills) — швидко знайти потрібний файл серед багатьох — той самий урок, що з термінала в нашій задачі.

---

## 3. SSH / Linux Privilege Escalation

→ [`03-ssh-privesc/`](03-ssh-privesc/) — слабкий пароль → SSH-ключ → cron-privesc до root.

> Тут найкращі збіги з усього списку — picoCTF має цілу серію задач саме
> на Linux privilege escalation через SSH.

- **Permissions** (General Skills) — SSH-вхід, `sudo -l`, підвищення прав через GTFOBins (`vi`). Дуже схоже на ланцюжок veronica→michael→steve.
- **Absolute Nano** (General Skills) — misconfigured `sudoers` через `nano`, SUID-бінарники, cron. Прямий аналог кроку "root запускає скрипт із теки, куди можна писати".
- **Sudo Make Me a Sandwich** (General Skills) — підвищення прав через GTFOBins-техніки для `sudo`.
- **PW Crack 1** (Cryptography) — підбір/дешифрування пароля, перший рівень серії.
- **PW Crack 3** (Cryptography) — підбір хешу за словником — той самий принцип, що й `hydra` + `rockyou.txt`.
- **Nice netcat** (General Skills) — мережеві інструменти командного рядка.
- **Wave a Flag** (General Skills) — базові CLI-навички перед серйознішими задачами.

---

## 4. Ransomware Attack (Memory Forensics)

→ [`04-ransomware-attack/`](04-ransomware-attack/) — Volatility, пошук AES-ключа в пам'яті, XOR, розшифровка.

- **Bitlocker-2** (Forensics) — Volatility, ключ шифрування в дампі пам'яті. Найближчий аналог `aeskeyfind` з нашої задачі.
- **Operation Orchid** (Forensics) — дешифрування AES-файлу через `openssl` з відомим паролем.
- **Operation Oni** (Forensics) — аналіз дискового образу (Autopsy) — суміжна навичка "форензік з нуля".
- **vault-door-6** (Reverse Engineering, частина серії vault-door) — XOR-шифр, читання логіки шифрування прямо з коду.
- **packer** (Reverse Engineering) — розпакування "запакованого" бінарника — аналог dropper-механізму.
- **Static ain't always noise** (Forensics/RE) — `strings` на stripped-бінарнику, щоб знайти захований прапор.
- **crackme-py** (Reverse Engineering) — базова логіка реверсу перед складнішими задачами.

---

## 5. Malicious Document Forensics

→ [`05-malicious-document/`](05-malicious-document/) — фішинг-лист → remote template injection → PowerShell → ексфільтрація.

- **Who is it?** (Forensics) — заголовки email, походження листа — той самий крок, що аналіз `.eml`.
- **Ph4nt0m 1ntrud3r** (Forensics) — фрагментований base64 у мережевих пакетах, треба зібрати частини докупи. Схоже на збір даних по шматках.
- **Packets Primer** (Forensics) — вступ до аналізу трафіку у Wireshark/tshark.
- **Secret of the Polyglot** (Forensics) — файл маскується під інший тип. Той самий принцип, що й `.docx`/`.dotm`-трюк (remote template injection).
- **Big Zip** (General Skills) — робота з архівами — пряма навичка для "`.docx` — це насправді ZIP".
- **Trivial File Transfer Protocol** (Forensics) — витяг переданого файлу з pcap-дампу.
- **Verify** (Forensics) — звірка хешів + дешифрування через `openssl`.

---

## 6. Flag Eater

→ [`06-flag-eater/`](06-flag-eater/) — stripped ELF, dropper, XOR-шифр із `time()`-seed, radare2.

> Найсильніший збір задач із усього списку — reverse engineering це
> основна категорія picoCTF, і саме тут найбільше прямих аналогів.

- **vault-door-1** → **vault-door-6** (серія Reverse Engineering) — прогресивна серія: від простого XOR до складніших схем кодування. Проходь по порядку.
- **packer** (Reverse Engineering) — розпакування вбудованого запакованого бінарника — прямий аналог dropper-механізму FlagEater.
- **crackme-py** (Reverse Engineering) — базова логіка реверсу.
- **keygenme-py** (Reverse Engineering) — реверс у стилі keygen: відтворити алгоритм генерації значення.
- **patchme-py** (Reverse Engineering) — патчинг логіки бінарника після аналізу.
- **Static ain't always noise** (Forensics/RE) — `strings` на stripped-бінарнику.
- **Some Assembly Required 1** (Reverse Engineering, серія) — читання x86-асемблера вручну.

---

## 7. Simple Data Exfiltration Detection

→ [`07-data-exfiltration/`](07-data-exfiltration/) — DNS-ексфільтрація, tshark, Base64, OUI/MAC.

> Тут є **прямий 1-в-1 аналог**: "Wireshark twoo twooo two twoo" — це той
> самий DNS-exfiltration-трюк (закодовані дані в subdomain), що і в нашій
> задачі.

- **Wireshark twoo twooo two twoo** (Forensics) — DNS-ексфільтрація: дані закодовані у base64 і заховані в subdomain DNS-запитів. **Прямий аналог нашої задачі 7.**
- **Wireshark doo dooo do doo...** (Forensics) — базовий аналіз pcap, `follow TCP stream`.
- **Packets Primer** (Forensics) — вступ до tshark/Wireshark.
- **Ph4nt0m 1ntrud3r** (Forensics) — фрагментований base64 у мережевих пакетах, треба скласти частини в правильному порядку.
- **Trivial File Transfer Protocol** (Forensics) — витяг переданого файлу з pcap.
- **Bases** (General Skills) — розпізнавання й декодування base64/hex за алфавітом.

---

## Як цим користуватись

1. Заведи акаунт на [learn.cylabacademy.org](https://learn.cylabacademy.org) (безкоштовно) і відкрий **Challenge Library**.
2. Шукай задачі з розділу вище за назвою або фільтруй за категорією/рівнем — назви або самі задачі майже напевно там є.
3. Почни з легших, і тільки після кількох переходь до складніших у тій самій секції — не намагайся одразу робити найважчу.
