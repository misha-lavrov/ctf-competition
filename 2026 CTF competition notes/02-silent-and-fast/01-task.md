# Задача 2: Silent and Fast

> **Статус відновлення:** усі 13 підзадач відомі дослівно (зі скріншотів
> платформи, не з AI-переказу). Оригінальний вступний текст умови (сценарій)
> поки не знайдено — TODO нижче. Жодна підзадача поки не має підтвердженої ✅
> відповіді, лише невдалі спроби — див. позначки нижче.

## Тип задачі

Схоже на **DFIR / Log & Timeline Forensics**: потрібно відновити хронологію
дій зловмисника на Linux-хості — яким сервісом він зайшов, з якої IP, коли,
скільки було невдалих/вдалих спроб входу, яку першу команду виконав, яку
persistence спробував налаштувати, і зрештою — розшифрувати файл, який
зловмисник зашифрував і вивів (принаймні частину) як base64.

Судячи зі скріншота термінала (підзадача, над якою працював учасник),
артефактом для аналізу був файл **`dump.scap`** — розширення `.scap`
найімовірніше означає **Sysdig capture** (запис системних викликів:
процеси, мережеві з'єднання, файлові операції). Це TODO-гіпотеза — не
підтверджено дослівним текстом умови, лише виведена з того, що звичайний
`strings`/`cat`/`cd` на цей файл не спрацював (див. `02-solution.md`).

## Оригінальна умова

TODO — вступний сценарій (як в інших задачах: "An employee workstation...")
не знайдено в жодному зі зібраних джерел. Нижче — лише текст самих підзадач,
скопійований дослівно зі скріншотів інтерфейсу платформи (це вже оригінал,
не reconstructed).

## Підзадачі

Усі підзадачі — по **50 балів**, 5 спроб на кожну (спільні на команду).

### 1. Service/protocol

**Original:** Which service/protocol did the attacker use to access the host?
**Flag format:** `UR{servicename}`
**Статус:** не спробовано (поле порожнє на скріншоті)

### 2. Attacker's IP address

**Original:** What IP address did the attacker belong to?
**Flag format:** `UR{192.168.0.1}`
**Спроби:** 1/5 — `UR{192.168.178.126}` ❌ (неправильно)

### 3. UTC time of first accepted connection

**Original:** What was the UTC time of the first accepted connection from that IP?
**Flag format:** `UR{HH:MM:SS}`
**Спроби:** 2/5 — `UR{22:31:13}` ❌; ще одна спроба доведена до 4/5 (конкретне значення на скріншоті не видно)

### 4. Failed login attempts

**Original:** How many failed login attempts were there?
**Flag format:** `UR{7}` (це приклад формату з платформи, не відповідь)
**Статус:** не спробовано

### 5. Successful logins

**Original:** How many successful logins were there?
**Flag format:** `UR{4}` (приклад формату, не відповідь)
**Статус:** не спробовано

### 6. First command after login

**Original:** What was the first command executed by the attacker after logging in?
**Flag format:** `UR{command -arg}`
**Статус:** не спробовано

### 7. Kernel version

**Original:** What kernel version is installed?
**Flag format:** `UR{1.2.3-45-server}` (приклад формату)
**Статус:** не спробовано

### 8. Persistence callback host/IP

**Original:** The attacker attempted to establish persistence - where was the callback intended to connect (host/IP)?
**Flag format:** `UR{192.168.0.1}`
**Спроби:** 1/5 — `UR{192.168.178.108}` ❌ (неправильно)

### 9. Which file was encrypted

**Original:** Which file was encrypted?
**Flag format:** `UR{file.mp3}` — **важлива підказка:** формат-приклад саме `.mp3`, а не generic `filename`, як в інших підзадачах. Схоже, справжня відповідь — реальна назва mp3-файлу (аудіо), а не довільного файлу.
**Статус:** не спробовано (поле порожнє на скріншоті)

### 10. Content of that file

**Original:** What was the content of that file?
**Flag format:** `UR{flag}` — тобто вміст самого файлу, після розшифровки, **і є** черговий прапор у форматі `UR{...}` (як у задачі 6 Flag Eater — прихований hex/зашифрований текст).
**Статус:** не спробовано

### 11. Encryption passphrase

**Original:** Specify the passphrase with which the file was encrypted.
**Flag format:** `UR{passphrase}`
**Спроби:** 4/5 — `UR{random/uuid}` ❌ (неправильно)

### 12. Base64-printed flag, first part

**Original:** The attacker printed the encrypted flag as base64. Provide the first part of the output up to //.
**Flag format:** `UR{base64text}`
**Спроби:** 1/5 — `UR{bod}` ❌ (неправильно, схоже на надто коротку/неповну спробу)

### 13. UTC time connection was closed

**Original:** Provide the UTC time when the connection with the attacker was closed.
**Flag format:** `UR{HH:MM:SS}`
**Спроби:** дві невдалі — `UR{19:31:44}` ❌ (2/5) і `UR{19:31:29}` ❌ (4/5). Обидва в тій самій хвилині — ймовірно, помилка в секундах або неправильно визначений момент "закриття" з'єднання.

## Джерела

Відновлено з реальних скріншотів інтерфейсу платформи (папка
`CTF_завдання\CTF` у Telegram Desktop-завантаженнях команди), а не з
переказу AI-чату — тому текст підзадач і flag-формати вище можна вважати
дослівним оригіналом, а не reconstruction.
