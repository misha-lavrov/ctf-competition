# Задача 3: Authorization and SSH Challenge in Linux CTF

## Тип задачі

**Мережеве проникнення + Privilege Escalation** (доступ до сервера і підвищення
привілеїв у Linux).

Простими словами: є сервер, до якого треба підключитись, підібравши/знайшовши
доступи, а потім "піднятись" від звичайного користувача до вищих прав, щоб
дістатися до захищених файлів. Класичний ланцюжок: **зайти → знайти шлях далі →
стати іншим користувачем → врешті root**.

Мета сервера: `10.0.31.207`

---

## Оригінальна умова

> Your well-known friend, owner of the IT hardware supplier company, asked to
> conduct a security audit of his work server. He would also be extra grateful if
> you would recover the backup of his sales report for March: it became
> unaccessible in /backups directory when their previous sysadmin left. He
> provided some of his employees usernames to help you get started: veronica,
> steve, michael and joanna. He hints that Veronica, not too keen on complex
> passwords, could be the first lead.

**Переклад суті:** друг просить провести аудит його робочого сервера і відновити
березневий звіт із продажів, що став недоступним у теці `/backups`. Дав імена
співробітників: veronica, steve, michael, joanna. Натяк: у Veronica простий
пароль — почни з неї.

---

## Підзадачі

Ланцюжок складається з кількох частин (у цьому чаті детально пройдено вхід і
підвищення привілеїв):

### Частина 1: Підбір пароля Veronica (перший вхід)
→ Підібрати простий пароль користувача veronica і зайти по SSH.
**Відповідь (пароль-прапор):** `UR{blink182}`

### Частина 2: Key in the file with the exposed team members credentials (100 балів)
**Key in the file with the exposed team members credentials.**
Формат: `UR{key}`
→ Знайти файл, де "засвітились" паролі команди, і взяти з нього ключ.
Файл: `team_credentials.txt` (закритий на групу `michael`, тож треба спершу стати
michael через його SSH-ключ).

### Частина 3: Flag in the sales report backup for 01.03 (100 балів)
**Flag in the sales report backup for 01.03.**
Формат: `UR{flag from backup}`
→ Відновити березневий бекап звіту з `/backups` (тека закрита, потрібне
підвищення привілеїв до root через крон-задачу) і дістати прапор із файлу
`summary_sales_01_03.csv.bak`.

---

## Логіка задачі одним абзацом

Це "матрьошка" з доступів: заходимо як **veronica** (слабкий пароль) → знаходимо
приватний SSH-ключ **michael** (лежав із неправильними правами доступу) →
у файлі team_credentials.txt лежать паролі **steve** і **joanna** → у **steve** є
доступ до теки зі скриптами, які **root запускає щохвилини через крон** → пишемо
свій скрипт → отримуємо права **root** → читаємо `/backups`.

Головний урок: кожен наступний крок — це знайдена "недбалість" адміністратора
(слабкий пароль, ключ із відкритими правами, паролі в текстовому файлі, крон від
root на теку, куди може писати звичайний користувач).
