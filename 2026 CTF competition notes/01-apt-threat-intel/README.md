# 1. APT / Threat Intelligence

**Категорія:** CTI / Threat Intelligence · OSINT · Email forensics
**Статус:** ✅ більшість підзадач вирішено (частина — reconstructed з Discord)

Матеріали першої задачі з CTF 18.09.2026.

## Файли

- [`01-task.md`](01-task.md) — загальна умова, терміни, карта підзадач і відомі flags.
- [`02-solution.md`](02-solution.md) — покроковий практичний розбір, PowerShell-команди та пояснення інструментів.
- [`../files/01-apt-threat-intel/`](../files/01-apt-threat-intel/) — оригінальні файли задачі (локально, не в git — див. `../README.md`). Наразі є `Sample_1.hta` (реконструйовано з копії, вставленої в AI-чат — див. примітку нижче). ⚠️ TODO: усе ще бракує `.eml`-листа і `Sample_2`-скрипта (підзадача №20).

## Ключові навички

- Аналіз phishing email (`.eml`)
- Static malware analysis (VBScript/HTA без запуску)
- OSINT + Google Dorks
- MITRE ATT&CK mapping
- IoC extraction, Pyramid of Pain

## Примітка

Не всі оригінальні тексти 25 підзадач збереглись. У таких місцях прямо вказано `reconstructed`.

`files/01-apt-threat-intel/Sample_1.hta` — не байтова копія оригіналу з
платформи, а реконструкція: хтось вставив вміст файлу в чат зі своїм AI, той
рендерив його як Markdown-текст (а не код-блок), через що частина символів
(`<`, `_`, `*`, автопосилання на URL) стала escaped/спотвореною, а зверху
приклеївся текст самої платформи (номер підзадачі, бали, умова). Це прибрано:
знята escaping-розмітка, видалені зайві порожні рядки й текст платформи,
файл перейменовано з `.md` на `.hta` (реальний тип — HTML Application з
вбудованим VBScript, як і описано в `01-task.md`/`02-solution.md`). Сама
логіка скрипта не змінювалась — реконструкцію звірено з підтвердженими
flags підзадач 11–14 (User-Agent, generated URL, legit URL, registry key),
усе збігається.

Головний workflow:

```text
artifact → static analysis → IoC → OSINT → MITRE → verification → flag
```
