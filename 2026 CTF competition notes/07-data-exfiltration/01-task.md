# Задача 7: Simple Data Exfiltration Detection

**Категорія:** Network Forensics (аналіз мережевого трафіку)
**Бали:** 4 підзадачі × 100 балів
**Формат прапора:** `UR{...}` (окремий для кожної підзадачі)

## Тип задачі та суть

Дається файл захоплення трафіку (`.pcap`/`.pcapng`) з підозрою на витік даних (data exfiltration). Потрібно:

1. Проаналізувати трафік і знайти аномалію — нестандартний канал передачі даних та підозрілий зовнішній хост.
2. Визначити пристрій-джерело витоку за його MAC-адресою.
3. З'ясувати, яким методом кодувались вкрадені дані.
4. Декодувати дані й визначити, який системний файл був вкрадений.

Це типова вправа на "DNS exfiltration" — техніку, коли атакуючий (або шкідливе ПЗ на зараженій машині) передає вкрадені дані назовні, ховаючи їх у DNS-запитах (замість імені домену підставляється закодований шматок даних). DNS часто не блокується фаєрволами, тому це популярний прихований канал.

## Оригінальна умова (EN)

> In this challenge, you'll be assuming the role of a security analyst tasked with analyzing a .pcap dump suspected of containing malicious exfiltration activity. Your objective is to inspect the network traffic within the capture file to identify any signs of unauthorized data transfer or suspicious communication patterns. Look for anomalies such as utilizing unconventional channels for data transfer and suspicious destinations.
>
> To start the simulation walkthrough, please download the file provided below.

**Наданий файл:** `Simple Data Exfiltration Detection.pcap`

---

## Підзадачі

### Task 1 — 100 балів (спроб використано: 1/5)

**EN:** What is the IPv4 address of the server to which data is being infiltrated?

**Формат прапора:** `UR{IPv4 address}`

**Суть:** знайти зовнішню IP-адресу, на яку йде передача вкрадених даних (тобто адресу "приймача" ексфільтрації).

### Task 2 — 100 балів (спроб використано: 2/5)

**EN:** Based on the MAC address, what is the manufacturer's name (first two words) of the infected device?

**Формат прапора:** `UR{manufacturer's name}`

**Суть:** за MAC-адресою зараженого хоста визначити виробника мережевого обладнання (перші 3 байти MAC — це OUI, ідентифікатор виробника).

### Task 3 — 100 балів (спроб використано: 1/5)

**EN:** What encoding algorithm is used during the data exfiltration?

**Формат прапора:** `UR{encoding algorithm}`

**Суть:** визначити, яким алгоритмом кодування (не шифрування!) були закодовані дані перед вставкою у DNS-запити.

### Task 4 — 100 балів (спроб використано: 1/5)

**EN:** Which default OS file's part was exfiltrated by the attacker (beginning of file path)?

**Формат прапора:** `UR{full/path/to/file}`

**Суть:** декодувати перехоплені дані та визначити, вміст якого стандартного системного файлу було вкрадено.
