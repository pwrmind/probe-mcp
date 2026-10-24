# Практикум по 🧪probe: 11 модулей

Пошаговый гайд для студентов. Каждый модуль — независимый (можно пропустить или переставить), но вместе они образуют единую линию: от «загрузить бинарник» до «составить научный отчёт об исследовании».

---

## Подготовка (5 минут)

```powershell
# 1. Собрать crackme
cd crackme
rustc --crate-type=cdylib --target i686-pc-windows-msvc -O crackme.rs `
  -C link-arg=/BASE:0x10000000 `
  -C link-arg=/DYNAMICBASE:NO `
  -C link-arg=/FIXED:NO `
  -o crackme.dll

# 2. Собрать probe (если не собран)
cd ..
cargo build --target i686-pc-windows-msvc --release

# 3. Запустить
.\target\i686-pc-windows-msvc\release\probe.exe .\crackme\crackme.dll
```

Ожидаемый стартовый экран:

```
[*] Loading PE image: .\crackme\crackme.dll
[+] imports: resolved=N, failed=0
[+] Mapped ... at 0x10000000; ~22 functions; entry = 0x...
[+] Default mocks generated for K functions (EAX=0)
[+] probe ready. type 'help' for commands.
probe>
```

> ⚠️ Если `detect_debugger` (fs:[0x30]) или `crash_illegal_instruction` (ud2) не собрались — замените их тело на `{ 0 }` и `{ loop {} }` соответственно. Это редкие места, где MSVC x86 может ругаться на inline-asm.

---

## Карта модулей

| # | Модуль | Функции crackme | Что отрабатывается в probe |
|---|---|---|---|
| 0 | Первый контакт | — | `find function`, `get function`, `disasm` |
| 1 | Моки и ветвление | `login` / `is_admin` / `check_password` | `set mock`, `runtime mock hits`, mock scope |
| 2 | Работа с памятью | `fill` / `copy_upper` | `alloc`, `poke`, `peek`, `--diff N` |
| 3 | Multi-condition | `validate_premium_user` | короткое замыкание, все моки → 1 |
| 4 | Timing side-channel | `verify_serial_timing` | `__loop_marker`, счётчик как «итерационный оракул» |
| 5 | Out-параметры | `derive_session_key` | `--diff`, `peek`, восстановление буфера |
| 6 | Обфускация | `verify_license` / `decrypt_inplace` | статический vs динамический анализ |
| 7 | Краши | `crash_div` / `crash_ill` / `crash_null` | VEH, коды исключений, `call log` |
| 8 | Buffer overflow | `parse_user_bio` | CWE-121, границы, изоляция |
| 9 | Unsafe parse | `process_custom_packet` | CWE-502 / OOB read, `poke` как фаззер |
| 10 | Anti-debug | `detect_debugger` / `protected_operation` | probe ≠ debugger, симуляция через mock |
| 11 | Научный журнал | все | `call log` как evidence |

**Пререквизиты:** модули 1–2 обязательны для понимания всего остального. Остальные — свободный порядок.

---

## Модуль 0. Первый контакт

**Цель:** научиться загружать бинарник и осматриваться, не зная, что где лежит.

**Что вводить:**

```
probe> find function
```

**Что видеть:** таблица с 22+ функций. Экспортированные — с именами (`login`, `is_admin`, `check_password`, `crash_div`, `verify_serial_timing`, ...). Внутренние CRT — с `-`.

```
probe> find function --sort calls
```

Сортирует по числу CALL. `login` — 2, `validate_premium_user` — 3, `check_obfuscated_password` — 1 (только `decrypt_inplace`), `main`-подобных нет (это DLL).

```
probe> find function --filter "name == login"
```

Точечно находит функцию.

```
probe> get function login
```

Показывает:
```
Function 0x100011E0 (login)
  size: 28
  convention: Cdecl
  mock: Some(Default)          ← уже есть авто-мок (return 0)
  calls (2):
    0x100011E0 -> 0x100011D0  is_admin
    0x100011EB -> 0x10001000  check_password
```

Здесь студент впервые видит **граф вызовов**: `login` вызывает ровно две функции, обе с именами.

```
probe> disasm login 10
```

```
  0x100011E0  E8 EB FF FF FF     call 100011D0h
  0x100011E5  85 C0              test eax,eax
  0x100011E7  74 04              je 100011EDh
  ...
```

**Что обсудить:** `disasm` показывает реальные машинные инструкции. Студент видит, что `login` первой строкой делает `call is_admin`, потом `test eax,eax` (проверка на 0), потом условный переход. Это **не догадка из названия** — это реальный код.

**Продвинутый вопрос:** «Почему у `__loop_marker` (крохотная функция) в таблице `calls: 0`, а у `login` — `calls: 2`?»

---

## Модуль 1. Моки и ветвление

**Цель:** научиться подменять вызов и понимать, **какие** моки реально сработали.

### 1.1 Backdoor через `is_admin`

```
probe> reset mock --all
probe> set mock is_admin --return 1
probe> invoke function login ["user" "wrong"]
```

**Что видеть:**
```
[+] done: EAX = 0x00000001 (1)
    patched call sites: 2
    mock targets:
      -> 0x100011D0  is_admin
      -> 0x10001000  check_password
    runtime mock hits:
      -> 0x100011D0  is_admin         x1
```

**Ключевое наблюдение:** `patched call sites: 2` — оба CALL переписаны на моки. Но `runtime mock hits` показывает, что **сработал только `is_admin`**. `check_password` была пропатчена, но не выполнена — потому что `login` вышел через `return 1` после первой проверки.

Это **x-ray через счётчики**. Обычный отладчик показал бы вам то же, но за пошаговый проход вручную.

### 1.2 Честный пароль через passthrough

```
probe> reset mock --all
probe> set mock check_password --passthrough
probe> invoke function login ["user" "s3cr3t"]
```

**Что видеть:**
```
[+] done: EAX = 0x00000001 (1)
    patched call sites: 1                    ← только is_admin пропатчен
    runtime mock hits:
      -> 0x100011D0  is_admin         x1
```

`check_password` не в `mock targets` (passthrough убрал патч), но реальный `check_password` вернул 1 — потому что пароль `s3cr3t` правильный.

```
probe> invoke function login ["user" "wrong"]
```

`EAX=0`. Реальная проверка не прошла.

### 1.3 Mock scope — важная ловушка

```
probe> reset mock --all
probe> set mock is_admin --return 1
probe> invoke function is_admin []
```

**Что видеть:**
```
[!] note: a custom mock is set for is_admin. `invoke function` runs the real code;
    the mock only affects CALLERS of this function.
[*] invoke is_admin ...
[+] done: EAX = 0x00000000 (0)
```

**Несмотря на мок `--return 1`**, `invoke function is_admin` вернул 0 — потому что `invoke function X` исполняет **реальный** `X`, а мок перехватывает `CALL` на `X` **из других функций**.

Чтобы проверить stub:

```
probe> invoke mock is_admin []
[+] done: EAX = 0x00000001 (1)       ← stub отработал
```

**Преподавательская заметка:** это самая частая путаница. Настаивайте на различии «invoke function (запустить реальный код)» vs «invoke mock (проверить заглушку)».

### Задания

1. Найдите комбинацию моков, при которой `login` вернёт 1, **не заходя в `check_password`**. Объясните через `runtime hits`.
2. Сделайте так, чтобы `login` вернул 1 **только** через реальный `check_password` (мок `is_admin` не должен сработать).
3. **Предскажите без запуска:** что вернёт `login ["u" "s3cr3t"]`, если `is_admin` замокан на `--return 1`? Проверьте.

---

## Модуль 2. Работа с памятью

**Цель:** освоить `alloc` / `poke` / `peek` / `--diff`.

### 2.1 `fill` — простая запись

```
probe> alloc 64
[+] allocated 64 bytes at 0x02010000

probe> invoke function fill [0x02010000 0x41 8] --diff 64
```

**Что видеть:**
```
[+] done: EAX = 0x00000008 (8)
    patched call sites: 0
    --- diff: 1 buffer(s) watched ---
    addr 0x02010000 (64 bytes) [8 bytes changed]
      before: 00 00 00 00 00 00 00 00 00 00 ...
      after:  41 41 41 41 41 41 41 41 00 00 ...
```

`--diff` сравнивает состояние буфера до/после. 8 байт изменились.

### 2.2 `peek` — что реально лежит в памяти

```
probe> peek 0x02010000 16
```

**Что видеть:** hexdump с ASCII-колонкой, видно `AAAA...`.

### 2.3 `copy_upper` — переписать с трансформацией

```
probe> alloc 16
[+] allocated 16 bytes at 0x02020000

probe> poke 0x02020000 "hello"
[+] wrote 5 byte(s) to 0x02020000
    0x02020000: 68 65 6C 6C 6F

probe> alloc 16
[+] allocated 16 bytes at 0x02030000

probe> invoke function copy_upper [0x02020000 0x02030000 5] --diff 16
```

**Что видеть:**
```
[+] done: EAX = 0x00000005 (5)
    --- diff: 2 buffer(s) watched ---
    addr 0x02020000 (16 bytes) [unchanged]     ← src не менялся
    addr 0x02030000 (16 bytes) [5 bytes changed]
      before: 00 00 00 00 00 ...
      after:  48 45 4C 4C 4F ...
```

`48 45 4C 4C 4F` = `HELLO`. Студент видит **два** буфера: src (не изменён) и dst (изменён). Это закрепляет понимание in/out параметров.

### 2.4 Невалидный указатель → VEH

```
probe> invoke function copy_upper ["hello" 0x00A40000 5]
```

**Что видеть:**
```
[!] warning: arg #1 (0x00A40000) is not readable; any dereference will fault
[*] invoke copy_upper ...
[!] sandbox crashed (code 0xC0000005)
    fault instruction: 0x10001089
    fault memory access: 0x00A40000
    EAX marker = 0xDEADFA11
probe>
```

**REPL жив.** Это первый контакт с VEH. Обсудите:
- почему `warning` появился **до** вызова (probe проверяет `ReadProcessMemory`);
- почему падение в `copy_upper` не убило probe;
- что значит `fault_data=0x00A40000`.

### Задания

1. Через `--diff 4` покажите, что `fill` записывает ровно N байт, а не больше.
2. Сделайте `copy_upper` с `len=0`. Что вернёт? Изменится ли буфер?
3. **Предскажите:** `invoke function fill [0x02020000 0x42 100]` при том, что `alloc` был на 64 байта. Будет крэш? Почему?

---

## Модуль 3. Multi-condition: короткое замыкание

**Цель:** понять, что `&&` в машинном коде — это **последовательные** CALL с early-return, а не параллельная проверка.

### 3.1 Базовый вызов

```
probe> reset mock --all
probe> invoke function validate_premium_user []
[+] done: EAX = 0x00000000 (0)
    patched call sites: 3
    runtime mock hits:
      -> 0x...  check_hardware_id       x1
```

**Удивление:** `patched call sites: 3`, но **сработал только первый**. Второй (`check_network_token`) и третий (`check_subscription_status`) CALL **не выполнились** — потому что `check_hardware_id` вернул 0 и `&&` коротко замкнулся.

### 3.2 All mocks → 1

```
probe> set mock check_hardware_id --return 1
probe> set mock check_network_token --return 1
probe> set mock check_subscription_status --return 1
probe> invoke function validate_premium_user []
```

**Что видеть:**
```
[+] done: EAX = 0x00000001 (1)
    runtime mock hits:
      -> 0x...  check_hardware_id       x1
      -> 0x...  check_network_token     x1
      -> 0x...  check_subscription_status x1
```

Все три сработали. `EAX=1`.

### 3.3 Ромбовидное исследование

```
probe> reset mock --all
probe> set mock check_hardware_id --return 1
probe> set mock check_network_token --return 0     ← только второй 0
probe> invoke function validate_premium_user []
```

**Что видеть:**
```
[+] done: EAX = 0x00000000 (0)
    runtime mock hits:
      -> 0x...  check_hardware_id       x1
      -> 0x...  check_network_token     x1
```

Третий CALL **не выполнился** — `check_network_token` вернул 0 и дальше не пошли. Студент через `hits` видит **точку короткого замыкания**.

### Задания

1. Найдите минимальный набор моков, при котором функция вернёт 1.
2. Сделайте так, чтобы сработали ровно **две** проверки, но результат был 0. Объясните через hits.
3. **Предскажите:** сколько будет `runtime hits` (суммарно), если `check_hardware_id` замокан на 1, а `check_network_token` — passthrough? Проверьте.

---

## Модуль 4. Timing side-channel через счётчик

**Цель:** восстановить пароль **без дизассемблера**, только наблюдая `runtime mock hits`.

### 4.1 Идея

`verify_serial_timing` проходит по 7 байтам пароля. На **каждой** итерации вызывает `__loop_marker()`. Если символ не совпал — `return 0`, и цикл обрывается.

Так как `__loop_marker` замокан (default), на каждой итерации `counter` увеличивается. **Число hits = число итераций до провала.** Один верный символ = +1 hit.

### 4.2 Эксперимент

```
probe> reset mock --all
probe> invoke function verify_serial_timing ["AAAAAAA"]
[+] done: EAX = 0x00000000 (0)
    runtime mock hits:
      -> 0x...  __loop_marker  x1
```

`x1` → первый символ `A` не равен `P` (первый символ цели). Цикл прошёл 1 итерацию.

```
probe> invoke function verify_serial_timing ["PAAAAAA"]
[+] done: EAX = 0x00000000 (0)
    runtime mock hits:
      -> 0x...  __loop_marker  x2
```

`x2` → `P` совпал, `A` — нет. **Первый символ найден.**

```
probe> invoke function verify_serial_timing ["PR0BE42"]
[+] done: EAX = 0x00000001 (1)
    runtime mock hits:
      -> 0x...  __loop_marker  x7
```

`x7` = 7 итераций, все верны, `EAX=1`. Пароль восстановлен.

### 4.3 Это и есть timing атака?

**Формально — нет.** Классическая timing атака измеряет **наносекунды**. Мы измеряем **счётчик итераций**. Это называется «side-channel по количеству вызовов» или «counting oracle».

**Почему это лучше timing-атаки:**
- Не нужно наносекундное разрешение (которого в probe нет).
- Не влияет шум ОС и планировщика.
- Работает даже когда функция делается **быстрее** на совпавших символах (что сломало бы timing-атаку).

Но принцип тот же: **наблюдаемая утечка через побочный канал**. Студент должен понять, что «timing side-channel» — это подмножество «observable discrepancy».

### 4.4 Контрольный пример

```
probe> set mock __loop_marker --passthrough
probe> invoke function verify_serial_timing ["PAAAAAA"]
[+] done: EAX = 0x00000000 (0)
    patched call sites: 0                    ← мока нет
```

С passthrough мок не стоит, счётчики не работают, атака не воспроизводится. **Это доказывает, что атака возможна именно благодаря моку-счётчику.**

### Задания

1. Восстановите пароль побайтово. На каждом шаге записывайте: `input` → `hits` → вывод.
2. **Задача-вызов:** если бы `__loop_marker` был через `#[inline]` (inlined), работал бы счётчик? Почему?
3. Придумайте функцию-маркер, которая отличает «совпал 5-й символ» от «совпал 5-й + 6-й не совпал» — не по количеству, а по **разным** счётчикам.

---

## Модуль 5. Out-параметры

**Цель:** научиться извлекать данные, которые функция пишет в переданный буфер.

### 5.1 Один seed

```
probe> reset mock --all
probe> alloc 16
[+] allocated 16 bytes at 0x02040000

probe> invoke function derive_session_key [42 0x02040000] --diff 16
[+] done: EAX = 0x00000001 (1)
    --- diff: 1 buffer(s) watched ---
    addr 0x02040000 (16 bytes) [16 bytes changed]
      before: 00 00 00 00 ...
      after:  E8 E9 EA EB EC ED EE EF F0 F1 F2 F3 F4 F5 F6 F7

probe> peek 0x02040000 16
```

Ключ сгенерирован и записан в буфер. Студент видит: **функция ничего не возвращает в EAX кроме успеха**, но пишет 16 байт в out-параметр.

### 5.2 Два seed'а → сравнение

```
probe> alloc 16
[+] allocated 16 bytes at 0x02050000

probe> invoke function derive_session_key [0 0x02050000] --diff 16
probe> peek 0x02050000 16
```

Сравнивая два seed'а (`0` и `42`), студент по разнице байт восстанавливает формулу: `byte[i] = (seed + i) ^ 0x5A`. **Без дизассемблера.**

### 5.3 Три seed'а — точное доказательство

```
probe> alloc 16
probe> invoke function derive_session_key [1 0x02060000] --diff 16
probe> peek 0x02060000 16
```

Три точки достаточно для подтверждения линейности + XOR-маски.

### Задания

1. Восстановите формулу по трём seed'ам. Проверьте предсказание на seed=100 — `peek` должен совпасть с расчётом.
2. **Задача-вызов:** какие аргументы `derive_session_key` были бы уязвимы, если бы она вызывала `memcpy` без проверки длины? (См. `--diff` покажет, куда пишет `memcpy`.)

---

## Модуль 6. Обфускация: два пути

**Цель:** понять разницу между статическим и динамическим анализом.

### Путь A — статический (`disasm`)

```
probe> disasm verify_license 30
```

В потоке инструкций студент увидит:

```
movzx ecx, byte ptr [eax+0x1000XXXX]    ← G_LICENSE_KEY
xor ecx, 0x3D                           ← маска
cmp dl, cl                              ← сравнение с input
jne ...
```

Из этого **сразу** видно: `key[i] = G_LICENSE_KEY[i] ^ 0x3D`. Дальше — `peek 0x1000XXXX 8` (адрес берётся из `disasm`) — видит зашифрованные байты. Вручную XOR'ит → получает `pr0be!1`.

### Путь B — динамический (`decrypt_inplace`)

```
probe> alloc 8
[+] allocated 8 bytes at 0x02070000

probe> poke 0x02070000 0x59 0x5B 0x46 0x4B 0x4C 0x1D 0x1B 0x29
[+] wrote 8 byte(s) to 0x02070000

probe> invoke function decrypt_inplace [0x02070000 8] --diff 8
```

**Что видеть:**
```
[+] done: EAX = 0x00000008 (8)
    --- diff: 1 buffer(s) watched ---
    addr 0x02070000 (8 bytes) [8 bytes changed]
      before: 59 5B 46 4B 4C 1D 1B 29
      after:  70 72 6F 62 65 34 32 00     ← "probe42\0"
```

Зашифрованные байты сразу видны как ASCII во `--diff`. **Не нужно понимать алгоритм.** Студент видит текст.

### Обсуждение

- **Путь A** даёт понимание **почему** (маска 0x3D) и работает даже на **неизменяемом** буфере.
- **Путь B** даёт **что** (итоговые байты), но требует вызывать функцию — и не работает, если функция in-place **не** работает или имеет сайд-эффекты.
- **Оба** пути дополняют друг друга: статика даёт гипотезу, динамика её подтверждает.

### 6.3 Mock на `decrypt_inplace` → ломает приложение

```
probe> reset mock --all
probe> invoke function check_obfuscated_password ["probe42"]
[+] done: EAX = 0x00000001 (1)              ← честный пароль

probe> set mock decrypt_inplace --return 0
probe> invoke function check_obfuscated_password ["probe42"]
[+] done: EAX = 0x00000000 (0)              ← мок сломал расшифровку
    runtime mock hits:
      -> 0x...  decrypt_inplace  x1
```

**Обучающий момент:** мок на «внутренний хелпер» ломает прикладную логику — не потому что хелпер «неправильный», а потому что мы **симулировали его отказ**. Это ровно то, что делает probe в сценарии «что если эта зависимость сломана?».

### Задания

1. Определите пароль для `verify_license` **только** через `disasm` (не вызывая функцию). Проверьте через `invoke function verify_license ["<guess>"]`.
2. Определите пароль для `verify_license` **только** через `decrypt_inplace`. Проверьте.
3. **Задача-вызов:** придумайте, как восстановить XOR-маску, если её нет в `disasm` (например, применена к вычисляемому значению).

---

## Модуль 7. Краши: три типа исключений

**Цель:** увидеть, что probe переживает **любой** краш, и научиться различать коды исключений.

### 7.1 Division by zero

```
probe> invoke function crash_div [10 0]
[!] sandbox crashed (code 0xC0000094)
    fault instruction: 0x...crash_div+...
    EAX marker = 0xDEADFA11
```

### 7.2 Illegal instruction

```
probe> invoke function crash_illegal_instruction []
[!] sandbox crashed (code 0xC000001D)
    EAX marker = 0xDEADFA11
```

### 7.3 Null deref

```
probe> invoke function crash_null_deref []
[!] sandbox crashed (code 0xC0000005)
    fault instruction: 0x...crash_null_deref
    fault memory access: 0x00000000
    EAX marker = 0xDEADFA11
```

### 7.4 Что запомнить

| Код | Имя | Причина |
|---|---|---|
| `0xC0000094` | INT_DIVIDE_BY_ZERO | деление на 0 |
| `0xC000001D` | ILLEGAL_INSTRUCTION | ud2, невалидный opcode |
| `0xC0000005` | ACCESS_VIOLATION | чтение/запись по невалидному адресу |

`fault instruction` показывает **адрес инструкции**, на которой произошёл краш. `fault memory access` показывает **адрес данных** (только для AV).

### 7.5 `call log` как следственный журнал

```
probe> call log
  #  Function                  EAX          Status    Patch     Hits
  1  crash_div                 0xDEADFA11   AV/0x94       0        0
  2  crash_illegal_instruction 0xDEADFA11   AV/0x1D       0        0
  3  crash_null_deref          0xDEADFA11   AV/0x5        0        0
```

Все три краша в одной сессии, REPL жив. `AV/0x94` — сокращение от кода.

### Задания

1. Прогоните `crash_div [10 0]` и `crash_div [10 2]`. Сравните `Status` в `call log`.
2. Что произойдёт, если `crash_div [10 0]` вызвать **до** любого другого invoke? (`<UEF>` warning — почему?)
3. **Задача-вызов:** придумайте вызов, который даст `EXCEPTION_BREAKPOINT` (`0x80000003`), без изменения crackme (подсказка: `int3` через `alloc`/`poke`).

---

## Модуль 8. Buffer overflow (CWE-121)

**Цель:** увидеть, как размер влияет на целостность стека.

### 8.1 Безопасный размер

```
probe> alloc 64
[+] allocated 64 bytes at 0x02080000

probe> poke 0x02080000 "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH..."
probe> invoke function parse_user_bio [0x02080000 16]
[+] done: EAX = 0x00000001 (1)
```

`16` байт — ровно размер `local_bio[32]`, всё помещается.

### 8.2 На грани

```
probe> invoke function parse_user_bio [0x02080000 32]
[+] done: EAX = 0x00000001 (1)
```

Ровно `32` — на границе. Обычно OK, но saved EBP/EIP уже могут быть затронуты (зависит от epilogue).

### 8.3 Переполнение

```
probe> invoke function parse_user_bio [0x02080000 40]
[!] sandbox crashed (code 0xC0000005)
    fault instruction: ...
    fault memory access: ...
```

`40 > 32` — перезаписан saved EBP и часть saved EIP. Функция при `ret` прыгает в мусор → AV.

### 8.4 Доказательство размера буфера

```
probe> disasm parse_user_bio 15
```

В `disasm` видно `sub esp, 0x20` (или `push` 8 раз по 4 байта) — стековый фрейм под `[u8; 32]`. Студент находит точный размер через `disasm` **без** знания Rust-исходника.

Затем подтверждает гипотезу через бинарный поиск:
- `size=31` → ok
- `size=32` → ok
- `size=33` → ok (но перезаписывает padding)
- `size=36` → crash (перезаписан saved EBP + EIP)
- `size=40` → crash

**Обучающий момент:** граница краша **не равна** границе буфера. Нужно понимать layout стека (local_bio → padding → saved EBP → saved EIP).

### Задания

1. Бинарным поиском найдите минимальный `size`, при котором происходит краш. Сколько он? Почему больше 32?
2. **Задача-вызов:** проверьте гипотезу «между 32 и 36 есть окно, где функция возвращает ok, но saved EBP уже испорчен». Как это увидеть через `invoke`? (Подсказка: следующий `invoke` из этого же `alloc`-буфера — ведёт ли себя странно?)

---

## Модуль 9. Unsafe parsing (CWE-502)

**Цель:** показать, как `poke` превращается в фаззер бинарных форматов.

### 9.1 Валидный пакет

```
probe> alloc 8
[+] allocated 8 bytes at 0x02090000

probe> poke 0x02090000 0x04 0x01 0x02 0x03 0x04
[+] wrote 5 byte(s) to 0x02090000

probe> invoke function process_custom_packet [0x02090000]
[+] done: EAX = 0x0000000A (10)         ← 1+2+3+4
```

Пакет: `[len=4][payload 4 bytes]`. Сумма payload = 10.

### 9.2 Злонамеренный пакет

```
probe> poke 0x02090000 0xFF
[+] wrote 1 byte(s) to 0x02090000

probe> invoke function process_custom_packet [0x02090000]
[!] sandbox crashed (code 0xC0000005)
    fault instruction: ...
    fault memory access: 0x...
```

Функция читает `len=255` байт по `packet+1`, выходит за пределы 8-байтного `alloc`-буфера, попадает в невыделенную страницу → AV. Это OOB read.

### 9.3 Точечный фаззинг

Каждый `poke` меняет один байт заголовка, `invoke` проверяет реакцию. Например:

```
probe> poke 0x02090000 0x00           ← len=0
probe> invoke function process_custom_packet [0x02090000]
[+] done: EAX = 0x00000000 (0)        ← пустой payload, сумма 0

probe> poke 0x02090000 0x08           ← len=8, но payload всего 4 байта
probe> invoke function process_custom_packet [0x02090000]
[!] sandbox crashed (code 0xC0000005)  ← читает за пределами
```

**Обучающий момент:** `poke` + `invoke` — это ручной фаззер. Точка, где поведение меняется с `ok` на `crash`, и есть **невалидированный параметр**.

### Задания

1. Найдите минимальный `len`, при котором `process_custom_packet` крашится (при `alloc 8`).
2. Постройте таблицу `len ∈ {0, 1, 4, 8, 16, 32, 64, 128, 255}` → статус (ok / crash). Нарисуйте график.
3. **Задача-вызов:** измените пакет так, чтобы **не было** краша, но `EAX` был больше 1000 (подсказка: `poke` payload).

---

## Модуль 10. Anti-debug (CWE-749)

**Цель:** понять, что probe **не является отладчиком**, но может **симулировать** обнаружение отладчика.

### 10.1 Честный процесс

```
probe> reset mock --all
probe> invoke function detect_debugger []
[+] done: EAX = 0x00000000 (0)             ← BeingDebugged = 0
```

`detect_debugger` читает `PEB->BeingDebugged` через `FS:[0x30]+2`. Probe — обычный процесс, не отлаживаемый, поэтому `0`.

```
probe> invoke function protected_operation []
[+] done: EAX = 0x0000002A (42)            ← "всё ок"
```

### 10.2 Симуляция отладчика

```
probe> set mock detect_debugger --return 1
probe> invoke function protected_operation []
[+] done: EAX = 0xFFFFFFFF (-1)            ← "обнаружен отладчик"
    runtime mock hits:
      -> 0x...  detect_debugger  x1
```

Студент **создал сценарий**, при котором приложение ведёт себя «как под отладчиком» — без реальной отладки. Это и есть сила моков.

### 10.3 Отличие от Frida / x64dbg

**Frida и отладчики** обычно **незаметны** для `IsDebuggerPresent`, но:
- устанавливают hooks в код (детектируется через проверку целостности);
- создают поток-агент (видим в `NtQuerySystemInformation`);
- изменяют IAT-таблицы;
- имеют специфические имена модулей.

**Probe** — не устанавливает агент, не патчит память постоянно, не меняет IAT надолго. Он **полностью независим** от процесса-жертвы. Единственное, что было модифицировано — временные CALL-патчи на время invoke, которые немедленно откатываются.

**Обучающий момент:** «anti-debug обходится не всегда тем, что отключить отладчик. Иногда — тем, что отладчика **не используют**.»

### Задания

1. Покажите, что `protected_operation` при default-моках возвращает 42 (probe чист).
2. Замокайте `detect_debugger` на 1 и покажите `-1`.
3. **Задача-вызов:** «представьте, что `protected_operation` — это не проверка, а **настоящая** защита (шифрует файлы). Опишите, как `runtime mock hits` поможет обнаружить, что защита сработала».

---

## Модуль 11. Научный журнал: `call log`

**Цель:** научиться вести эксперимент как научный: гипотеза → прогон → доказательство.

### 11.1 Сценарий

Студент выполняет **серию** invoke подряд, пытаясь понять, что делает `login`. Все вызовы автоматически попадают в `call log`.

```
probe> reset mock --all
probe> invoke function login ["u" "wrong"]
probe> set mock is_admin --return 1
probe> invoke function login ["u" "wrong"]
probe> set mock is_admin --return 0
probe> set mock check_password --passthrough
probe> invoke function login ["u" "s3cr3t"]

probe> call log
  #  Function  EAX          Status    Patch     Hits
  1  login     0x00000000   ok            2        2
  2  login     0x00000001   ok            2        1
  3  login     0x00000001   ok            1        1
```

**Что студент видит как «научные данные»:**
- Вызов 1 (обе проверки default): EAX=0, hits=2 (обе зависимости сработали)
- Вызов 2 (is_admin→1): EAX=1, hits=1 (только is_admin; short-circuit)
- Вызов 3 (check_password passthrough): EAX=1, patch=1 (is_admin замокан, check_password — нет), hits=1

**Три строки — три доказательства.** Это и есть «научный журнал»: каждая строка подтверждает или опровергает гипотезу.

### 11.2 Экспериментальный отчёт

Формат отчёта (который студент сдаёт):

```markdown
## Гипотеза
login(user, pass) = 1 iff (is_admin() == 1) OR (check_password(pass) == 1)

## Эксперименты
| # | Моки | Вход | EAX | Hits | Вывод |
|---|------|------|-----|------|-------|
| 1 | default | "u","wrong" | 0 | is_admin, check_password | обе вызваны, обе 0 |
| 2 | is_admin=1 | "u","wrong" | 1 | is_admin | short-circuit: 2-я не вызвана |
| 3 | is_admin=0, check_password=passthrough | "u","s3cr3t" | 1 | is_admin | реальный пароль проходит |

## Вывод
Гипотеза подтверждена. Логика OR-соединения.
```

### 11.3 `call log clear` — новый эксперимент

```
probe> call log clear
[+] call log cleared
probe> call log
(call log is empty). Every `invoke` appends an entry.
```

**Обучающий момент:** каждый эксперимент начинается с чистого журнала. Не смешивайте данные.

### Задания

1. Сформулируйте гипотезу о поведении `validate_premium_user` (без чтения `disasm`). Проверьте тремя вызовами, оформите отчёт.
2. **Задача-вызов:** получите `login` возвращающий 1, **ни разу** не замокав `is_admin` на 1. Оформите как отчёт.

---

## Сводная матрица: какой пример что покрывает

| Функция | Модуль | Feature probe | CWE/CAPEC |
|---|---|---|---|
| `login` | 1, 11 | `set mock`, `runtime hits`, `call log` | — |
| `fill` | 2 | `alloc`, `poke`, `--diff` | — |
| `copy_upper` | 2 | `--diff` (in+out) | — |
| `validate_premium_user` | 3 | короткое замыкание | CAPEC-29 |
| `verify_serial_timing` | 4 | `runtime hits` как counter oracle | CWE-208 |
| `derive_session_key` | 5 | `--diff`, `peek` | CAPEC-462 |
| `verify_license` | 6 | `disasm`, `peek` | CWE-321 |
| `decrypt_inplace` | 6 | `--diff`, mock side-effect | CAPEC-462 |
| `check_obfuscated_password` | 6 | mock dependency | — |
| `crash_div` | 7 | VEH, `call log` | CWE-369 |
| `crash_illegal_instruction` | 7 | VEH | CWE-248 |
| `crash_null_deref` | 7 | VEH | CWE-476 |
| `parse_user_bio` | 8 | VEH, `disasm` | CWE-121 |
| `process_custom_packet` | 9 | `poke` как фаззер | CWE-502 / CWE-125 |
| `detect_debugger` | 10 | mock как симулятор | CWE-749 |

---

## Ошибки, с которыми столкнётся студент

| Симптом | Причина | Что делать |
|---|---|---|
| `[!] note: a custom mock is set for X. invoke function runs the real code` | Студент ждёт, что `invoke function X` применит мок к `X` | Использовать `invoke mock X` |
| `[!] warning: arg #N (...) is not readable` | Аргумент — битый указатель | Проверить `alloc`-адрес, `peek` перед invoke |
| `[!] sandbox crashed (code 0xC0000005)` | Краш внутри функции | Норма; проверить `fault instruction` и `fault memory access` |
| `[-] cannot resolve: ...` | Опечатка в имени экспорта | `find function --sort name` для точного имени |
| `[UEF] sandbox exception deferred to WoW64` | Не ошибка; WoW64 применяет CONTEXT через второй шанс | Игнорировать |
| `patch_count: 0` при `set mock X` | `invoke` идёт в X напрямую, а не в CALL на X | Норма; использовать `invoke mock X` |
| `EAX = 0` на `verify_license ["<guess>"]` | Неверный пароль | Восстановить по `disasm` или через `decrypt_inplace` |

---

## Итоговое задание (capstone)

Задача: **исследовать crackme полностью и сдать отчёт**. В отчёте:

1. **Карта функций** — для каждой экспортированной функции: назначение (гипотеза), подтверждение (метод).
2. **Восстановленные данные** — пароль `verify_license`, пароль `verify_serial_timing`, пароль `check_obfuscated_password`, формула `derive_session_key`.
3. **Обнаруженные уязвимости** — как минимум 3 CWE из списка, с указанием: код-симптом, код-эксплойт через probe, `call log` как доказательство.
4. **Обход защиты** — как обойти `validate_premium_user` и `check_obfuscated_password` через моки.
5. **Мета-рефлексия** — что далось легко (динамика), что — тяжело (без `disasm` не восстанавливается XOR-маска), в чём probe **незаменим** по сравнению с ручным reverse.

Отчёт — это и есть **доказательство**, что студент научился работать с инструментом в полном цикле: discovery → hypothesis → experiment → evidence → report.
