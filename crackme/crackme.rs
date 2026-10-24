// crackme.rs  (cdylib, PE32/x86)
//
// Сборка:
//   rustc --crate-type=cdylib --target i686-pc-windows-msvc -O crackme.rs ^
//     -C link-arg=/BASE:0x10000000 ^
//     -C link-arg=/DYNAMICBASE:NO ^
//     -C link-arg=/FIXED:NO ^
//     -o crackme.dll
//
// Эталонный полигон для probe. Каждая функция — отдельный сценарий
// (CWE / CAPEC / OWASP). Комментарий над каждой содержит:
//   - что демонстрирует;
//   - эталонные probe-команды;
//   - ожидаемое поведение.

// ============================================================
// ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ (секция .data/.rdata)
// ============================================================

#[no_mangle]
pub static mut G_ADMIN_FLAG: i32 = 0;
// Адрес ищется через `disasm is_admin` → `mov eax, [0x1000XXXX]`.
// `set mock is_admin --return 1` уже не меняет флаг, но даёт тот же результат.

/// XOR-маскированный ключ лицензии. Расшифровка: `byte ^ 0x3D` даёт "pr0be!1\0".
/// Студент находит адрес через `disasm verify_license` и видит xor 0x3D в цикле.
#[no_mangle]
pub static G_LICENSE_KEY: [u8; 8] = [
    0x4D, 0x4F, 0x0D, 0x5F, 0x58, 0x1C, 0x0C, 0x3D,
];

/// XOR-маскированный пароль "probe42\0" (маска 0x29).
/// Используется в check_obfuscated_password через decrypt_inplace.
#[no_mangle]
pub static OBFUSCATED_PASSWORD: [u8; 8] = [
    0x59, 0x5B, 0x46, 0x4B, 0x4C, 0x1D, 0x1B, 0x29,
];

// ============================================================
// БЛОК 1. Базовая аутентификация
// ============================================================

/// Возвращает текущий флаг администратора (volatile, чтобы не свернулось в константу).
///
/// probe:
///   invoke function is_admin []                 → EAX=0
///   set mock is_admin --return 1
///   invoke function login ["u" "wrong"]         → EAX=1 через backdoor
#[inline(never)]
#[no_mangle]
pub extern "C" fn is_admin() -> i32 {
    unsafe { std::ptr::read_volatile(&raw const G_ADMIN_FLAG) }
}

/// Сравнение с литералом "s3cr3t\0".
///
/// probe:
///   invoke function check_password ["s3cr3t"]   → EAX=1
///   invoke function check_password ["wrong"]    → EAX=0
#[inline(never)]
#[no_mangle]
pub extern "C" fn check_password(pass: *const u8) -> i32 {
    if pass.is_null() {
        return 0;
    }
    unsafe {
        let p = std::slice::from_raw_parts(pass, 7);
        if p == b"s3cr3t\0" { 1 } else { 0 }
    }
}

/// Два CALL: сначала is_admin, потом check_password (только если первый вернул 0).
/// Идеально для демонстрации `runtime mock hits`: видно, какая ветка реально выполнилась.
///
/// probe (backdoor):
///   set mock is_admin --return 1
///   invoke function login ["u" "wrong"]
///     → EAX=1, hits: is_admin x1, check_password (отсутствует)
///
/// probe (честный пароль):
///   set mock check_password --passthrough
///   invoke function login ["u" "s3cr3t"]
///     → EAX=1, hits: is_admin x1 (check_password — не мокается)
#[inline(never)]
#[no_mangle]
pub extern "C" fn login(_user: *const u8, pass: *const u8) -> i32 {
    if is_admin() != 0 {
        return 1;
    }
    if check_password(pass) != 0 {
        return 1;
    }
    0
}

// ============================================================
// БЛОК 2. Утилиты памяти (--diff / poke)
// ============================================================

/// Заполняет буфер байтом. Возвращает длину.
///
/// probe:
///   alloc 64 → 0x02000000
///   invoke function fill [0x02000000 0x41 8] --diff 64
///     → diff: 8 bytes changed → "41 41 41 41 41 41 41 41"
#[inline(never)]
#[no_mangle]
pub extern "C" fn fill(buf: *mut u8, byte: u32, len: u32) -> u32 {
    if buf.is_null() || len == 0 {
        return 0;
    }
    unsafe {
        for i in 0..len as usize {
            *buf.add(i) = byte as u8;
        }
    }
    len
}

/// Копирует с повышением регистра (a-z → A-Z). Возвращает длину.
///
/// probe:
///   alloc 16 → 0x02010000
///   poke 0x02010000 "hello"
///   invoke function copy_upper [0x02010000 0x02020000 5] --diff 16
///     → diff: "48 45 4C 4C 4F"
#[inline(never)]
#[no_mangle]
pub extern "C" fn copy_upper(src: *const u8, dst: *mut u8, len: u32) -> u32 {
    if src.is_null() || dst.is_null() || len == 0 {
        return 0;
    }
    unsafe {
        for i in 0..len as usize {
            let c = *src.add(i);
            *dst.add(i) = if (b'a'..=b'z').contains(&c) { c - 32 } else { c };
        }
    }
    len
}

// ============================================================
// БЛОК 3. Timing side-channel через счётчик (CWE-208)
// ============================================================
//
// Идея: у нас нет доступа к TSC/наносекундам из probe. Зато есть
// runtime mock hits. Делаем цикл с CALL на пустышку на каждой итерации.
// Сколько итераций прошло до return 0 — столько байт совпало.

/// Пустышка-маркер. Внутри цикла проверки serial — call на каждом шаге.
/// Счётчик мока = число совпавших символов + 1.
///
/// Не мокайте эту функцию через `--passthrough`: смысл именно в подсчёте.
/// Дефолтный мок (return 0) работает: inc counter всё равно выполняется.
#[inline(never)]
#[no_mangle]
pub extern "C" fn __loop_marker() {
    unsafe {
        std::arch::asm!("nop", options(nostack, preserves_flags));
    }
}

/// Побайтовая проверка с early-return. Таргет "PR0BE42".
///
/// probe (bit-by-bit):
///   invoke function verify_serial_timing ["AAAAAAA"]
///     → EAX=0, hits: __loop_marker x1     (первый символ не совпал)
///   invoke function verify_serial_timing ["PAAAAAA"]
///     → EAX=0, hits: __loop_marker x2     (P совпал, A — нет)
///   invoke function verify_serial_timing ["PR0BE42"]
///     → EAX=1, hits: __loop_marker x7
///
/// Ключ восстанавливается без чтения ассемблера — только по hits.
#[inline(never)]
#[no_mangle]
pub extern "C" fn verify_serial_timing(serial: *const u8) -> i32 {
    if serial.is_null() {
        return 0;
    }
    let target = b"PR0BE42\0";
    unsafe {
        for i in 0..7 {
            __loop_marker();
            if *serial.add(i) != target[i] {
                return 0;
            }
        }
    }
    1
}

// ============================================================
// БЛОК 4. Многоуровневая защита (all mocks to 1)
// ============================================================
//
// Классическая лицензия: 3 независимые проверки, все должны вернуть 1.
// По умолчанию каждая возвращает 0. Студент замокает все три на 1.

#[inline(never)]
#[no_mangle]
pub extern "C" fn check_hardware_id() -> i32 { 0 }

#[inline(never)]
#[no_mangle]
pub extern "C" fn check_network_token() -> i32 { 0 }

#[inline(never)]
#[no_mangle]
pub extern "C" fn check_subscription_status() -> i32 { 0 }

/// Требует, чтобы ВСЕ три проверки вернули 1.
///
/// probe:
///   invoke function validate_premium_user []
///     → EAX=0 (все три возвращают 0)
///   set mock check_hardware_id --return 1
///   set mock check_network_token --return 1
///   set mock check_subscription_status --return 1
///   invoke function validate_premium_user []
///     → EAX=1, hits: все три x1
///
/// Также интересно: как только первая проверка возвращает 0,
/// остальные CALL не выполняются (&&). `runtime mock hits` это покажет.
#[inline(never)]
#[no_mangle]
pub extern "C" fn validate_premium_user() -> i32 {
    if check_hardware_id() == 1
        && check_network_token() == 1
        && check_subscription_status() == 1
    {
        return 1;
    }
    0
}

// ============================================================
// БЛОК 5. Скрытый out-параметр (CAPEC-462)
// ============================================================

/// Генерирует 16-байтовый "ключ" на основе seed и пишет в out-буфер.
///
/// probe:
///   alloc 16 → 0x02030000
///   invoke function derive_session_key [42 0x02030000] --diff 16
///     → diff: 16 bytes changed; содержимое зависит от seed
///   peek 0x02030000 16           → забрать готовый ключ
#[inline(never)]
#[no_mangle]
pub extern "C" fn derive_session_key(seed: u32, out_buffer: *mut u8) -> i32 {
    if out_buffer.is_null() {
        return 0;
    }
    unsafe {
        for i in 0..16 {
            *out_buffer.add(i) = ((seed.wrapping_add(i as u32)) ^ 0x5A) as u8;
        }
    }
    1
}

// ============================================================
// БЛОК 6. Проверка лицензии с XOR-маской (CWE-321 / OWASP A02)
// ============================================================

/// Сравнивает 8 байт с G_LICENSE_KEY[i] ^ 0x3D. Правильный ключ: "pr0be!1\0".
///
/// probe (два пути):
///   1. `disasm verify_license 30` → видит `xor al, 0x3D` и `movzx ... [0x1000XXXX]`
///      → вручную: ключ[i] = G_LICENSE_KEY[i] ^ 0x3D
///   2. `invoke function verify_license ["pr0be!1"]` → EAX=1
#[inline(never)]
#[no_mangle]
pub extern "C" fn verify_license(key: *const u8) -> i32 {
    if key.is_null() {
        return 0;
    }
    unsafe {
        for i in 0..8 {
            let expected = G_LICENSE_KEY[i] ^ 0x3D;
            if *key.add(i) != expected {
                return 0;
            }
        }
    }
    1
}

// ============================================================
// БЛОК 7. Переполнение стека на стеке (CWE-121)
// ============================================================
//
// ВНИМАНИЕ: этот пример намеренно уязвим. При size > 32 (размер буфера)
// начнётся перезапись saved EBP, при size > 36 — saved EIP.
// БЕЗОПАСНЫЙ ДИАПАЗОН для probe: size <= 71.
// При size > 71 повреждается saved_ebx фрейма probe_call_with_stack,
// и VEH может потерять возможность восстановления (крайне редко, но
// используйте 32..40 для чистой демонстрации).

/// Копирует size байт в локальный буфер [u8; 32] без проверки.
///
/// probe (безопасно):
///   alloc 64 → 0x02040000; poke "AAAA..."
///   invoke function parse_user_bio [0x02040000 16]   → EAX=1
///
/// probe (краш):
///   invoke function parse_user_bio [0x02040000 40]
///     → sandbox crashed (code 0xC0000005), EAX = 0xDEADFA11
///     → probe остаётся жить, REPL продолжает принимать команды
#[inline(never)]
#[no_mangle]
pub extern "C" fn parse_user_bio(data: *const u8, size: u32) -> i32 {
    if data.is_null() {
        return 0;
    }
    let mut local_bio: [u8; 32] = [0; 32];
    unsafe {
        // Уязвимое копирование: size контролируется вызывающим.
        std::ptr::copy_nonoverlapping(data, local_bio.as_mut_ptr(), size as usize);
        // volatile read, чтобы компилятор не выкинул local_bio как "unused"
        let _ = std::ptr::read_volatile(&local_bio[0]);
    }
    1
}

// ============================================================
// БЛОК 8. Небезопасный парсинг бинарных данных (CWE-502 / CWE-125)
// ============================================================

/// Формат пакета: [1 байт: len][N байт: payload].
/// Читает len байт по указателю packet+1 без проверки границ.
///
/// probe (валидно):
///   alloc 8 → 0x02050000
///   poke 0x02050000 0x04 0x01 0x02 0x03 0x04
///   invoke function process_custom_packet [0x02050000] → EAX=10 (1+2+3+4)
///
/// probe (out-of-bounds read):
///   poke 0x02050000 0xFF        (len=255, но выделено только 8 байт)
///   invoke function process_custom_packet [0x02050000]
///     → sandbox crashed (code 0xC0000005); VEH ловит
#[inline(never)]
#[no_mangle]
pub extern "C" fn process_custom_packet(packet: *const u8) -> i32 {
    if packet.is_null() {
        return -1;
    }
    unsafe {
        let len = *packet as usize;
        let payload = packet.add(1);
        let mut sum: u32 = 0;
        for i in 0..len {
            sum = sum.wrapping_add(*payload.add(i) as u32);
        }
        sum as i32
    }
}

// ============================================================
// БЛОК 9. Обфусцированные строки (CAPEC-462)
// ============================================================

/// Расшифровывает буфер XOR'ом с 0x29 (in-place). Возвращает длину.
///
/// probe (прямой вызов):
///   alloc 8 → 0x02060000
///   poke 0x02060000 0x59 0x5B 0x46 0x4B 0x4C 0x1D 0x1B 0x29
///   invoke function decrypt_inplace [0x02060000 8] --diff 8
///     → diff: 8 bytes changed → "70 72 6F 62 65 34 32 00" = "probe42\0"
#[inline(never)]
#[no_mangle]
pub extern "C" fn decrypt_inplace(buf: *mut u8, len: u32) -> u32 {
    if buf.is_null() || len == 0 {
        return 0;
    }
    unsafe {
        for i in 0..len as usize {
            *buf.add(i) ^= 0x29;
        }
    }
    len
}

/// Расшифровывает локальную копию OBFUSCATED_PASSWORD через CALL на decrypt_inplace,
/// затем сравнивает с candidate. Правильный пароль: "probe42".
///
/// probe:
///   invoke function check_obfuscated_password ["probe42"]  → EAX=1
///   invoke function check_obfuscated_password ["wrong"]    → EAX=0
///   set mock decrypt_inplace --return 0
///   invoke function check_obfuscated_password ["probe42"]
///     → EAX=0 — мок глушит расшифровку, пароль не совпадает
///
/// Отличная демонстрация: патчинг зависимости ломает прикладную логику.
#[inline(never)]
#[no_mangle]
pub extern "C" fn check_obfuscated_password(candidate: *const u8) -> i32 {
    if candidate.is_null() {
        return 0;
    }
    let mut buf = [0u8; 8];
    unsafe {
        std::ptr::copy_nonoverlapping(OBFUSCATED_PASSWORD.as_ptr(), buf.as_mut_ptr(), 8);
    }
    decrypt_inplace(buf.as_mut_ptr(), 8);
    unsafe {
        for i in 0..8 {
            if *candidate.add(i) != buf[i] {
                return 0;
            }
        }
    }
    1
}

// ============================================================
// БЛОК 10. Краши для VEH-тестов
// ============================================================
//
// probe ловит все эти коды через veh_handler:
//   EXCEPTION_INT_DIVIDE_BY_ZERO   (0xC0000094)
//   EXCEPTION_ILLEGAL_INSTRUCTION  (0xC000001D)
//   EXCEPTION_ACCESS_VIOLATION     (0xC0000005)

/// Деление на ноль. Вызывать с `[10 0]`.
///
/// probe:
///   invoke function crash_div [10 0]
///     → sandbox crashed (code 0xC0000094), EAX = 0xDEADFA11
#[inline(never)]
#[no_mangle]
pub extern "C" fn crash_div(n: u32, d: u32) -> u32 {
    n / d
}

/// Инструкция ud2 (undefined instruction). Безусловный crash.
///
/// probe:
///   invoke function crash_illegal_instruction []
///     → sandbox crashed (code 0xC000001D)
#[inline(never)]
#[no_mangle]
pub extern "C" fn crash_illegal_instruction() -> u32 {
    unsafe {
        std::arch::asm!("ud2", options(noreturn));
    }
}

/// Разыменование null. AV по адресу 0x00000000.
///
/// probe:
///   invoke function crash_null_deref []
///     → sandbox crashed (code 0xC0000005, fault_data=0x00000000)
#[inline(never)]
#[no_mangle]
pub extern "C" fn crash_null_deref() -> u32 {
    let ptr = std::hint::black_box(std::ptr::null::<u32>());
    unsafe { std::ptr::read_volatile(ptr) }
}

// ============================================================
// БЛОК 11. Anti-debug (CWE-749)
// ============================================================

/// Читает PEB->BeingDebugged через FS:[0x30]. На чистом процессе — 0.
///
/// probe:
///   invoke function detect_debugger []
///     → EAX=0 (probe не отладчик)
///
/// probe (симуляция):
///   set mock detect_debugger --return 1
///   invoke function protected_operation []  → EAX=-1
#[inline(never)]
#[no_mangle]
pub extern "C" fn detect_debugger() -> i32 {
    let peb_ptr: *const u8;
    unsafe {
        std::arch::asm!("mov {}, fs:[0x30]", out(reg) peb_ptr, options(nostack, preserves_flags));
    }
    if peb_ptr.is_null() {
        return -1;
    }
    unsafe { *peb_ptr.add(2) as i32 }
}

/// Если detect_debugger() != 0 — возвращает -1 (обнаружен отладчик), иначе 42.
///
/// probe:
///   invoke function protected_operation []              → EAX=42 (probe чист)
///   set mock detect_debugger --return 1
///   invoke function protected_operation []              → EAX=-1 (симуляция отладчика)
///
/// set mock detect_debugger --passthrough → снова 42
#[inline(never)]
#[no_mangle]
pub extern "C" fn protected_operation() -> i32 {
    if detect_debugger() != 0 {
        -1
    } else {
        42
    }
}

// ============================================================
// KEEPALIVE TABLE
// ============================================================
//
// MSVC-линкер с /OPT:REF вырезает все `#[no_mangle] pub extern "C"`
// функции, которые не достижимы из других функций крейта. В оригинале
// переживали только 5 (`is_admin`, `check_password`, `login`, `fill`,
// `copy_upper`), потому что каждая либо вызывается из `login`, либо
// достижима от неё. Остальные 17 — выкидывались.
//
// `#[used]` на этом статике запрещает линкеру его удалить. Каждый
// элемент — адрес соответствующей функции; `foo as usize` порождает
// релокацию, и линкер обязан сохранить каждую функцию, чтобы релокация
// резолвилась. Результат: `dumpbin /exports` показывает 22 символа.

#[used]
#[allow(non_upper_case_globals)]
static _CRACKME_KEEP: [usize; 22] = [
    is_admin as usize,
    check_password as usize,
    login as usize,
    fill as usize,
    copy_upper as usize,
    __loop_marker as usize,
    verify_serial_timing as usize,
    check_hardware_id as usize,
    check_network_token as usize,
    check_subscription_status as usize,
    validate_premium_user as usize,
    derive_session_key as usize,
    verify_license as usize,
    parse_user_bio as usize,
    process_custom_packet as usize,
    decrypt_inplace as usize,
    check_obfuscated_password as usize,
    crash_div as usize,
    crash_illegal_instruction as usize,
    crash_null_deref as usize,
    detect_debugger as usize,
    protected_operation as usize,
];