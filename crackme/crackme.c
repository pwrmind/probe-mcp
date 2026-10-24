// crackme.c
// Собрать: см. команды ниже. Должен быть PE32 (x86), ImageBase = 0x10000000.
//
// Логика:
//   login(user, pass) -> 1 если (is_admin() != 0) ИЛИ (check_password(pass) == 1)
//   check_password простая, возвращает 1 только для пароля "s3cr3t"
//   is_admin читает volatile-глобал, который всегда 0
//   main читает user + pass и вызывает login

#include <stdio.h>

// volatile — чтобы компилятор не свернул is_admin в константу 0,
// и в login остался настоящий CALL на is_admin.
volatile int g_admin_flag = 0;

__declspec(noinline) int __cdecl is_admin(void) {
    return g_admin_flag;
}

__declspec(noinline) int __cdecl check_password(const char* pass) {
    if (pass[0] == 's' && pass[1] == '3' && pass[2] == 'c' &&
        pass[3] == 'r' && pass[4] == '3' && pass[5] == 't' && pass[6] == 0)
        return 1;
    return 0;
}

__declspec(noinline) int __cdecl login(const char* user, const char* pass) {
    (void)user; // в этой версии user не используется, но оставлен в сигнатуре
    if (is_admin()) return 1;
    if (check_password(pass)) return 1;
    return 0;
}

int main(void) {
    char u[64] = {0};
    char p[64] = {0};
    printf("user: ");
    scanf_s("%63s", u, 63);
    printf("pass: ");
    scanf_s("%63s", p, 63);

    if (login(u, p)) printf("Access granted\n");
    else             printf("Access denied\n");
    return 0;
}