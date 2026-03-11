/*
 * vuln_example.c
 * A realistic-looking C file with several common vulnerabilities.
 * Used to demonstrate locate_vuln.py.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LOG_FILE "/tmp/app.log"

/* ------------------------------------------------------------------ */
/* 1. Buffer overflow — strcpy with no bounds check                    */
/* ------------------------------------------------------------------ */
void greet_user(char *username) {
    char buf[64];
    strcpy(buf, username);          /* VULN: no bounds check on username */
    printf("Hello, %s!\n", buf);
}

/* ------------------------------------------------------------------ */
/* 2. Format string vulnerability                                       */
/* ------------------------------------------------------------------ */
void log_message(char *msg) {
    FILE *f = fopen(LOG_FILE, "a");
    if (f) {
        fprintf(f, msg);            /* VULN: user-controlled format string */
        fclose(f);
    }
}

/* ------------------------------------------------------------------ */
/* 3. Command injection via system()                                   */
/* ------------------------------------------------------------------ */
void run_report(char *filename) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "cat %s", filename);
    system(cmd);                    /* VULN: unsanitised filename injected into shell */
}

/* ------------------------------------------------------------------ */
/* 4. Use-after-free                                                   */
/* ------------------------------------------------------------------ */
void process_data(int *data, int len) {
    int *tmp = (int *)malloc(len * sizeof(int));
    memcpy(tmp, data, len * sizeof(int));
    free(tmp);
    printf("First element: %d\n", tmp[0]);  /* VULN: use-after-free */
}

/* ------------------------------------------------------------------ */
/* 5. Integer overflow leading to heap underallocation                 */
/* ------------------------------------------------------------------ */
void store_items(unsigned int count) {
    /* If count is close to UINT_MAX, count+1 wraps to 0 */
    int *items = (int *)malloc((count + 1) * sizeof(int));  /* VULN: integer overflow */
    if (!items) return;
    memset(items, 0, (count + 1) * sizeof(int));
    free(items);
}

/* ------------------------------------------------------------------ */
/* Safe helper — bounds-checked copy (no vulnerability)                */
/* ------------------------------------------------------------------ */
void safe_copy(char *dst, const char *src, size_t dst_size) {
    strncpy(dst, src, dst_size - 1);
    dst[dst_size - 1] = '\0';
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <username>\n", argv[0]);
        return 1;
    }
    greet_user(argv[1]);
    log_message(argv[1]);
    run_report(argv[1]);
    return 0;
}
