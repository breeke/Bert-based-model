"""
Multi-Language Dataset Creator for CodeBERT/UniXcoder Vulnerability Detection
==============================================================================
Generates a unified dataset of C, Python, Java, JavaScript, and Go code samples
with realistic vulnerability patterns and their safe counterparts.

Vulnerability categories covered:
  C:          buffer overflow, format string, use-after-free, double free,
              integer overflow, null deref, command injection, off-by-one,
              uninitialized vars, race conditions, heap overflow,
              hardcoded credentials (CWE-798), path traversal (CWE-22),
              insecure file permissions (CWE-732), weak crypto (CWE-327),
              SQL injection (CWE-89)
  Python:     SQL injection, command injection, path traversal, deserialization,
              eval/exec injection, SSRF, hardcoded credentials, weak crypto,
              XXE, insecure file permissions, TOCTOU race, ReDoS,
              format string / template injection (CWE-134)
  Java:       SQL injection, command injection, path traversal, weak crypto,
              format string, TOCTOU race, insecure permissions,
              hardcoded credentials
  JavaScript: SQL injection, command injection, path traversal, weak crypto,
              template injection, TOCTOU race, insecure permissions,
              hardcoded credentials
  Go:         SQL injection, command injection, path traversal, weak crypto,
              format string, TOCTOU race, insecure permissions,
              hardcoded credentials

Cross-language CWEs (all 5 languages):
  CWE-78  command injection, CWE-367 TOCTOU race,
  CWE-798 hardcoded credentials, CWE-22 path traversal,
  CWE-732 insecure file permissions, CWE-327 weak crypto,
  CWE-89  SQL injection, CWE-134 format/template injection
"""

import json
import os
import random
import hashlib
import logging
from collections import Counter

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# C VULNERABLE PATTERNS  (target = 1)
# ---------------------------------------------------------------------------
C_VULNERABLE = [
    # ---- Buffer Overflow (CWE-120) ----
    {
        "func": """void process_input(char *user_input) {
    char buffer[64];
    strcpy(buffer, user_input);
    printf("Processed: %s\\n", buffer);
}""",
        "cwe": ["CWE-120"], "language": "c", "category": "buffer_overflow"
    },
    {
        "func": """void concat_strings(char *a, char *b) {
    char result[128];
    strcpy(result, a);
    strcat(result, b);
    send_response(result);
}""",
        "cwe": ["CWE-120"], "language": "c", "category": "buffer_overflow"
    },
    {
        "func": """int read_name(int fd) {
    char name[32];
    read(fd, name, 256);
    log_user(name);
    return 0;
}""",
        "cwe": ["CWE-120"], "language": "c", "category": "buffer_overflow"
    },
    {
        "func": """void handle_header(const char *header) {
    char local_buf[100];
    sprintf(local_buf, "Header: %s", header);
    process_header(local_buf);
}""",
        "cwe": ["CWE-120"], "language": "c", "category": "buffer_overflow"
    },
    {
        "func": """void copy_payload(const char *src) {
    char dest[256];
    memcpy(dest, src, strlen(src));
    dest[strlen(src)] = '\\0';
    dispatch(dest);
}""",
        "cwe": ["CWE-120"], "language": "c", "category": "buffer_overflow"
    },
    {
        "func": """void parse_token(char *token) {
    char parsed[16];
    int i = 0;
    while (*token) {
        parsed[i++] = *token++;
    }
    parsed[i] = '\\0';
}""",
        "cwe": ["CWE-120"], "language": "c", "category": "buffer_overflow"
    },
    {
        "func": """void get_env_value(const char *key) {
    char value[64];
    char *env = getenv(key);
    if (env)
        strcpy(value, env);
    use_value(value);
}""",
        "cwe": ["CWE-120"], "language": "c", "category": "buffer_overflow"
    },
    {
        "func": """void receive_message(int sock) {
    char msg[512];
    int len = recv(sock, msg, 4096, 0);
    msg[len] = '\\0';
    handle_message(msg);
}""",
        "cwe": ["CWE-120"], "language": "c", "category": "buffer_overflow"
    },

    # ---- Buffer Overflow — harder patterns ----
    {
        "func": """int handle_packet(struct packet *pkt, char *out, size_t out_len) {
    int header_len = pkt->header_size;
    int body_len   = pkt->body_size;
    if (header_len < 0 || body_len < 0)
        return -1;
    memcpy(out, pkt->header, header_len);
    memcpy(out + header_len, pkt->body, body_len);
    return header_len + body_len;
}""",
        "cwe": ["CWE-120"], "language": "c", "category": "buffer_overflow"
    },
    {
        "func": """void build_response(const char *status, const char *body) {
    char response[512];
    int  n;
    n  = snprintf(response, sizeof(response), "HTTP/1.1 %s\\r\\n", status);
    n += snprintf(response + n, sizeof(response), "Content-Length: %zu\\r\\n\\r\\n", strlen(body));
    strcpy(response + n, body);
    send_raw(response, strlen(response));
}""",
        "cwe": ["CWE-120"], "language": "c", "category": "buffer_overflow"
    },
    {
        "func": """char *normalise_path(const char *base, const char *rel) {
    static char resolved[256];
    strncpy(resolved, base, sizeof(resolved));
    strncat(resolved, "/", sizeof(resolved) - strlen(resolved) - 1);
    strncat(resolved, rel,  strlen(rel));
    return resolved;
}""",
        "cwe": ["CWE-120"], "language": "c", "category": "buffer_overflow"
    },

    # ---- Format String (CWE-134) ----
    {
        "func": """void log_error(char *user_msg) {
    char logbuf[256];
    snprintf(logbuf, sizeof(logbuf), user_msg);
    write_log(logbuf);
}""",
        "cwe": ["CWE-134"], "language": "c", "category": "format_string"
    },
    {
        "func": """void print_status(char *status) {
    fprintf(stderr, status);
}""",
        "cwe": ["CWE-134"], "language": "c", "category": "format_string"
    },
    {
        "func": """void debug_print(const char *input) {
    printf(input);
}""",
        "cwe": ["CWE-134"], "language": "c", "category": "format_string"
    },
    {
        "func": """void syslog_message(char *msg) {
    syslog(LOG_INFO, msg);
}""",
        "cwe": ["CWE-134"], "language": "c", "category": "format_string"
    },
    {
        "func": """void log_request(char *method, char *path) {
    char entry[512];
    sprintf(entry, method);
    strcat(entry, " ");
    strcat(entry, path);
    printf(entry);
}""",
        "cwe": ["CWE-134"], "language": "c", "category": "format_string"
    },

    # ---- Use-After-Free (CWE-416) ----
    {
        "func": """char* get_cached_data(int refresh) {
    char *cache = malloc(1024);
    load_data(cache);
    if (refresh) {
        free(cache);
    }
    return cache;
}""",
        "cwe": ["CWE-416"], "language": "c", "category": "use_after_free"
    },
    {
        "func": """void process_request(struct request *req) {
    char *body = req->body;
    free(req);
    parse_body(body);
    log_request(req->method);
}""",
        "cwe": ["CWE-416"], "language": "c", "category": "use_after_free"
    },
    {
        "func": """void cleanup_session(struct session *s) {
    free(s->token);
    free(s);
    audit_log("Session closed for user: %s", s->username);
}""",
        "cwe": ["CWE-416"], "language": "c", "category": "use_after_free"
    },
    {
        "func": """int handle_connection(int fd) {
    struct conn *c = malloc(sizeof(struct conn));
    c->fd = fd;
    if (authenticate(c) < 0) {
        free(c);
    }
    return c->fd;
}""",
        "cwe": ["CWE-416"], "language": "c", "category": "use_after_free"
    },
    {
        "func": """void update_list(struct node *head) {
    struct node *curr = head;
    while (curr) {
        struct node *next = curr->next;
        if (curr->expired) {
            free(curr);
        }
        curr->visited = 1;
        curr = next;
    }
}""",
        "cwe": ["CWE-416"], "language": "c", "category": "use_after_free"
    },

    # ---- Double Free (CWE-415) ----
    {
        "func": """void free_context(struct ctx *c) {
    if (c->buffer)
        free(c->buffer);
    cleanup_internals(c);
    free(c->buffer);
    free(c);
}""",
        "cwe": ["CWE-415"], "language": "c", "category": "double_free"
    },
    {
        "func": """int release_resources(char *a, char *b) {
    free(a);
    if (a == b)
        return 0;
    free(b);
    free(a);
    return 1;
}""",
        "cwe": ["CWE-415"], "language": "c", "category": "double_free"
    },
    {
        "func": """void destroy_object(struct obj *o) {
    free(o->name);
    free(o->data);
    if (o->error) {
        free(o->name);
        report_error(o->error);
    }
    free(o);
}""",
        "cwe": ["CWE-415"], "language": "c", "category": "double_free"
    },

    # ---- Integer Overflow (CWE-190) ----
    {
        "func": """void *allocate_buffer(int count, int elem_size) {
    int total = count * elem_size;
    void *buf = malloc(total);
    return buf;
}""",
        "cwe": ["CWE-190"], "language": "c", "category": "integer_overflow"
    },
    {
        "func": """char *resize_array(char *old, unsigned short old_len, unsigned short add_len) {
    unsigned short new_len = old_len + add_len;
    char *new_buf = realloc(old, new_len);
    return new_buf;
}""",
        "cwe": ["CWE-190"], "language": "c", "category": "integer_overflow"
    },
    {
        "func": """int compute_offset(int base, int index, int width) {
    int offset = base + index * width;
    return data[offset];
}""",
        "cwe": ["CWE-190"], "language": "c", "category": "integer_overflow"
    },
    {
        "func": """void read_records(int fd, uint16_t num_records) {
    size_t buf_size = num_records * sizeof(struct record);
    struct record *records = malloc(buf_size);
    read(fd, records, buf_size);
    process_records(records, num_records);
    free(records);
}""",
        "cwe": ["CWE-190"], "language": "c", "category": "integer_overflow"
    },

    # ---- Null Pointer Dereference (CWE-476) ----
    {
        "func": """void process_config(const char *path) {
    FILE *f = fopen(path, "r");
    char line[256];
    fgets(line, sizeof(line), f);
    fclose(f);
}""",
        "cwe": ["CWE-476"], "language": "c", "category": "null_deref"
    },
    {
        "func": """int get_user_id(const char *username) {
    struct user *u = find_user(username);
    return u->id;
}""",
        "cwe": ["CWE-476"], "language": "c", "category": "null_deref"
    },
    {
        "func": """void print_result(struct result *r) {
    char *msg = r->message;
    int len = strlen(msg);
    printf("Result (%d): %s\\n", len, msg);
}""",
        "cwe": ["CWE-476"], "language": "c", "category": "null_deref"
    },
    {
        "func": """char *lookup_value(struct map *m, const char *key) {
    struct entry *e = map_get(m, key);
    char *copy = strdup(e->value);
    return copy;
}""",
        "cwe": ["CWE-476"], "language": "c", "category": "null_deref"
    },

    # ---- Command Injection (CWE-78) ----
    {
        "func": """int check_host(const char *hostname) {
    char cmd[256];
    sprintf(cmd, "ping -c 1 %s", hostname);
    return system(cmd);
}""",
        "cwe": ["CWE-78"], "language": "c", "category": "command_injection"
    },
    {
        "func": """void compress_file(const char *filename) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "gzip %s", filename);
    system(cmd);
}""",
        "cwe": ["CWE-78"], "language": "c", "category": "command_injection"
    },
    {
        "func": """int dns_lookup(const char *domain) {
    char buf[256];
    sprintf(buf, "nslookup %s", domain);
    FILE *p = popen(buf, "r");
    char result[1024];
    fread(result, 1, sizeof(result), p);
    pclose(p);
    return parse_dns(result);
}""",
        "cwe": ["CWE-78"], "language": "c", "category": "command_injection"
    },
    {
        "func": """void create_user_dir(const char *username) {
    char cmd[256];
    sprintf(cmd, "mkdir -p /home/%s", username);
    system(cmd);
}""",
        "cwe": ["CWE-78"], "language": "c", "category": "command_injection"
    },

    # ---- Command Injection — harder patterns ----
    {
        "func": """int run_converter(const char *input_file, const char *fmt) {
    char cmd[512];
    int  rc;
    snprintf(cmd, sizeof(cmd), "convert %s -format %s /tmp/out.bin", input_file, fmt);
    rc = system(cmd);
    return (rc == 0) ? 0 : -1;
}""",
        "cwe": ["CWE-78"], "language": "c", "category": "command_injection"
    },
    {
        "func": """void archive_logs(const char *date_str) {
    char path[256];
    char cmd[512];
    snprintf(path, sizeof(path), "/var/log/app-%s.log", date_str);
    snprintf(cmd,  sizeof(cmd),  "tar czf /backup/logs.tgz %s", path);
    popen(cmd, "r");
}""",
        "cwe": ["CWE-78"], "language": "c", "category": "command_injection"
    },

    # ---- Off-by-One (CWE-193) ----
    {
        "func": """void copy_string(char *dest, const char *src, int max) {
    int i;
    for (i = 0; i <= max; i++) {
        dest[i] = src[i];
    }
    dest[i] = '\\0';
}""",
        "cwe": ["CWE-193"], "language": "c", "category": "off_by_one"
    },
    {
        "func": """int find_char(const char *str, char c) {
    int len = strlen(str);
    for (int i = 0; i <= len; i++) {
        if (str[i] == c)
            return i;
    }
    return -1;
}""",
        "cwe": ["CWE-193"], "language": "c", "category": "off_by_one"
    },
    {
        "func": """void reverse_buffer(char *buf, int len) {
    for (int i = 0; i <= len / 2; i++) {
        char tmp = buf[i];
        buf[i] = buf[len - i];
        buf[len - i] = tmp;
    }
}""",
        "cwe": ["CWE-193"], "language": "c", "category": "off_by_one"
    },

    # ---- Uninitialized Variable (CWE-457) ----
    {
        "func": """int authenticate(const char *pass) {
    int authenticated;
    if (strcmp(pass, get_password()) == 0)
        authenticated = 1;
    return authenticated;
}""",
        "cwe": ["CWE-457"], "language": "c", "category": "uninitialized"
    },
    {
        "func": """void send_packet(int fd) {
    struct packet pkt;
    pkt.type = PKT_DATA;
    pkt.length = 64;
    write(fd, &pkt, sizeof(pkt));
}""",
        "cwe": ["CWE-457"], "language": "c", "category": "uninitialized"
    },
    {
        "func": """char *get_temp_path() {
    char path[256];
    char *tmp = getenv("TMPDIR");
    if (tmp)
        snprintf(path, sizeof(path), "%s/app", tmp);
    return strdup(path);
}""",
        "cwe": ["CWE-457"], "language": "c", "category": "uninitialized"
    },

    # ---- Race Condition / TOCTOU (CWE-367) ----
    {
        "func": """int safe_write(const char *path, const char *data) {
    if (access(path, W_OK) == 0) {
        FILE *f = fopen(path, "w");
        fputs(data, f);
        fclose(f);
        return 0;
    }
    return -1;
}""",
        "cwe": ["CWE-367"], "language": "c", "category": "race_condition"
    },
    {
        "func": """int delete_if_exists(const char *filepath) {
    struct stat st;
    if (stat(filepath, &st) == 0) {
        if (S_ISREG(st.st_mode)) {
            unlink(filepath);
            return 1;
        }
    }
    return 0;
}""",
        "cwe": ["CWE-367"], "language": "c", "category": "race_condition"
    },

    # ---- Heap Overflow (CWE-122) ----
    {
        "func": """void parse_header(const char *raw, int raw_len) {
    char *header = malloc(64);
    memcpy(header, raw, raw_len);
    header[raw_len] = '\\0';
    process(header);
    free(header);
}""",
        "cwe": ["CWE-122"], "language": "c", "category": "heap_overflow"
    },
    {
        "func": """struct user *deserialize_user(const char *data, int len) {
    struct user *u = malloc(sizeof(struct user));
    memcpy(u->name, data, len);
    u->name[len] = '\\0';
    return u;
}""",
        "cwe": ["CWE-122"], "language": "c", "category": "heap_overflow"
    },
    {
        "func": """char *decode_base64(const char *input) {
    int len = strlen(input);
    char *output = malloc(len);
    int out_len = base64_decode(input, len, output, len * 2);
    output[out_len] = '\\0';
    return output;
}""",
        "cwe": ["CWE-122"], "language": "c", "category": "heap_overflow"
    },

    # ---- Hardcoded Credentials (CWE-798) ----
    {
        "func": """int authenticate(const char *username, const char *password) {
    if (strcmp(username, "admin") == 0 && strcmp(password, "s3cr3tP@ss") == 0)
        return 1;
    return 0;
}""",
        "cwe": ["CWE-798"], "language": "c", "category": "hardcoded_credentials"
    },
    {
        "func": """void connect_db(void) {
    const char *host = "db.internal";
    const char *user = "root";
    const char *pass = "rootpassword123";
    db_connect(host, user, pass);
}""",
        "cwe": ["CWE-798"], "language": "c", "category": "hardcoded_credentials"
    },
    {
        "func": """int verify_token(const char *token) {
    const char *SECRET = "hardcoded_jwt_secret_key";
    return jwt_verify(token, SECRET);
}""",
        "cwe": ["CWE-798"], "language": "c", "category": "hardcoded_credentials"
    },

    # ---- Path Traversal (CWE-22) ----
    {
        "func": """void serve_file(const char *filename) {
    char path[512];
    snprintf(path, sizeof(path), "/var/www/files/%s", filename);
    FILE *f = fopen(path, "r");
    if (f) { send_file(f); fclose(f); }
}""",
        "cwe": ["CWE-22"], "language": "c", "category": "path_traversal"
    },
    {
        "func": """int read_config(const char *name) {
    char filepath[256];
    sprintf(filepath, "/etc/app/%s.conf", name);
    return load_config(filepath);
}""",
        "cwe": ["CWE-22"], "language": "c", "category": "path_traversal"
    },
    {
        "func": """void delete_log(const char *logname) {
    char path[512];
    snprintf(path, sizeof(path), "/var/log/app/%s", logname);
    remove(path);
}""",
        "cwe": ["CWE-22"], "language": "c", "category": "path_traversal"
    },

    # ---- Insecure File Permissions (CWE-732) ----
    {
        "func": """void create_temp_file(const char *name) {
    int fd = open(name, O_WRONLY | O_CREAT | O_TRUNC, 0777);
    if (fd >= 0) close(fd);
}""",
        "cwe": ["CWE-732"], "language": "c", "category": "insecure_permissions"
    },
    {
        "func": """int write_credentials(const char *path, const char *creds) {
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    fprintf(f, "%s", creds);
    fclose(f);
    chmod(path, 0666);
    return 0;
}""",
        "cwe": ["CWE-732"], "language": "c", "category": "insecure_permissions"
    },
    {
        "func": """void init_socket_file(const char *sock_path) {
    unlink(sock_path);
    int fd = open(sock_path, O_WRONLY | O_CREAT, 0777);
    close(fd);
}""",
        "cwe": ["CWE-732"], "language": "c", "category": "insecure_permissions"
    },

    # ---- Weak Cryptography (CWE-327) ----
    {
        "func": """void hash_password(const char *password, unsigned char *digest) {
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, password, strlen(password));
    MD5_Final(digest, &ctx);
}""",
        "cwe": ["CWE-327"], "language": "c", "category": "weak_crypto"
    },
    {
        "func": """void encrypt_data(const unsigned char *key, const unsigned char *in,
                   unsigned char *out, int len) {
    DES_key_schedule ks;
    DES_set_key((DES_cblock *)key, &ks);
    DES_ecb_encrypt((DES_cblock *)in, (DES_cblock *)out, &ks, DES_ENCRYPT);
}""",
        "cwe": ["CWE-327"], "language": "c", "category": "weak_crypto"
    },
    {
        "func": """char *sign_data(const char *data) {
    unsigned char digest[20];
    SHA1((unsigned char *)data, strlen(data), digest);
    return base64_encode(digest, 20);
}""",
        "cwe": ["CWE-327"], "language": "c", "category": "weak_crypto"
    },

    # ---- SQL Injection (CWE-89) ----
    {
        "func": """int get_user(sqlite3 *db, const char *username) {
    char query[512];
    snprintf(query, sizeof(query),
             "SELECT * FROM users WHERE name='%s'", username);
    return sqlite3_exec(db, query, NULL, NULL, NULL);
}""",
        "cwe": ["CWE-89"], "language": "c", "category": "sql_injection"
    },
    {
        "func": """void delete_record(sqlite3 *db, const char *id) {
    char sql[256];
    sprintf(sql, "DELETE FROM records WHERE id=%s", id);
    sqlite3_exec(db, sql, 0, 0, 0);
}""",
        "cwe": ["CWE-89"], "language": "c", "category": "sql_injection"
    },
    {
        "func": """int login(sqlite3 *db, const char *user, const char *pass) {
    char buf[512];
    snprintf(buf, sizeof(buf),
             "SELECT id FROM accounts WHERE user='%s' AND pass='%s'", user, pass);
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db, buf, -1, &stmt, NULL);
    return sqlite3_step(stmt) == SQLITE_ROW;
}""",
        "cwe": ["CWE-89"], "language": "c", "category": "sql_injection"
    },
    # ---- SQL Injection — harder patterns ----
    {
        "func": """int search_products(sqlite3 *db, const char *category, int limit) {
    char query[512];
    const char *base = "SELECT id, name, price FROM products WHERE category='";
    char limit_str[16];
    snprintf(limit_str, sizeof(limit_str), "%d", limit);
    strncpy(query, base, sizeof(query));
    strncat(query, category, sizeof(query) - strlen(query) - 1);
    strncat(query, "' LIMIT ", sizeof(query) - strlen(query) - 1);
    strncat(query, limit_str, sizeof(query) - strlen(query) - 1);
    return sqlite3_exec(db, query, NULL, NULL, NULL);
}""",
        "cwe": ["CWE-89"], "language": "c", "category": "sql_injection"
    },
    {
        "func": """void update_profile(sqlite3 *db, int uid, const char *bio) {
    char stmt[768];
    int  n = snprintf(stmt, sizeof(stmt),
                      "UPDATE users SET bio='%s', updated_at=datetime('now') "
                      "WHERE id=%d", bio, uid);
    if (n > 0 && n < (int)sizeof(stmt))
        sqlite3_exec(db, stmt, NULL, NULL, NULL);
}""",
        "cwe": ["CWE-89"], "language": "c", "category": "sql_injection"
    },

    # ---- Out-of-Bounds Write (CWE-787) ----
    {
        "func": """void write_field(struct record *rec, int field_idx, const char *value) {
    int offset = field_idx * FIELD_SIZE;
    memcpy(rec->data + offset, value, strlen(value));
    rec->data[offset + strlen(value)] = '\\0';
}""",
        "cwe": ["CWE-787"], "language": "c", "category": "oob_write"
    },
    {
        "func": """int append_chunk(char *dst, int dst_used, int dst_cap,
                  const char *chunk, int chunk_len) {
    memcpy(dst + dst_used, chunk, chunk_len);
    return dst_used + chunk_len;
}""",
        "cwe": ["CWE-787"], "language": "c", "category": "oob_write"
    },
    {
        "func": """void serialize_items(struct item *items, int count, uint8_t *out) {
    int pos = 0;
    for (int i = 0; i < count; i++) {
        memcpy(out + pos, &items[i], sizeof(struct item));
        pos += sizeof(struct item);
    }
}""",
        "cwe": ["CWE-787"], "language": "c", "category": "oob_write"
    },
    {
        "func": """void build_tlv(uint8_t *buf, uint8_t tag, const uint8_t *val, uint16_t vlen) {
    buf[0] = tag;
    buf[1] = (vlen >> 8) & 0xff;
    buf[2] = vlen & 0xff;
    memcpy(buf + 3, val, vlen);
}""",
        "cwe": ["CWE-787"], "language": "c", "category": "oob_write"
    },

    # ---- Buffer Error / General (CWE-119) ----
    {
        "func": """int parse_config_line(char *line, struct config *cfg) {
    char key[64], value[256];
    sscanf(line, "%s = %s", key, value);
    config_set(cfg, key, value);
    return 0;
}""",
        "cwe": ["CWE-119"], "language": "c", "category": "buffer_error"
    },
    {
        "func": """void read_token(FILE *fp, char *token_out) {
    int c, i = 0;
    while ((c = fgetc(fp)) != EOF && c != ' ' && c != '\\n')
        token_out[i++] = (char)c;
    token_out[i] = '\\0';
}""",
        "cwe": ["CWE-119"], "language": "c", "category": "buffer_error"
    },
    {
        "func": """int decode_base64(const char *in, uint8_t *out) {
    int i = 0, j = 0;
    while (in[i]) {
        out[j++] = base64_decode_char(in[i++]);
        out[j++] = base64_decode_char(in[i++]);
        out[j++] = base64_decode_char(in[i++]);
    }
    return j;
}""",
        "cwe": ["CWE-119"], "language": "c", "category": "buffer_error"
    },

    # ---- Improper Input Validation (CWE-20) ----
    {
        "func": """void set_user_age(struct user *u, const char *age_str) {
    u->age = atoi(age_str);
    update_user(u);
}""",
        "cwe": ["CWE-20"], "language": "c", "category": "input_validation"
    },
    {
        "func": """int resize_pool(struct pool *p, const char *new_size_str) {
    int new_size = atoi(new_size_str);
    p->data = realloc(p->data, new_size * sizeof(void *));
    p->capacity = new_size;
    return 0;
}""",
        "cwe": ["CWE-20"], "language": "c", "category": "input_validation"
    },
    {
        "func": """void set_timeout(struct conn *c, const char *ms_str) {
    c->timeout_ms = strtol(ms_str, NULL, 10);
    apply_timeout(c);
}""",
        "cwe": ["CWE-20"], "language": "c", "category": "input_validation"
    },
    {
        "func": """int jump_to_offset(struct vm *vm, const char *offset_str) {
    int offset = atoi(offset_str);
    vm->pc += offset;
    return execute(vm);
}""",
        "cwe": ["CWE-20"], "language": "c", "category": "input_validation"
    },

    # ---- Resource Exhaustion (CWE-400) ----
    {
        "func": """void handle_upload(int fd, uint32_t claimed_size) {
    char *buf = malloc(claimed_size);
    read(fd, buf, claimed_size);
    process_upload(buf, claimed_size);
    free(buf);
}""",
        "cwe": ["CWE-400"], "language": "c", "category": "resource_exhaustion"
    },
    {
        "func": """int expand_history(struct shell *sh, uint32_t new_entries) {
    sh->history = realloc(sh->history,
                          new_entries * sizeof(struct hist_entry));
    sh->history_cap = new_entries;
    return 0;
}""",
        "cwe": ["CWE-400"], "language": "c", "category": "resource_exhaustion"
    },
    {
        "func": """void cache_response(const char *key, const char *body, uint32_t body_len) {
    struct cache_entry *e = malloc(sizeof(*e) + body_len);
    memcpy(e->data, body, body_len);
    e->size = body_len;
    cache_insert(key, e);
}""",
        "cwe": ["CWE-400"], "language": "c", "category": "resource_exhaustion"
    },
]

# ---------------------------------------------------------------------------
# C SAFE PATTERNS  (target = 0)
# ---------------------------------------------------------------------------
C_SAFE = [
    # ---- Safe Buffer Operations ----
    {
        "func": """void process_input(const char *user_input) {
    char buffer[64];
    strncpy(buffer, user_input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\\0';
    printf("Processed: %s\\n", buffer);
}""",
        "cwe": [], "language": "c", "category": "buffer_safe"
    },
    {
        "func": """void concat_strings(const char *a, const char *b) {
    char result[128];
    snprintf(result, sizeof(result), "%s%s", a, b);
    send_response(result);
}""",
        "cwe": [], "language": "c", "category": "buffer_safe"
    },
    {
        "func": """int read_name(int fd) {
    char name[32];
    ssize_t n = read(fd, name, sizeof(name) - 1);
    if (n < 0) return -1;
    name[n] = '\\0';
    log_user(name);
    return 0;
}""",
        "cwe": [], "language": "c", "category": "buffer_safe"
    },
    {
        "func": """void handle_header(const char *header) {
    char local_buf[100];
    snprintf(local_buf, sizeof(local_buf), "Header: %s", header);
    process_header(local_buf);
}""",
        "cwe": [], "language": "c", "category": "buffer_safe"
    },
    {
        "func": """void copy_payload(const char *src, size_t src_len) {
    char dest[256];
    size_t copy_len = src_len < sizeof(dest) - 1 ? src_len : sizeof(dest) - 1;
    memcpy(dest, src, copy_len);
    dest[copy_len] = '\\0';
    dispatch(dest);
}""",
        "cwe": [], "language": "c", "category": "buffer_safe"
    },
    {
        "func": """void parse_token(const char *token) {
    char parsed[16];
    size_t len = strlen(token);
    if (len >= sizeof(parsed))
        len = sizeof(parsed) - 1;
    memcpy(parsed, token, len);
    parsed[len] = '\\0';
}""",
        "cwe": [], "language": "c", "category": "buffer_safe"
    },
    {
        "func": """void get_env_value(const char *key) {
    char value[64];
    char *env = getenv(key);
    if (env) {
        strncpy(value, env, sizeof(value) - 1);
        value[sizeof(value) - 1] = '\\0';
    } else {
        value[0] = '\\0';
    }
    use_value(value);
}""",
        "cwe": [], "language": "c", "category": "buffer_safe"
    },
    {
        "func": """void receive_message(int sock) {
    char msg[512];
    int len = recv(sock, msg, sizeof(msg) - 1, 0);
    if (len <= 0) return;
    msg[len] = '\\0';
    handle_message(msg);
}""",
        "cwe": [], "language": "c", "category": "buffer_safe"
    },

    # ---- Safe Format Strings ----
    {
        "func": """void log_error(const char *user_msg) {
    char logbuf[256];
    snprintf(logbuf, sizeof(logbuf), "%s", user_msg);
    write_log(logbuf);
}""",
        "cwe": [], "language": "c", "category": "format_safe"
    },
    {
        "func": """void print_status(const char *status) {
    fprintf(stderr, "%s", status);
}""",
        "cwe": [], "language": "c", "category": "format_safe"
    },
    {
        "func": """void debug_print(const char *input) {
    printf("%s", input);
}""",
        "cwe": [], "language": "c", "category": "format_safe"
    },
    {
        "func": """void syslog_message(const char *msg) {
    syslog(LOG_INFO, "%s", msg);
}""",
        "cwe": [], "language": "c", "category": "format_safe"
    },
    {
        "func": """void log_request(const char *method, const char *path) {
    printf("%s %s\\n", method, path);
}""",
        "cwe": [], "language": "c", "category": "format_safe"
    },

    # ---- Safe Memory Management ----
    {
        "func": """char* get_cached_data(int refresh) {
    char *cache = malloc(1024);
    if (!cache) return NULL;
    load_data(cache);
    if (refresh) {
        free(cache);
        cache = malloc(1024);
        if (cache) load_data(cache);
    }
    return cache;
}""",
        "cwe": [], "language": "c", "category": "memory_safe"
    },
    {
        "func": """void process_request(struct request *req) {
    char *method = strdup(req->method);
    char *body = strdup(req->body);
    free(req);
    parse_body(body);
    log_request(method);
    free(method);
    free(body);
}""",
        "cwe": [], "language": "c", "category": "memory_safe"
    },
    {
        "func": """void cleanup_session(struct session *s) {
    char *username = strdup(s->username);
    free(s->token);
    free(s);
    audit_log("Session closed for user: %s", username);
    free(username);
}""",
        "cwe": [], "language": "c", "category": "memory_safe"
    },
    {
        "func": """int handle_connection(int fd) {
    struct conn *c = malloc(sizeof(struct conn));
    if (!c) return -1;
    c->fd = fd;
    if (authenticate(c) < 0) {
        int saved_fd = c->fd;
        free(c);
        return saved_fd;
    }
    return c->fd;
}""",
        "cwe": [], "language": "c", "category": "memory_safe"
    },
    {
        "func": """void update_list(struct node *head) {
    struct node *curr = head;
    while (curr) {
        struct node *next = curr->next;
        if (curr->expired) {
            free(curr);
        } else {
            curr->visited = 1;
        }
        curr = next;
    }
}""",
        "cwe": [], "language": "c", "category": "memory_safe"
    },

    # ---- Safe Double-Free Prevention ----
    {
        "func": """void free_context(struct ctx *c) {
    if (c->buffer) {
        free(c->buffer);
        c->buffer = NULL;
    }
    cleanup_internals(c);
    free(c);
}""",
        "cwe": [], "language": "c", "category": "memory_safe"
    },
    {
        "func": """int release_resources(char *a, char *b) {
    free(a);
    if (a != b)
        free(b);
    return 1;
}""",
        "cwe": [], "language": "c", "category": "memory_safe"
    },

    # ---- Safe Integer Arithmetic ----
    {
        "func": """void *allocate_buffer(size_t count, size_t elem_size) {
    if (count > 0 && elem_size > SIZE_MAX / count)
        return NULL;
    size_t total = count * elem_size;
    return malloc(total);
}""",
        "cwe": [], "language": "c", "category": "integer_safe"
    },
    {
        "func": """char *resize_array(char *old, size_t old_len, size_t add_len) {
    if (add_len > SIZE_MAX - old_len)
        return NULL;
    size_t new_len = old_len + add_len;
    char *new_buf = realloc(old, new_len);
    return new_buf;
}""",
        "cwe": [], "language": "c", "category": "integer_safe"
    },
    {
        "func": """void read_records(int fd, uint16_t num_records) {
    if (num_records > MAX_RECORDS) return;
    size_t buf_size = (size_t)num_records * sizeof(struct record);
    struct record *records = malloc(buf_size);
    if (!records) return;
    ssize_t n = read(fd, records, buf_size);
    if (n == (ssize_t)buf_size)
        process_records(records, num_records);
    free(records);
}""",
        "cwe": [], "language": "c", "category": "integer_safe"
    },

    # ---- Safe Null Checks ----
    {
        "func": """void process_config(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        perror("fopen");
        return;
    }
    char line[256];
    if (fgets(line, sizeof(line), f))
        process_line(line);
    fclose(f);
}""",
        "cwe": [], "language": "c", "category": "null_safe"
    },
    {
        "func": """int get_user_id(const char *username) {
    struct user *u = find_user(username);
    if (!u) return -1;
    return u->id;
}""",
        "cwe": [], "language": "c", "category": "null_safe"
    },
    {
        "func": """void print_result(struct result *r) {
    if (!r || !r->message) {
        printf("No result\\n");
        return;
    }
    printf("Result (%d): %s\\n", (int)strlen(r->message), r->message);
}""",
        "cwe": [], "language": "c", "category": "null_safe"
    },
    {
        "func": """char *lookup_value(struct map *m, const char *key) {
    struct entry *e = map_get(m, key);
    if (!e || !e->value) return NULL;
    return strdup(e->value);
}""",
        "cwe": [], "language": "c", "category": "null_safe"
    },

    # ---- Safe Command Execution ----
    {
        "func": """int check_host(const char *hostname) {
    for (int i = 0; hostname[i]; i++) {
        char c = hostname[i];
        if (!isalnum(c) && c != '.' && c != '-')
            return -1;
    }
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ping -c 1 %s", hostname);
    return system(cmd);
}""",
        "cwe": [], "language": "c", "category": "command_safe"
    },
    {
        "func": """void compress_file(const char *filename) {
    for (int i = 0; filename[i]; i++) {
        if (!isalnum(filename[i]) && filename[i] != '.' && filename[i] != '_' && filename[i] != '-')
            return;
    }
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "gzip -- '%s'", filename);
    system(cmd);
}""",
        "cwe": [], "language": "c", "category": "command_safe"
    },
    {
        "func": """void create_user_dir(const char *username) {
    if (!username || strlen(username) == 0) return;
    for (int i = 0; username[i]; i++) {
        if (!isalnum(username[i]) && username[i] != '_')
            return;
    }
    char path[256];
    snprintf(path, sizeof(path), "/home/%s", username);
    mkdir(path, 0750);
}""",
        "cwe": [], "language": "c", "category": "command_safe"
    },

    # ---- Safe Loop Bounds ----
    {
        "func": """void copy_string(char *dest, const char *src, int max) {
    int i;
    for (i = 0; i < max - 1 && src[i]; i++) {
        dest[i] = src[i];
    }
    dest[i] = '\\0';
}""",
        "cwe": [], "language": "c", "category": "bounds_safe"
    },
    {
        "func": """int find_char(const char *str, char c) {
    int len = strlen(str);
    for (int i = 0; i < len; i++) {
        if (str[i] == c)
            return i;
    }
    return -1;
}""",
        "cwe": [], "language": "c", "category": "bounds_safe"
    },
    {
        "func": """void reverse_buffer(char *buf, int len) {
    for (int i = 0; i < len / 2; i++) {
        char tmp = buf[i];
        buf[i] = buf[len - 1 - i];
        buf[len - 1 - i] = tmp;
    }
}""",
        "cwe": [], "language": "c", "category": "bounds_safe"
    },

    # ---- Safe Initialization ----
    {
        "func": """int authenticate(const char *pass) {
    int authenticated = 0;
    if (strcmp(pass, get_password()) == 0)
        authenticated = 1;
    return authenticated;
}""",
        "cwe": [], "language": "c", "category": "init_safe"
    },
    {
        "func": """void send_packet(int fd) {
    struct packet pkt;
    memset(&pkt, 0, sizeof(pkt));
    pkt.type = PKT_DATA;
    pkt.length = 64;
    write(fd, &pkt, sizeof(pkt));
}""",
        "cwe": [], "language": "c", "category": "init_safe"
    },
    {
        "func": """char *get_temp_path() {
    char path[256] = {0};
    char *tmp = getenv("TMPDIR");
    if (tmp)
        snprintf(path, sizeof(path), "%s/app", tmp);
    else
        snprintf(path, sizeof(path), "/tmp/app");
    return strdup(path);
}""",
        "cwe": [], "language": "c", "category": "init_safe"
    },

    # ---- Safe File Operations ----
    {
        "func": """int safe_write_file(const char *path, const char *data) {
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) return -1;
    write(fd, data, strlen(data));
    close(fd);
    return 0;
}""",
        "cwe": [], "language": "c", "category": "file_safe"
    },
    {
        "func": """int delete_if_exists(const char *filepath) {
    int fd = open(filepath, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return 0;
    struct stat st;
    if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode)) {
        close(fd);
        unlink(filepath);
        return 1;
    }
    close(fd);
    return 0;
}""",
        "cwe": [], "language": "c", "category": "file_safe"
    },

    # ---- Safe Heap Operations ----
    {
        "func": """void parse_header(const char *raw, int raw_len) {
    if (raw_len < 0 || raw_len > 63) return;
    char *header = malloc(64);
    if (!header) return;
    memcpy(header, raw, raw_len);
    header[raw_len] = '\\0';
    process(header);
    free(header);
}""",
        "cwe": [], "language": "c", "category": "heap_safe"
    },
    {
        "func": """struct user *deserialize_user(const char *data, int len) {
    if (len < 0 || (size_t)len >= sizeof(((struct user *)0)->name))
        return NULL;
    struct user *u = malloc(sizeof(struct user));
    if (!u) return NULL;
    memcpy(u->name, data, len);
    u->name[len] = '\\0';
    return u;
}""",
        "cwe": [], "language": "c", "category": "heap_safe"
    },
    {
        "func": """char *decode_base64(const char *input) {
    int len = strlen(input);
    int out_max = (len * 3) / 4 + 1;
    char *output = malloc(out_max + 1);
    if (!output) return NULL;
    int out_len = base64_decode(input, len, output, out_max);
    if (out_len < 0) { free(output); return NULL; }
    output[out_len] = '\\0';
    return output;
}""",
        "cwe": [], "language": "c", "category": "heap_safe"
    },

    # ---- Safe Credential Handling ----
    {
        "func": """int authenticate(const char *username, const char *password) {
    const char *expected_hash = get_stored_hash(username);
    if (!expected_hash) return 0;
    return verify_bcrypt(password, expected_hash);
}""",
        "cwe": [], "language": "c", "category": "credentials_safe"
    },
    {
        "func": """void connect_db(void) {
    const char *host = getenv("DB_HOST");
    const char *user = getenv("DB_USER");
    const char *pass = getenv("DB_PASS");
    if (!host || !user || !pass) { log_error("missing db env vars"); return; }
    db_connect(host, user, pass);
}""",
        "cwe": [], "language": "c", "category": "credentials_safe"
    },

    # ---- Safe Path Handling ----
    {
        "func": """void serve_file(const char *filename) {
    char resolved[PATH_MAX];
    char path[512];
    snprintf(path, sizeof(path), "/var/www/files/%s", filename);
    if (!realpath(path, resolved)) return;
    if (strncmp(resolved, "/var/www/files/", 15) != 0) return;
    FILE *f = fopen(resolved, "r");
    if (f) { send_file(f); fclose(f); }
}""",
        "cwe": [], "language": "c", "category": "path_safe"
    },
    {
        "func": """int read_config(const char *name) {
    for (int i = 0; name[i]; i++) {
        if (!isalnum(name[i]) && name[i] != '_') return -1;
    }
    char filepath[256];
    snprintf(filepath, sizeof(filepath), "/etc/app/%s.conf", name);
    return load_config(filepath);
}""",
        "cwe": [], "language": "c", "category": "path_safe"
    },

    # ---- Safe File Permissions ----
    {
        "func": """void create_temp_file(const char *name) {
    int fd = open(name, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd >= 0) close(fd);
}""",
        "cwe": [], "language": "c", "category": "permissions_safe"
    },
    {
        "func": """int write_credentials(const char *path, const char *creds) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return -1;
    write(fd, creds, strlen(creds));
    close(fd);
    return 0;
}""",
        "cwe": [], "language": "c", "category": "permissions_safe"
    },

    # ---- Safe Cryptography ----
    {
        "func": """void hash_password(const char *password, unsigned char *digest) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, password, strlen(password));
    SHA256_Final(digest, &ctx);
}""",
        "cwe": [], "language": "c", "category": "crypto_safe"
    },
    {
        "func": """void encrypt_data(const unsigned char *key, const unsigned char *in,
                   unsigned char *out, int len) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outl;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, NULL);
    EVP_EncryptUpdate(ctx, out, &outl, in, len);
    EVP_CIPHER_CTX_free(ctx);
}""",
        "cwe": [], "language": "c", "category": "crypto_safe"
    },

    # ---- Safe SQL (parameterized) ----
    {
        "func": """int get_user(sqlite3 *db, const char *username) {
    sqlite3_stmt *stmt;
    const char *query = "SELECT * FROM users WHERE name=?";
    if (sqlite3_prepare_v2(db, query, -1, &stmt, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_ROW ? 1 : 0;
}""",
        "cwe": [], "language": "c", "category": "sql_safe"
    },
    {
        "func": """int login(sqlite3 *db, const char *user, const char *pass) {
    sqlite3_stmt *stmt;
    const char *sql = "SELECT id FROM accounts WHERE user=? AND pass=?";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_text(stmt, 1, user, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, pass, -1, SQLITE_STATIC);
    int found = sqlite3_step(stmt) == SQLITE_ROW;
    sqlite3_finalize(stmt);
    return found;
}""",
        "cwe": [], "language": "c", "category": "sql_safe"
    },

    # ---- Safe: CWE-787 (bounds-checked writes) ----
    {
        "func": """void write_field(struct record *rec, int field_idx, const char *value) {
    if (field_idx < 0 || field_idx >= MAX_FIELDS) return;
    int offset = field_idx * FIELD_SIZE;
    size_t vlen = strnlen(value, FIELD_SIZE - 1);
    memcpy(rec->data + offset, value, vlen);
    rec->data[offset + vlen] = '\\0';
}""",
        "cwe": [], "language": "c", "category": "oob_write_safe"
    },
    {
        "func": """int append_chunk(char *dst, int dst_used, int dst_cap,
                  const char *chunk, int chunk_len) {
    if (chunk_len <= 0 || dst_used + chunk_len > dst_cap) return -1;
    memcpy(dst + dst_used, chunk, chunk_len);
    return dst_used + chunk_len;
}""",
        "cwe": [], "language": "c", "category": "oob_write_safe"
    },

    # ---- Safe: CWE-119 (width-limited parsing) ----
    {
        "func": """int parse_config_line(char *line, struct config *cfg) {
    char key[64], value[256];
    if (sscanf(line, "%63s = %255s", key, value) != 2) return -1;
    config_set(cfg, key, value);
    return 0;
}""",
        "cwe": [], "language": "c", "category": "buffer_error_safe"
    },
    {
        "func": """void read_token(FILE *fp, char *token_out, size_t max_len) {
    int c;
    size_t i = 0;
    while ((c = fgetc(fp)) != EOF && c != ' ' && c != '\\n') {
        if (i + 1 >= max_len) break;
        token_out[i++] = (char)c;
    }
    token_out[i] = '\\0';
}""",
        "cwe": [], "language": "c", "category": "buffer_error_safe"
    },

    # ---- Safe: CWE-20 (validated input) ----
    {
        "func": """int resize_pool(struct pool *p, const char *new_size_str) {
    char *end;
    long new_size = strtol(new_size_str, &end, 10);
    if (*end != '\\0' || new_size <= 0 || new_size > MAX_POOL_SIZE) return -1;
    void *tmp = realloc(p->data, (size_t)new_size * sizeof(void *));
    if (!tmp) return -1;
    p->data = tmp;
    p->capacity = (int)new_size;
    return 0;
}""",
        "cwe": [], "language": "c", "category": "input_validation_safe"
    },
    {
        "func": """void set_user_age(struct user *u, const char *age_str) {
    char *end;
    long age = strtol(age_str, &end, 10);
    if (*end != '\\0' || age < 0 || age > 150) return;
    u->age = (int)age;
    update_user(u);
}""",
        "cwe": [], "language": "c", "category": "input_validation_safe"
    },

    # ---- Safe: CWE-400 (size-capped allocation) ----
    {
        "func": """void handle_upload(int fd, uint32_t claimed_size) {
    if (claimed_size == 0 || claimed_size > MAX_UPLOAD_SIZE) return;
    char *buf = malloc(claimed_size);
    if (!buf) return;
    ssize_t got = read(fd, buf, claimed_size);
    if (got > 0) process_upload(buf, (size_t)got);
    free(buf);
}""",
        "cwe": [], "language": "c", "category": "resource_exhaustion_safe"
    },
    {
        "func": """void cache_response(const char *key, const char *body, uint32_t body_len) {
    if (body_len > MAX_CACHE_ENTRY) return;
    struct cache_entry *e = malloc(sizeof(*e) + body_len);
    if (!e) return;
    memcpy(e->data, body, body_len);
    e->size = body_len;
    cache_insert(key, e);
}""",
        "cwe": [], "language": "c", "category": "resource_exhaustion_safe"
    },
]

# ---------------------------------------------------------------------------
# PYTHON VULNERABLE PATTERNS  (target = 1)
# ---------------------------------------------------------------------------
PYTHON_VULNERABLE = [
    # ---- SQL Injection (CWE-89) ----
    {
        "func": """def get_user(username):
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()""",
        "cwe": ["CWE-89"], "language": "python", "category": "sql_injection"
    },
    {
        "func": """def search_products(keyword):
    sql = f"SELECT * FROM products WHERE name LIKE '%{keyword}%'"
    db.execute(sql)
    return db.fetchall()""",
        "cwe": ["CWE-89"], "language": "python", "category": "sql_injection"
    },
    {
        "func": """def delete_record(table, record_id):
    query = "DELETE FROM %s WHERE id = %s" % (table, record_id)
    cursor.execute(query)
    db.commit()""",
        "cwe": ["CWE-89"], "language": "python", "category": "sql_injection"
    },
    {
        "func": """def authenticate(username, password):
    query = "SELECT id FROM users WHERE username='" + username + "' AND password='" + password + "'"
    result = db.execute(query)
    return result.fetchone() is not None""",
        "cwe": ["CWE-89"], "language": "python", "category": "sql_injection"
    },
    {
        "func": """def update_email(user_id, email):
    sql = f"UPDATE users SET email='{email}' WHERE id={user_id}"
    cursor.execute(sql)
    connection.commit()""",
        "cwe": ["CWE-89"], "language": "python", "category": "sql_injection"
    },
    {
        "func": """def get_orders(status, limit):
    query = "SELECT * FROM orders WHERE status = '{}' LIMIT {}".format(status, limit)
    return db.execute(query).fetchall()""",
        "cwe": ["CWE-89"], "language": "python", "category": "sql_injection"
    },
    # ---- SQL Injection — harder patterns ----
    {
        "func": """def get_report(start_date, end_date, department):
    filters = []
    if department:
        filters.append(f"department = '{department}'")
    filters.append(f"created_at BETWEEN '{start_date}' AND '{end_date}'")
    where = " AND ".join(filters)
    sql = f"SELECT * FROM events WHERE {where} ORDER BY created_at DESC"
    return db.execute(sql).fetchall()""",
        "cwe": ["CWE-89"], "language": "python", "category": "sql_injection"
    },
    {
        "func": """def bulk_update_status(ids, new_status):
    id_list = ", ".join(ids)
    query = f"UPDATE tasks SET status = '{new_status}' WHERE id IN ({id_list})"
    cursor.execute(query)
    db.commit()
    return cursor.rowcount""",
        "cwe": ["CWE-89"], "language": "python", "category": "sql_injection"
    },
    {
        "func": """def find_users(search_term, sort_col, sort_dir):
    allowed_dirs = ("ASC", "DESC")
    direction = sort_dir if sort_dir in allowed_dirs else "ASC"
    sql = ("SELECT id, name, email FROM users "
           f"WHERE name LIKE '%{search_term}%' "
           f"ORDER BY {sort_col} {direction}")
    return conn.execute(sql).fetchall()""",
        "cwe": ["CWE-89"], "language": "python", "category": "sql_injection"
    },

    # ---- Command Injection (CWE-78) ----
    {
        "func": """def ping_host(host):
    import os
    os.system("ping -c 4 " + host)""",
        "cwe": ["CWE-78"], "language": "python", "category": "command_injection"
    },
    {
        "func": """def convert_image(input_path, output_format):
    import subprocess
    cmd = f"convert {input_path} output.{output_format}"
    subprocess.call(cmd, shell=True)""",
        "cwe": ["CWE-78"], "language": "python", "category": "command_injection"
    },
    {
        "func": """def run_diagnostics(target):
    import os
    cmd = "nmap -sV " + target
    output = os.popen(cmd).read()
    return output""",
        "cwe": ["CWE-78"], "language": "python", "category": "command_injection"
    },
    {
        "func": """def backup_database(db_name, dest):
    import subprocess
    cmd = "pg_dump {} > {}".format(db_name, dest)
    subprocess.Popen(cmd, shell=True)""",
        "cwe": ["CWE-78"], "language": "python", "category": "command_injection"
    },
    {
        "func": """def list_files(directory):
    import subprocess
    result = subprocess.check_output("ls -la " + directory, shell=True)
    return result.decode()""",
        "cwe": ["CWE-78"], "language": "python", "category": "command_injection"
    },

    # ---- Command Injection — harder patterns ----
    {
        "func": """def export_report(report_id, output_format, destination):
    import subprocess
    report_path = f"/reports/{report_id}.json"
    cmd = f"report-cli render {report_path} --format {output_format} --out {destination}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.returncode == 0""",
        "cwe": ["CWE-78"], "language": "python", "category": "command_injection"
    },
    {
        "func": """def send_notification(user_email, subject, body_file):
    import os
    cmd = f'mail -s "{subject}" {user_email} < {body_file}'
    os.system(cmd)""",
        "cwe": ["CWE-78"], "language": "python", "category": "command_injection"
    },
    {
        "func": """def resize_image(source, width, height):
    import subprocess
    out_path = source.replace(".jpg", f"_{width}x{height}.jpg")
    subprocess.call(
        f"convert {source} -resize {width}x{height} {out_path}",
        shell=True
    )
    return out_path""",
        "cwe": ["CWE-78"], "language": "python", "category": "command_injection"
    },

    # ---- Path Traversal (CWE-22) ----
    {
        "func": """def read_file(filename):
    filepath = "/var/www/uploads/" + filename
    with open(filepath, "r") as f:
        return f.read()""",
        "cwe": ["CWE-22"], "language": "python", "category": "path_traversal"
    },
    {
        "func": """def serve_static(request):
    path = os.path.join("/static", request.args.get("file"))
    return open(path, "rb").read()""",
        "cwe": ["CWE-22"], "language": "python", "category": "path_traversal"
    },
    {
        "func": """def download_attachment(name):
    base_dir = "/data/attachments/"
    full_path = base_dir + name
    with open(full_path, "rb") as f:
        return f.read()""",
        "cwe": ["CWE-22"], "language": "python", "category": "path_traversal"
    },
    {
        "func": """def get_template(template_name):
    template_dir = "templates/"
    path = template_dir + template_name
    with open(path) as f:
        return f.read()""",
        "cwe": ["CWE-22"], "language": "python", "category": "path_traversal"
    },
    {
        "func": """def load_config(config_name):
    config_path = os.path.join(CONFIG_DIR, config_name)
    with open(config_path) as f:
        return json.load(f)""",
        "cwe": ["CWE-22"], "language": "python", "category": "path_traversal"
    },

    # ---- Deserialization (CWE-502) ----
    {
        "func": """def load_session(data):
    import pickle
    return pickle.loads(data)""",
        "cwe": ["CWE-502"], "language": "python", "category": "deserialization"
    },
    {
        "func": """def restore_object(filepath):
    import pickle
    with open(filepath, "rb") as f:
        return pickle.load(f)""",
        "cwe": ["CWE-502"], "language": "python", "category": "deserialization"
    },
    {
        "func": """def process_message(raw_bytes):
    import pickle
    msg = pickle.loads(raw_bytes)
    handle_message(msg)""",
        "cwe": ["CWE-502"], "language": "python", "category": "deserialization"
    },
    {
        "func": """def load_cache(cache_file):
    import yaml
    with open(cache_file) as f:
        return yaml.load(f)""",
        "cwe": ["CWE-502"], "language": "python", "category": "deserialization"
    },

    # ---- Eval / Exec Injection (CWE-95) ----
    {
        "func": """def calculate(expression):
    return eval(expression)""",
        "cwe": ["CWE-95"], "language": "python", "category": "eval_injection"
    },
    {
        "func": """def dynamic_import(module_name, func_name, args):
    code = f"from {module_name} import {func_name}; result = {func_name}({args})"
    exec(code)
    return result""",
        "cwe": ["CWE-95"], "language": "python", "category": "eval_injection"
    },
    {
        "func": """def apply_filter(data, filter_expr):
    return [item for item in data if eval(filter_expr)]""",
        "cwe": ["CWE-95"], "language": "python", "category": "eval_injection"
    },
    {
        "func": """def run_user_code(code_string):
    local_vars = {}
    exec(code_string, {}, local_vars)
    return local_vars.get("result")""",
        "cwe": ["CWE-95"], "language": "python", "category": "eval_injection"
    },
    {
        "func": """def compute_formula(formula, variables):
    for name, value in variables.items():
        formula = formula.replace(name, str(value))
    return eval(formula)""",
        "cwe": ["CWE-95"], "language": "python", "category": "eval_injection"
    },

    # ---- Hardcoded Credentials (CWE-798) ----
    {
        "func": """def connect_database():
    import mysql.connector
    conn = mysql.connector.connect(
        host="db.internal.company.com",
        user="admin",
        password="SuperSecret123!",
        database="production"
    )
    return conn""",
        "cwe": ["CWE-798"], "language": "python", "category": "hardcoded_creds"
    },
    {
        "func": """def get_api_client():
    API_KEY = "sk-a1b2c3d4e5f6g7h8i9j0"
    headers = {"Authorization": f"Bearer {API_KEY}"}
    return requests.Session(), headers""",
        "cwe": ["CWE-798"], "language": "python", "category": "hardcoded_creds"
    },
    {
        "func": """def send_notification(message):
    SLACK_TOKEN = "FAKE-SLACK-TOKEN-PLACEHOLDER"
    requests.post(
        "https://slack.com/api/chat.postMessage",
        headers={"Authorization": f"Bearer {SLACK_TOKEN}"},
        json={"channel": "#alerts", "text": message}
    )""",
        "cwe": ["CWE-798"], "language": "python", "category": "hardcoded_creds"
    },
    {
        "func": """def encrypt_data(data):
    SECRET_KEY = b"my-secret-key-1234567890123456"
    from Crypto.Cipher import AES
    cipher = AES.new(SECRET_KEY, AES.MODE_ECB)
    return cipher.encrypt(pad(data))""",
        "cwe": ["CWE-798"], "language": "python", "category": "hardcoded_creds"
    },

    # ---- Weak Cryptography (CWE-327) ----
    {
        "func": """def hash_password(password):
    import hashlib
    return hashlib.md5(password.encode()).hexdigest()""",
        "cwe": ["CWE-327"], "language": "python", "category": "weak_crypto"
    },
    {
        "func": """def generate_token(user_id):
    import hashlib
    token = hashlib.sha1(str(user_id).encode()).hexdigest()
    return token""",
        "cwe": ["CWE-327"], "language": "python", "category": "weak_crypto"
    },
    {
        "func": """def create_session_id():
    import random
    return str(random.randint(100000, 999999))""",
        "cwe": ["CWE-330"], "language": "python", "category": "weak_crypto"
    },
    {
        "func": """def encrypt_message(message, key):
    encrypted = bytearray()
    for i, ch in enumerate(message):
        encrypted.append(ord(ch) ^ key[i % len(key)])
    return bytes(encrypted)""",
        "cwe": ["CWE-327"], "language": "python", "category": "weak_crypto"
    },

    # ---- XXE (CWE-611) ----
    {
        "func": """def parse_xml_config(xml_string):
    from lxml import etree
    parser = etree.XMLParser()
    root = etree.fromstring(xml_string, parser)
    return {child.tag: child.text for child in root}""",
        "cwe": ["CWE-611"], "language": "python", "category": "xxe"
    },
    {
        "func": """def process_xml_upload(xml_data):
    import xml.etree.ElementTree as ET
    root = ET.fromstring(xml_data)
    return root.find("data").text""",
        "cwe": ["CWE-611"], "language": "python", "category": "xxe"
    },

    # ---- SSRF (CWE-918) ----
    {
        "func": """def fetch_url(url):
    import requests
    response = requests.get(url)
    return response.text""",
        "cwe": ["CWE-918"], "language": "python", "category": "ssrf"
    },
    {
        "func": """def proxy_request(target_url):
    import urllib.request
    return urllib.request.urlopen(target_url).read().decode()""",
        "cwe": ["CWE-918"], "language": "python", "category": "ssrf"
    },
    {
        "func": """def check_webhook(callback_url, payload):
    import requests
    response = requests.post(callback_url, json=payload, timeout=10)
    return response.status_code""",
        "cwe": ["CWE-918"], "language": "python", "category": "ssrf"
    },

    # ---- Insecure File Permissions (CWE-732) ----
    {
        "func": """def save_credentials(username, token):
    with open("/etc/app/credentials.conf", "w") as f:
        f.write(f"{username}:{token}")
    os.chmod("/etc/app/credentials.conf", 0o777)""",
        "cwe": ["CWE-732"], "language": "python", "category": "insecure_permissions"
    },
    {
        "func": """def write_private_key(key_data, path):
    with open(path, "w") as f:
        f.write(key_data)
    os.chmod(path, 0o644)""",
        "cwe": ["CWE-732"], "language": "python", "category": "insecure_permissions"
    },

    # ---- TOCTOU Race (CWE-367) ----
    {
        "func": """def safe_read(filepath):
    if os.path.exists(filepath):
        if os.path.isfile(filepath):
            with open(filepath) as f:
                return f.read()
    return None""",
        "cwe": ["CWE-367"], "language": "python", "category": "toctou"
    },
    {
        "func": """def process_upload(filepath):
    if os.path.getsize(filepath) < MAX_SIZE:
        with open(filepath, "rb") as f:
            data = f.read()
            return process(data)
    return None""",
        "cwe": ["CWE-367"], "language": "python", "category": "toctou"
    },

    # ---- ReDoS (CWE-1333) ----
    {
        "func": """def validate_email(email):
    import re
    pattern = r"^([a-zA-Z0-9]+\.)*[a-zA-Z0-9]+@([a-zA-Z0-9]+\.)+[a-zA-Z]{2,}$"
    return bool(re.match(pattern, email))""",
        "cwe": ["CWE-1333"], "language": "python", "category": "redos"
    },
    {
        "func": """def parse_user_agent(ua_string):
    import re
    pattern = r"(.*?)\\s*(\\(.*?\\))?\\s*(.*?)$"
    match = re.match(pattern, ua_string)
    return match.groups() if match else None""",
        "cwe": ["CWE-1333"], "language": "python", "category": "redos"
    },

    # ---- Format String / Template Injection (CWE-134) ----
    {
        "func": """def render_greeting(template, username):
    return template % username""",
        "cwe": ["CWE-134"], "language": "python", "category": "format_string"
    },
    {
        "func": """def build_query(table, column, value):
    sql = "SELECT %s FROM %s WHERE id=%s" % (column, table, value)
    return db.execute(sql)""",
        "cwe": ["CWE-134"], "language": "python", "category": "format_string"
    },
    {
        "func": """def log_request(fmt, *args):
    import logging
    logging.warning(fmt % args)""",
        "cwe": ["CWE-134"], "language": "python", "category": "format_string"
    },
    {
        "func": """def format_email(template, user_data):
    from string import Formatter
    return Formatter().vformat(template, [], user_data)""",
        "cwe": ["CWE-134"], "language": "python", "category": "format_string"
    },

    # ---- Improper Input Validation (CWE-20) ----
    {
        "func": """def set_page_size(request, config):
    page_size = int(request.args.get('page_size', 20))
    config['page_size'] = page_size
    return config""",
        "cwe": ["CWE-20"], "language": "python", "category": "input_validation"
    },
    {
        "func": """def move_player(game_state, dx, dy):
    game_state['x'] += int(dx)
    game_state['y'] += int(dy)
    return game_state""",
        "cwe": ["CWE-20"], "language": "python", "category": "input_validation"
    },
    {
        "func": """def apply_discount(cart, discount_str):
    discount = float(discount_str)
    cart['total'] = cart['total'] * (1 - discount)
    return cart""",
        "cwe": ["CWE-20"], "language": "python", "category": "input_validation"
    },

    # ---- Resource Exhaustion (CWE-400) ----
    {
        "func": """def expand_list(items, repeat_count):
    repeat = int(repeat_count)
    return items * repeat""",
        "cwe": ["CWE-400"], "language": "python", "category": "resource_exhaustion"
    },
    {
        "func": """def read_upload(request):
    data = request.body.read()
    return process(data)""",
        "cwe": ["CWE-400"], "language": "python", "category": "resource_exhaustion"
    },
    {
        "func": """def cache_all(db, key_prefix):
    rows = db.execute("SELECT * FROM events").fetchall()
    for row in rows:
        cache.set(f"{key_prefix}:{row['id']}", row)
    return len(rows)""",
        "cwe": ["CWE-400"], "language": "python", "category": "resource_exhaustion"
    },
]

# ---------------------------------------------------------------------------
# PYTHON SAFE PATTERNS  (target = 0)
# ---------------------------------------------------------------------------
PYTHON_SAFE = [
    # ---- Safe SQL ----
    {
        "func": """def get_user(username):
    query = "SELECT * FROM users WHERE name = %s"
    cursor.execute(query, (username,))
    return cursor.fetchone()""",
        "cwe": [], "language": "python", "category": "sql_safe"
    },
    {
        "func": """def search_products(keyword):
    sql = "SELECT * FROM products WHERE name LIKE %s"
    db.execute(sql, (f"%{keyword}%",))
    return db.fetchall()""",
        "cwe": [], "language": "python", "category": "sql_safe"
    },
    {
        "func": """def delete_record(record_id):
    query = "DELETE FROM records WHERE id = %s"
    cursor.execute(query, (record_id,))
    db.commit()""",
        "cwe": [], "language": "python", "category": "sql_safe"
    },
    {
        "func": """def authenticate(username, password):
    query = "SELECT id FROM users WHERE username = %s AND password = %s"
    result = db.execute(query, (username, password))
    return result.fetchone() is not None""",
        "cwe": [], "language": "python", "category": "sql_safe"
    },
    {
        "func": """def update_email(user_id, email):
    sql = "UPDATE users SET email = %s WHERE id = %s"
    cursor.execute(sql, (email, user_id))
    connection.commit()""",
        "cwe": [], "language": "python", "category": "sql_safe"
    },
    {
        "func": """def get_orders(status, limit):
    query = "SELECT * FROM orders WHERE status = %s LIMIT %s"
    return db.execute(query, (status, limit)).fetchall()""",
        "cwe": [], "language": "python", "category": "sql_safe"
    },

    # ---- Safe Command Execution ----
    {
        "func": """def ping_host(host):
    import subprocess
    import re
    if not re.match(r'^[a-zA-Z0-9.\\-]+$', host):
        raise ValueError("Invalid hostname")
    subprocess.run(["ping", "-c", "4", host], check=True)""",
        "cwe": [], "language": "python", "category": "command_safe"
    },
    {
        "func": """def convert_image(input_path, output_format):
    import subprocess
    allowed_formats = {"png", "jpg", "gif", "webp"}
    if output_format not in allowed_formats:
        raise ValueError("Unsupported format")
    subprocess.run(["convert", input_path, f"output.{output_format}"], check=True)""",
        "cwe": [], "language": "python", "category": "command_safe"
    },
    {
        "func": """def backup_database(db_name, dest):
    import subprocess
    import re
    if not re.match(r'^[a-zA-Z0-9_]+$', db_name):
        raise ValueError("Invalid database name")
    subprocess.run(["pg_dump", "-f", dest, db_name], check=True)""",
        "cwe": [], "language": "python", "category": "command_safe"
    },
    {
        "func": """def list_files(directory):
    import os
    entries = os.listdir(directory)
    return entries""",
        "cwe": [], "language": "python", "category": "command_safe"
    },
    {
        "func": """def run_diagnostics(target):
    import subprocess
    import re
    if not re.match(r'^[a-zA-Z0-9.\\-]+$', target):
        raise ValueError("Invalid target")
    result = subprocess.run(["nmap", "-sV", target], capture_output=True, text=True)
    return result.stdout""",
        "cwe": [], "language": "python", "category": "command_safe"
    },

    # ---- Safe Path Handling ----
    {
        "func": """def read_file(filename):
    import os
    base = "/var/www/uploads/"
    filepath = os.path.realpath(os.path.join(base, filename))
    if not filepath.startswith(base):
        raise ValueError("Path traversal detected")
    with open(filepath, "r") as f:
        return f.read()""",
        "cwe": [], "language": "python", "category": "path_safe"
    },
    {
        "func": """def serve_static(request):
    import os
    base_dir = "/static"
    requested = request.args.get("file", "")
    full_path = os.path.realpath(os.path.join(base_dir, requested))
    if not full_path.startswith(os.path.realpath(base_dir)):
        return None
    return open(full_path, "rb").read()""",
        "cwe": [], "language": "python", "category": "path_safe"
    },
    {
        "func": """def download_attachment(name):
    from pathlib import Path
    base_dir = Path("/data/attachments/")
    full_path = (base_dir / name).resolve()
    if not str(full_path).startswith(str(base_dir.resolve())):
        raise ValueError("Invalid path")
    return full_path.read_bytes()""",
        "cwe": [], "language": "python", "category": "path_safe"
    },
    {
        "func": """def get_template(template_name):
    import os
    allowed = {"base.html", "index.html", "about.html", "contact.html"}
    if template_name not in allowed:
        raise ValueError("Unknown template")
    with open(os.path.join("templates", template_name)) as f:
        return f.read()""",
        "cwe": [], "language": "python", "category": "path_safe"
    },
    {
        "func": """def load_config(config_name):
    import os, re, json
    if not re.match(r'^[a-zA-Z0-9_\\-]+\\.json$', config_name):
        raise ValueError("Invalid config name")
    config_path = os.path.join(CONFIG_DIR, config_name)
    with open(config_path) as f:
        return json.load(f)""",
        "cwe": [], "language": "python", "category": "path_safe"
    },

    # ---- Safe Deserialization ----
    {
        "func": """def load_session(data):
    import json
    return json.loads(data)""",
        "cwe": [], "language": "python", "category": "deser_safe"
    },
    {
        "func": """def restore_object(filepath):
    import json
    with open(filepath, "r") as f:
        return json.load(f)""",
        "cwe": [], "language": "python", "category": "deser_safe"
    },
    {
        "func": """def process_message(raw_bytes):
    import json
    msg = json.loads(raw_bytes.decode("utf-8"))
    handle_message(msg)""",
        "cwe": [], "language": "python", "category": "deser_safe"
    },
    {
        "func": """def load_cache(cache_file):
    import yaml
    with open(cache_file) as f:
        return yaml.safe_load(f)""",
        "cwe": [], "language": "python", "category": "deser_safe"
    },

    # ---- Safe Expression Evaluation ----
    {
        "func": """def calculate(expression):
    import ast
    tree = ast.parse(expression, mode="eval")
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Expression, ast.Constant, ast.BinOp,
                                  ast.UnaryOp, ast.Add, ast.Sub, ast.Mult,
                                  ast.Div, ast.Mod, ast.Pow, ast.USub)):
            raise ValueError("Unsafe expression")
    return eval(compile(tree, "<expr>", "eval"))""",
        "cwe": [], "language": "python", "category": "eval_safe"
    },
    {
        "func": """def apply_filter(data, field, value):
    return [item for item in data if item.get(field) == value]""",
        "cwe": [], "language": "python", "category": "eval_safe"
    },
    {
        "func": """def compute_formula(formula, variables):
    import ast
    import operator
    ops = {ast.Add: operator.add, ast.Sub: operator.sub,
           ast.Mult: operator.mul, ast.Div: operator.truediv}
    tree = ast.parse(formula, mode="eval")
    def _eval(node):
        if isinstance(node, ast.Expression):
            return _eval(node.body)
        elif isinstance(node, ast.Constant):
            return node.value
        elif isinstance(node, ast.Name):
            if node.id in variables:
                return variables[node.id]
            raise ValueError(f"Unknown variable: {node.id}")
        elif isinstance(node, ast.BinOp):
            return ops[type(node.op)](_eval(node.left), _eval(node.right))
        raise ValueError("Unsupported expression")
    return _eval(tree)""",
        "cwe": [], "language": "python", "category": "eval_safe"
    },
    {
        "func": """def run_user_code(code_string):
    raise NotImplementedError("Arbitrary code execution is disabled")""",
        "cwe": [], "language": "python", "category": "eval_safe"
    },
    {
        "func": """def dynamic_import(module_name, func_name, args):
    ALLOWED_MODULES = {"math", "statistics", "datetime"}
    if module_name not in ALLOWED_MODULES:
        raise ValueError(f"Module {module_name} not allowed")
    import importlib
    mod = importlib.import_module(module_name)
    fn = getattr(mod, func_name)
    return fn(*args)""",
        "cwe": [], "language": "python", "category": "eval_safe"
    },

    # ---- Safe Credential Handling ----
    {
        "func": """def connect_database():
    import os
    import mysql.connector
    conn = mysql.connector.connect(
        host=os.environ["DB_HOST"],
        user=os.environ["DB_USER"],
        password=os.environ["DB_PASSWORD"],
        database=os.environ["DB_NAME"]
    )
    return conn""",
        "cwe": [], "language": "python", "category": "cred_safe"
    },
    {
        "func": """def get_api_client():
    import os
    api_key = os.environ.get("API_KEY")
    if not api_key:
        raise RuntimeError("API_KEY not configured")
    headers = {"Authorization": f"Bearer {api_key}"}
    return requests.Session(), headers""",
        "cwe": [], "language": "python", "category": "cred_safe"
    },
    {
        "func": """def send_notification(message):
    import os
    token = os.environ["SLACK_TOKEN"]
    requests.post(
        "https://slack.com/api/chat.postMessage",
        headers={"Authorization": f"Bearer {token}"},
        json={"channel": "#alerts", "text": message}
    )""",
        "cwe": [], "language": "python", "category": "cred_safe"
    },
    {
        "func": """def encrypt_data(data):
    import os
    from Crypto.Cipher import AES
    key = os.environ["ENCRYPTION_KEY"].encode()
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(pad(data))
    return cipher.nonce + tag + ciphertext""",
        "cwe": [], "language": "python", "category": "cred_safe"
    },

    # ---- Safe Cryptography ----
    {
        "func": """def hash_password(password):
    import bcrypt
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt)""",
        "cwe": [], "language": "python", "category": "crypto_safe"
    },
    {
        "func": """def generate_token(user_id):
    import secrets
    return secrets.token_urlsafe(32)""",
        "cwe": [], "language": "python", "category": "crypto_safe"
    },
    {
        "func": """def create_session_id():
    import secrets
    return secrets.token_hex(32)""",
        "cwe": [], "language": "python", "category": "crypto_safe"
    },
    {
        "func": """def encrypt_message(message, key):
    from cryptography.fernet import Fernet
    f = Fernet(key)
    return f.encrypt(message.encode())""",
        "cwe": [], "language": "python", "category": "crypto_safe"
    },

    # ---- Safe XML Parsing ----
    {
        "func": """def parse_xml_config(xml_string):
    from defusedxml.ElementTree import fromstring
    root = fromstring(xml_string)
    return {child.tag: child.text for child in root}""",
        "cwe": [], "language": "python", "category": "xml_safe"
    },
    {
        "func": """def process_xml_upload(xml_data):
    from defusedxml import ElementTree as ET
    root = ET.fromstring(xml_data)
    return root.find("data").text""",
        "cwe": [], "language": "python", "category": "xml_safe"
    },

    # ---- Safe URL Fetching ----
    {
        "func": """def fetch_url(url):
    import requests
    from urllib.parse import urlparse
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Invalid scheme")
    BLOCKED = {"localhost", "127.0.0.1", "0.0.0.0", "169.254.169.254"}
    if parsed.hostname in BLOCKED:
        raise ValueError("Blocked host")
    response = requests.get(url, timeout=10)
    return response.text""",
        "cwe": [], "language": "python", "category": "ssrf_safe"
    },
    {
        "func": """def proxy_request(target_url):
    import requests
    from urllib.parse import urlparse
    parsed = urlparse(target_url)
    ALLOWED_HOSTS = {"api.example.com", "cdn.example.com"}
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("Host not allowed")
    return requests.get(target_url, timeout=10).text""",
        "cwe": [], "language": "python", "category": "ssrf_safe"
    },
    {
        "func": """def check_webhook(callback_url, payload):
    import requests
    from urllib.parse import urlparse
    parsed = urlparse(callback_url)
    if parsed.scheme != "https":
        raise ValueError("HTTPS required for webhooks")
    if parsed.hostname.endswith(".internal"):
        raise ValueError("Internal hosts blocked")
    response = requests.post(callback_url, json=payload, timeout=10)
    return response.status_code""",
        "cwe": [], "language": "python", "category": "ssrf_safe"
    },

    # ---- Safe File Permissions ----
    {
        "func": """def save_credentials(username, token):
    import os
    path = "/etc/app/credentials.conf"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(f"{username}:{token}")""",
        "cwe": [], "language": "python", "category": "perm_safe"
    },
    {
        "func": """def write_private_key(key_data, path):
    import os
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(key_data)""",
        "cwe": [], "language": "python", "category": "perm_safe"
    },

    # ---- Safe File Reads (no TOCTOU) ----
    {
        "func": """def safe_read(filepath):
    try:
        with open(filepath) as f:
            return f.read()
    except (FileNotFoundError, PermissionError):
        return None""",
        "cwe": [], "language": "python", "category": "toctou_safe"
    },
    {
        "func": """def process_upload(filepath):
    try:
        with open(filepath, "rb") as f:
            data = f.read(MAX_SIZE)
            if len(data) >= MAX_SIZE:
                raise ValueError("File too large")
            return process(data)
    except FileNotFoundError:
        return None""",
        "cwe": [], "language": "python", "category": "toctou_safe"
    },

    # ---- Safe Regex ----
    {
        "func": """def validate_email(email):
    import re
    if len(email) > 254:
        return False
    pattern = r'^[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))""",
        "cwe": [], "language": "python", "category": "regex_safe"
    },
    {
        "func": """def parse_user_agent(ua_string):
    if len(ua_string) > 512:
        return None
    parts = ua_string.split()
    return parts[0] if parts else None""",
        "cwe": [], "language": "python", "category": "regex_safe"
    },

    # ---- Safe Format String Handling ----
    {
        "func": """def render_greeting(username):
    allowed = {c for c in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_- "}
    if not all(c in allowed for c in username):
        raise ValueError("invalid username")
    return "Hello, {}!".format(username)""",
        "cwe": [], "language": "python", "category": "format_safe"
    },
    {
        "func": """def build_query(table, column, value):
    ALLOWED_TABLES = {"users", "products", "orders"}
    ALLOWED_COLUMNS = {"id", "name", "email"}
    if table not in ALLOWED_TABLES or column not in ALLOWED_COLUMNS:
        raise ValueError("invalid table or column")
    sql = "SELECT {} FROM {} WHERE id = %s".format(column, table)
    return db.execute(sql, (value,))""",
        "cwe": [], "language": "python", "category": "format_safe"
    },
    {
        "func": """def log_request(message, *args):
    import logging
    logging.warning("%s", message % args if args else message)""",
        "cwe": [], "language": "python", "category": "format_safe"
    },
    {
        "func": """def format_email(template_name, user_data):
    TEMPLATES = {
        "welcome": "Hello {name}, welcome to the service!",
        "reset":   "Hi {name}, click the link to reset your password.",
    }
    tmpl = TEMPLATES.get(template_name)
    if tmpl is None:
        raise ValueError("unknown template")
    return tmpl.format(name=str(user_data.get("name", "User")))""",
        "cwe": [], "language": "python", "category": "format_safe"
    },

    # ---- Safe: CWE-20 (validated input) ----
    {
        "func": """def set_page_size(request, config):
    try:
        page_size = int(request.args.get('page_size', 20))
    except (TypeError, ValueError):
        page_size = 20
    config['page_size'] = max(1, min(page_size, 100))
    return config""",
        "cwe": [], "language": "python", "category": "input_validation_safe"
    },
    {
        "func": """def apply_discount(cart, discount_str):
    try:
        discount = float(discount_str)
    except (TypeError, ValueError):
        return cart
    if not (0.0 <= discount <= 1.0):
        raise ValueError('discount must be between 0 and 1')
    cart['total'] = round(cart['total'] * (1 - discount), 2)
    return cart""",
        "cwe": [], "language": "python", "category": "input_validation_safe"
    },

    # ---- Safe: CWE-400 (size-capped operations) ----
    {
        "func": """def expand_list(items, repeat_count):
    repeat = max(0, min(int(repeat_count), 1000))
    return items * repeat""",
        "cwe": [], "language": "python", "category": "resource_exhaustion_safe"
    },
    {
        "func": """def read_upload(request):
    MAX_SIZE = 10 * 1024 * 1024
    data = request.body.read(MAX_SIZE + 1)
    if len(data) > MAX_SIZE:
        raise ValueError('upload too large')
    return process(data)""",
        "cwe": [], "language": "python", "category": "resource_exhaustion_safe"
    },
]


# ---------------------------------------------------------------------------
# JAVA VULNERABLE PATTERNS  (target = 1)
# ---------------------------------------------------------------------------
JAVA_VULNERABLE = [
    # ---- SQL Injection (CWE-89) ----
    {
        "func": """String getUser(Connection conn, String username) throws SQLException {
    Statement stmt = conn.createStatement();
    ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE name='" + username + "'");
    return rs.next() ? rs.getString("name") : null;
}""",
        "cwe": ["CWE-89"], "language": "java", "category": "sql_injection"
    },
    {
        "func": """void deleteRecord(Connection conn, String id) throws SQLException {
    Statement stmt = conn.createStatement();
    stmt.execute("DELETE FROM records WHERE id=" + id);
}""",
        "cwe": ["CWE-89"], "language": "java", "category": "sql_injection"
    },
    {
        "func": """boolean login(Connection conn, String user, String pass) throws SQLException {
    String sql = String.format(
        "SELECT id FROM accounts WHERE user='%s' AND pass='%s'", user, pass);
    Statement stmt = conn.createStatement();
    return stmt.executeQuery(sql).next();
}""",
        "cwe": ["CWE-89"], "language": "java", "category": "sql_injection"
    },
    {
        "func": """List<String> searchProducts(Connection conn, String keyword) throws SQLException {
    Statement stmt = conn.createStatement();
    ResultSet rs = stmt.executeQuery(
        "SELECT name FROM products WHERE name LIKE '%" + keyword + "%'");
    List<String> results = new ArrayList<>();
    while (rs.next()) results.add(rs.getString("name"));
    return results;
}""",
        "cwe": ["CWE-89"], "language": "java", "category": "sql_injection"
    },

    # ---- Command Injection (CWE-78) ----
    {
        "func": """void checkHost(String hostname) throws Exception {
    Runtime.getRuntime().exec("ping -c 1 " + hostname);
}""",
        "cwe": ["CWE-78"], "language": "java", "category": "command_injection"
    },
    {
        "func": """String runDiagnostic(String target) throws Exception {
    Process p = Runtime.getRuntime().exec(
        new String[]{"sh", "-c", "nmap -sV " + target});
    return new String(p.getInputStream().readAllBytes());
}""",
        "cwe": ["CWE-78"], "language": "java", "category": "command_injection"
    },
    {
        "func": """void compressFile(String filename) throws Exception {
    ProcessBuilder pb = new ProcessBuilder("sh", "-c", "gzip " + filename);
    pb.start().waitFor();
}""",
        "cwe": ["CWE-78"], "language": "java", "category": "command_injection"
    },

    # ---- Path Traversal (CWE-22) ----
    {
        "func": """byte[] serveFile(String filename) throws IOException {
    File f = new File("/var/www/files/" + filename);
    return Files.readAllBytes(f.toPath());
}""",
        "cwe": ["CWE-22"], "language": "java", "category": "path_traversal"
    },
    {
        "func": """String loadConfig(String name) throws IOException {
    Path path = Paths.get("/etc/app/" + name + ".conf");
    return Files.readString(path);
}""",
        "cwe": ["CWE-22"], "language": "java", "category": "path_traversal"
    },
    {
        "func": """void deleteLog(String logname) throws IOException {
    new File("/var/log/app/" + logname).delete();
}""",
        "cwe": ["CWE-22"], "language": "java", "category": "path_traversal"
    },

    # ---- Weak Cryptography (CWE-327) ----
    {
        "func": """String hashPassword(String password) throws Exception {
    MessageDigest md = MessageDigest.getInstance("MD5");
    byte[] digest = md.digest(password.getBytes());
    return Base64.getEncoder().encodeToString(digest);
}""",
        "cwe": ["CWE-327"], "language": "java", "category": "weak_crypto"
    },
    {
        "func": """String generateToken(long userId) throws Exception {
    MessageDigest sha = MessageDigest.getInstance("SHA-1");
    byte[] digest = sha.digest(String.valueOf(userId).getBytes());
    return Base64.getEncoder().encodeToString(digest);
}""",
        "cwe": ["CWE-327"], "language": "java", "category": "weak_crypto"
    },
    {
        "func": """byte[] encryptData(byte[] key, byte[] data) throws Exception {
    Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
    SecretKeySpec keySpec = new SecretKeySpec(key, "DES");
    cipher.init(Cipher.ENCRYPT_MODE, keySpec);
    return cipher.doFinal(data);
}""",
        "cwe": ["CWE-327"], "language": "java", "category": "weak_crypto"
    },

    # ---- Format String / Template Injection (CWE-134) ----
    {
        "func": """String renderMessage(String template, Object... args) {
    return MessageFormat.format(template, args);
}""",
        "cwe": ["CWE-134"], "language": "java", "category": "format_string"
    },
    {
        "func": """void logRequest(String format, Object... args) {
    System.out.printf(format, args);
}""",
        "cwe": ["CWE-134"], "language": "java", "category": "format_string"
    },
    {
        "func": """String buildQuery(String table, String column, String value) {
    return String.format("SELECT %s FROM %s WHERE id=%s", column, table, value);
}""",
        "cwe": ["CWE-134"], "language": "java", "category": "format_string"
    },

    # ---- TOCTOU Race Condition (CWE-367) ----
    {
        "func": """boolean writeIfNotExists(String path, String data) throws IOException {
    File f = new File(path);
    if (!f.exists()) {
        Files.writeString(f.toPath(), data);
        return true;
    }
    return false;
}""",
        "cwe": ["CWE-367"], "language": "java", "category": "race_condition"
    },
    {
        "func": """void processUpload(String filepath) throws IOException {
    File f = new File(filepath);
    if (f.length() < MAX_SIZE) {
        byte[] data = Files.readAllBytes(f.toPath());
        process(data);
    }
}""",
        "cwe": ["CWE-367"], "language": "java", "category": "race_condition"
    },

    # ---- Insecure File Permissions (CWE-732) ----
    {
        "func": """void createTempFile(String name) throws IOException {
    File f = new File(name);
    f.createNewFile();
    f.setReadable(true, false);
    f.setWritable(true, false);
}""",
        "cwe": ["CWE-732"], "language": "java", "category": "insecure_permissions"
    },
    {
        "func": """void saveConfig(String path, String content) throws IOException {
    Files.writeString(Paths.get(path), content);
    new File(path).setReadable(true, false);
    new File(path).setWritable(true, false);
}""",
        "cwe": ["CWE-732"], "language": "java", "category": "insecure_permissions"
    },

    # ---- Hardcoded Credentials (CWE-798) ----
    {
        "func": """Connection getConnection() throws SQLException {
    return DriverManager.getConnection(
        "jdbc:mysql://db.internal/prod", "root", "rootpassword123");
}""",
        "cwe": ["CWE-798"], "language": "java", "category": "hardcoded_credentials"
    },
    {
        "func": """boolean verifyUser(String username, String password) {
    return username.equals("admin") && password.equals("admin123!");
}""",
        "cwe": ["CWE-798"], "language": "java", "category": "hardcoded_credentials"
    },
    {
        "func": """String getApiToken() {
    final String API_KEY = "sk-1234567890abcdef";
    return "Bearer " + API_KEY;
}""",
        "cwe": ["CWE-798"], "language": "java", "category": "hardcoded_credentials"
    },
]

# ---------------------------------------------------------------------------
# JAVA SAFE PATTERNS  (target = 0)
# ---------------------------------------------------------------------------
JAVA_SAFE = [
    # ---- Safe SQL ----
    {
        "func": """String getUser(Connection conn, String username) throws SQLException {
    PreparedStatement ps = conn.prepareStatement(
        "SELECT * FROM users WHERE name=?");
    ps.setString(1, username);
    ResultSet rs = ps.executeQuery();
    return rs.next() ? rs.getString("name") : null;
}""",
        "cwe": [], "language": "java", "category": "sql_safe"
    },
    {
        "func": """void deleteRecord(Connection conn, int id) throws SQLException {
    PreparedStatement ps = conn.prepareStatement(
        "DELETE FROM records WHERE id=?");
    ps.setInt(1, id);
    ps.execute();
}""",
        "cwe": [], "language": "java", "category": "sql_safe"
    },
    {
        "func": """boolean login(Connection conn, String user, String pass) throws SQLException {
    PreparedStatement ps = conn.prepareStatement(
        "SELECT id FROM accounts WHERE user=? AND pass=?");
    ps.setString(1, user);
    ps.setString(2, pass);
    return ps.executeQuery().next();
}""",
        "cwe": [], "language": "java", "category": "sql_safe"
    },

    # ---- Safe Commands ----
    {
        "func": """void checkHost(String hostname) throws Exception {
    if (!hostname.matches("[a-zA-Z0-9.\\\\-]+"))
        throw new IllegalArgumentException("Invalid hostname");
    ProcessBuilder pb = new ProcessBuilder("ping", "-c", "1", hostname);
    pb.start().waitFor();
}""",
        "cwe": [], "language": "java", "category": "command_safe"
    },
    {
        "func": """String runDiagnostic(String target) throws Exception {
    if (!target.matches("[a-zA-Z0-9.\\\\-]+"))
        throw new IllegalArgumentException("Invalid target");
    Process p = new ProcessBuilder("nmap", "-sV", target).start();
    return new String(p.getInputStream().readAllBytes());
}""",
        "cwe": [], "language": "java", "category": "command_safe"
    },

    # ---- Safe Paths ----
    {
        "func": """byte[] serveFile(String filename) throws IOException {
    Path base = Paths.get("/var/www/files/").toRealPath();
    Path full = base.resolve(filename).normalize();
    if (!full.startsWith(base))
        throw new SecurityException("Path traversal detected");
    return Files.readAllBytes(full);
}""",
        "cwe": [], "language": "java", "category": "path_safe"
    },
    {
        "func": """String loadConfig(String name) throws IOException {
    if (!name.matches("[a-zA-Z0-9_\\\\-]+"))
        throw new IllegalArgumentException("Invalid config name");
    return Files.readString(Paths.get("/etc/app/" + name + ".conf"));
}""",
        "cwe": [], "language": "java", "category": "path_safe"
    },

    # ---- Safe Cryptography ----
    {
        "func": """String hashPassword(String password) throws Exception {
    byte[] salt = new byte[16];
    new SecureRandom().nextBytes(salt);
    MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
    sha256.update(salt);
    byte[] digest = sha256.digest(password.getBytes(StandardCharsets.UTF_8));
    return Base64.getEncoder().encodeToString(digest);
}""",
        "cwe": [], "language": "java", "category": "crypto_safe"
    },
    {
        "func": """String generateToken(long userId) {
    return UUID.randomUUID().toString().replace("-", "");
}""",
        "cwe": [], "language": "java", "category": "crypto_safe"
    },
    {
        "func": """byte[] encryptData(byte[] key, byte[] data) throws Exception {
    byte[] iv = new byte[12];
    new SecureRandom().nextBytes(iv);
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(Cipher.ENCRYPT_MODE,
        new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
    return cipher.doFinal(data);
}""",
        "cwe": [], "language": "java", "category": "crypto_safe"
    },

    # ---- Safe Format ----
    {
        "func": """String renderMessage(String templateName, String username) {
    Map<String, String> templates = Map.of(
        "welcome", "Hello {0}!",
        "bye",     "Goodbye {0}.");
    String tmpl = templates.get(templateName);
    if (tmpl == null) throw new IllegalArgumentException("Unknown template");
    return MessageFormat.format(tmpl, username);
}""",
        "cwe": [], "language": "java", "category": "format_safe"
    },
    {
        "func": """void logRequest(String method, String path) {
    System.out.printf("%s %s%n", method, path);
}""",
        "cwe": [], "language": "java", "category": "format_safe"
    },

    # ---- Safe File Ops (no TOCTOU) ----
    {
        "func": """boolean writeIfNotExists(String path, String data) throws IOException {
    try {
        Files.writeString(Paths.get(path), data, StandardOpenOption.CREATE_NEW);
        return true;
    } catch (FileAlreadyExistsException e) {
        return false;
    }
}""",
        "cwe": [], "language": "java", "category": "file_safe"
    },
    {
        "func": """void processUpload(String filepath) throws IOException {
    try (InputStream is = Files.newInputStream(Paths.get(filepath))) {
        byte[] data = is.readNBytes(MAX_SIZE);
        if (data.length >= MAX_SIZE) throw new IOException("File too large");
        process(data);
    }
}""",
        "cwe": [], "language": "java", "category": "file_safe"
    },

    # ---- Safe Permissions ----
    {
        "func": """void createTempFile(String name) throws IOException {
    File f = new File(name);
    f.createNewFile();
    f.setReadable(true, true);
    f.setWritable(true, true);
}""",
        "cwe": [], "language": "java", "category": "permissions_safe"
    },
    {
        "func": """void saveConfig(String path, String content) throws IOException {
    Path p = Paths.get(path);
    Files.writeString(p, content);
    Set<PosixFilePermission> perms = PosixFilePermissions.fromString("rw-------");
    Files.setPosixFilePermissions(p, perms);
}""",
        "cwe": [], "language": "java", "category": "permissions_safe"
    },

    # ---- Safe Credentials ----
    {
        "func": """Connection getConnection() throws SQLException {
    String url  = System.getenv("DB_URL");
    String user = System.getenv("DB_USER");
    String pass = System.getenv("DB_PASS");
    if (url == null || user == null || pass == null)
        throw new IllegalStateException("DB env vars not set");
    return DriverManager.getConnection(url, user, pass);
}""",
        "cwe": [], "language": "java", "category": "credentials_safe"
    },
    {
        "func": """boolean verifyUser(String username, String password) {
    String storedHash = getUserHash(username);
    if (storedHash == null) return false;
    return BCrypt.checkpw(password, storedHash);
}""",
        "cwe": [], "language": "java", "category": "credentials_safe"
    },
]

# ---------------------------------------------------------------------------
# JAVASCRIPT VULNERABLE PATTERNS  (target = 1)
# ---------------------------------------------------------------------------
JS_VULNERABLE = [
    # ---- SQL Injection (CWE-89) ----
    {
        "func": """async function getUser(db, username) {
    const result = await db.query(
        "SELECT * FROM users WHERE name='" + username + "'");
    return result.rows[0];
}""",
        "cwe": ["CWE-89"], "language": "javascript", "category": "sql_injection"
    },
    {
        "func": """async function deleteRecord(db, id) {
    await db.query(`DELETE FROM records WHERE id=${id}`);
}""",
        "cwe": ["CWE-89"], "language": "javascript", "category": "sql_injection"
    },
    {
        "func": """async function login(db, user, pass) {
    const sql = `SELECT id FROM accounts WHERE user='${user}' AND pass='${pass}'`;
    const result = await db.query(sql);
    return result.rows.length > 0;
}""",
        "cwe": ["CWE-89"], "language": "javascript", "category": "sql_injection"
    },
    {
        "func": """async function searchProducts(db, keyword) {
    const rows = await db.query(
        "SELECT name FROM products WHERE name LIKE '%" + keyword + "%'");
    return rows;
}""",
        "cwe": ["CWE-89"], "language": "javascript", "category": "sql_injection"
    },

    # ---- Command Injection (CWE-78) ----
    {
        "func": """function pingHost(host) {
    const { exec } = require('child_process');
    exec('ping -c 1 ' + host);
}""",
        "cwe": ["CWE-78"], "language": "javascript", "category": "command_injection"
    },
    {
        "func": """async function runDiagnostic(target) {
    const { exec } = require('child_process');
    return new Promise((resolve) =>
        exec(`nmap -sV ${target}`, (_, out) => resolve(out)));
}""",
        "cwe": ["CWE-78"], "language": "javascript", "category": "command_injection"
    },
    {
        "func": """function compressFile(filename) {
    const { execSync } = require('child_process');
    execSync(`gzip ${filename}`);
}""",
        "cwe": ["CWE-78"], "language": "javascript", "category": "command_injection"
    },

    # ---- Path Traversal (CWE-22) ----
    {
        "func": """function readFile(filename) {
    const fs = require('fs');
    return fs.readFileSync('/var/www/uploads/' + filename, 'utf8');
}""",
        "cwe": ["CWE-22"], "language": "javascript", "category": "path_traversal"
    },
    {
        "func": """function serveStatic(req, res) {
    const fs   = require('fs');
    const path = require('path');
    const filePath = path.join('/static', req.query.file);
    res.send(fs.readFileSync(filePath));
}""",
        "cwe": ["CWE-22"], "language": "javascript", "category": "path_traversal"
    },
    {
        "func": """async function downloadAttachment(name) {
    const fs = require('fs').promises;
    return fs.readFile('/data/attachments/' + name);
}""",
        "cwe": ["CWE-22"], "language": "javascript", "category": "path_traversal"
    },

    # ---- Weak Cryptography (CWE-327) ----
    {
        "func": """function hashPassword(password) {
    const crypto = require('crypto');
    return crypto.createHash('md5').update(password).digest('hex');
}""",
        "cwe": ["CWE-327"], "language": "javascript", "category": "weak_crypto"
    },
    {
        "func": """function generateToken(userId) {
    const crypto = require('crypto');
    return crypto.createHash('sha1').update(String(userId)).digest('hex');
}""",
        "cwe": ["CWE-327"], "language": "javascript", "category": "weak_crypto"
    },
    {
        "func": """function createSessionId() {
    return Math.random().toString(36).substr(2, 16);
}""",
        "cwe": ["CWE-327"], "language": "javascript", "category": "weak_crypto"
    },

    # ---- Template Injection (CWE-134) ----
    {
        "func": """function renderTemplate(template, data) {
    return new Function('data', `return \`${template}\``)(data);
}""",
        "cwe": ["CWE-134"], "language": "javascript", "category": "template_injection"
    },
    {
        "func": """function buildQuery(table, column, value) {
    return `SELECT ${column} FROM ${table} WHERE id=${value}`;
}""",
        "cwe": ["CWE-134"], "language": "javascript", "category": "template_injection"
    },
    {
        "func": """function logRequest(format, ...args) {
    const util = require('util');
    console.log(util.format(format, ...args));
}""",
        "cwe": ["CWE-134"], "language": "javascript", "category": "template_injection"
    },

    # ---- TOCTOU Race Condition (CWE-367) ----
    {
        "func": """function writeIfNotExists(filepath, data) {
    const fs = require('fs');
    if (!fs.existsSync(filepath)) {
        fs.writeFileSync(filepath, data);
        return true;
    }
    return false;
}""",
        "cwe": ["CWE-367"], "language": "javascript", "category": "race_condition"
    },
    {
        "func": """async function processUpload(filepath) {
    const fs   = require('fs').promises;
    const stat = await fs.stat(filepath);
    if (stat.size < MAX_SIZE) {
        const data = await fs.readFile(filepath);
        return process(data);
    }
}""",
        "cwe": ["CWE-367"], "language": "javascript", "category": "race_condition"
    },

    # ---- Insecure File Permissions (CWE-732) ----
    {
        "func": """function createTempFile(name) {
    const fs = require('fs');
    fs.writeFileSync(name, '');
    fs.chmodSync(name, 0o777);
}""",
        "cwe": ["CWE-732"], "language": "javascript", "category": "insecure_permissions"
    },
    {
        "func": """function saveCredentials(path, creds) {
    const fs = require('fs');
    fs.writeFileSync(path, creds);
    fs.chmodSync(path, 0o644);
}""",
        "cwe": ["CWE-732"], "language": "javascript", "category": "insecure_permissions"
    },

    # ---- Hardcoded Credentials (CWE-798) ----
    {
        "func": """function connectDatabase() {
    const mysql = require('mysql2');
    return mysql.createConnection({
        host:     'db.internal',
        user:     'admin',
        password: 'SuperSecret123!',
        database: 'production'
    });
}""",
        "cwe": ["CWE-798"], "language": "javascript", "category": "hardcoded_credentials"
    },
    {
        "func": """function getApiClient() {
    const API_KEY = 'sk-1234567890abcdef';
    return { headers: { 'Authorization': `Bearer ${API_KEY}` } };
}""",
        "cwe": ["CWE-798"], "language": "javascript", "category": "hardcoded_credentials"
    },
    {
        "func": """function verifyToken(token) {
    const jwt = require('jsonwebtoken');
    return jwt.verify(token, 'hardcoded_jwt_secret_key');
}""",
        "cwe": ["CWE-798"], "language": "javascript", "category": "hardcoded_credentials"
    },
]

# ---------------------------------------------------------------------------
# JAVASCRIPT SAFE PATTERNS  (target = 0)
# ---------------------------------------------------------------------------
JS_SAFE = [
    # ---- Safe SQL ----
    {
        "func": """async function getUser(db, username) {
    const result = await db.query(
        "SELECT * FROM users WHERE name=$1", [username]);
    return result.rows[0];
}""",
        "cwe": [], "language": "javascript", "category": "sql_safe"
    },
    {
        "func": """async function deleteRecord(db, id) {
    await db.query("DELETE FROM records WHERE id=$1", [id]);
}""",
        "cwe": [], "language": "javascript", "category": "sql_safe"
    },
    {
        "func": """async function login(db, user, pass) {
    const result = await db.query(
        "SELECT id FROM accounts WHERE user=$1 AND pass=$2", [user, pass]);
    return result.rows.length > 0;
}""",
        "cwe": [], "language": "javascript", "category": "sql_safe"
    },

    # ---- Safe Commands ----
    {
        "func": """function pingHost(host) {
    if (!/^[a-zA-Z0-9.\\-]+$/.test(host))
        throw new Error('Invalid hostname');
    const { spawn } = require('child_process');
    spawn('ping', ['-c', '1', host]);
}""",
        "cwe": [], "language": "javascript", "category": "command_safe"
    },
    {
        "func": """async function runDiagnostic(target) {
    if (!/^[a-zA-Z0-9.\\-]+$/.test(target))
        throw new Error('Invalid target');
    const { spawn } = require('child_process');
    const p = spawn('nmap', ['-sV', target]);
    return new Promise((resolve) => {
        let out = '';
        p.stdout.on('data', (d) => { out += d; });
        p.on('close', () => resolve(out));
    });
}""",
        "cwe": [], "language": "javascript", "category": "command_safe"
    },

    # ---- Safe Paths ----
    {
        "func": """function readFile(filename) {
    const fs   = require('fs');
    const path = require('path');
    const base     = path.resolve('/var/www/uploads/');
    const fullPath = path.resolve(base, filename);
    if (!fullPath.startsWith(base + path.sep))
        throw new Error('Path traversal detected');
    return fs.readFileSync(fullPath, 'utf8');
}""",
        "cwe": [], "language": "javascript", "category": "path_safe"
    },
    {
        "func": """function serveStatic(req, res) {
    const fs   = require('fs');
    const path = require('path');
    const base     = path.resolve('/static');
    const fullPath = path.resolve(base, req.query.file || '');
    if (!fullPath.startsWith(base + path.sep)) {
        res.status(403).send('Forbidden');
        return;
    }
    res.send(fs.readFileSync(fullPath));
}""",
        "cwe": [], "language": "javascript", "category": "path_safe"
    },

    # ---- Safe Cryptography ----
    {
        "func": """async function hashPassword(password) {
    const bcrypt = require('bcrypt');
    return bcrypt.hash(password, 12);
}""",
        "cwe": [], "language": "javascript", "category": "crypto_safe"
    },
    {
        "func": """function generateToken(userId) {
    const crypto = require('crypto');
    return crypto.randomBytes(32).toString('hex');
}""",
        "cwe": [], "language": "javascript", "category": "crypto_safe"
    },
    {
        "func": """function createSessionId() {
    const crypto = require('crypto');
    return crypto.randomUUID();
}""",
        "cwe": [], "language": "javascript", "category": "crypto_safe"
    },

    # ---- Safe Templates ----
    {
        "func": """function renderTemplate(templateName, data) {
    const templates = {
        welcome: 'Hello, {name}!',
        bye:     'Goodbye, {name}!'
    };
    const tmpl = templates[templateName];
    if (!tmpl) throw new Error('Unknown template');
    return tmpl.replace('{name}', String(data.name || ''));
}""",
        "cwe": [], "language": "javascript", "category": "template_safe"
    },
    {
        "func": """function buildQuery(table, column, value, db) {
    const ALLOWED_TABLES   = new Set(['users', 'products']);
    const ALLOWED_COLUMNS  = new Set(['id', 'name']);
    if (!ALLOWED_TABLES.has(table) || !ALLOWED_COLUMNS.has(column))
        throw new Error('Invalid table or column');
    return db.query(`SELECT ${column} FROM ${table} WHERE id=$1`, [value]);
}""",
        "cwe": [], "language": "javascript", "category": "template_safe"
    },

    # ---- Safe File Ops ----
    {
        "func": """function writeIfNotExists(filepath, data) {
    const fs = require('fs');
    try {
        fs.writeFileSync(filepath, data, { flag: 'wx' });
        return true;
    } catch (e) {
        if (e.code === 'EEXIST') return false;
        throw e;
    }
}""",
        "cwe": [], "language": "javascript", "category": "file_safe"
    },
    {
        "func": """async function processUpload(filepath) {
    const fs = require('fs').promises;
    const fd = await fs.open(filepath, 'r');
    try {
        const buf = Buffer.alloc(MAX_SIZE);
        const { bytesRead } = await fd.read(buf, 0, MAX_SIZE);
        if (bytesRead >= MAX_SIZE) throw new Error('File too large');
        return process(buf.slice(0, bytesRead));
    } finally {
        await fd.close();
    }
}""",
        "cwe": [], "language": "javascript", "category": "file_safe"
    },

    # ---- Safe Permissions ----
    {
        "func": """function createTempFile(name) {
    const fs = require('fs');
    fs.writeFileSync(name, '', { mode: 0o600 });
}""",
        "cwe": [], "language": "javascript", "category": "permissions_safe"
    },
    {
        "func": """function saveCredentials(path, creds) {
    const fs = require('fs');
    fs.writeFileSync(path, creds, { mode: 0o600 });
}""",
        "cwe": [], "language": "javascript", "category": "permissions_safe"
    },

    # ---- Safe Credentials ----
    {
        "func": """function connectDatabase() {
    const mysql = require('mysql2');
    return mysql.createConnection({
        host:     process.env.DB_HOST,
        user:     process.env.DB_USER,
        password: process.env.DB_PASS,
        database: process.env.DB_NAME
    });
}""",
        "cwe": [], "language": "javascript", "category": "credentials_safe"
    },
    {
        "func": """function getApiClient() {
    const apiKey = process.env.API_KEY;
    if (!apiKey) throw new Error('API_KEY not configured');
    return { headers: { 'Authorization': `Bearer ${apiKey}` } };
}""",
        "cwe": [], "language": "javascript", "category": "credentials_safe"
    },
]

# ---------------------------------------------------------------------------
# GO VULNERABLE PATTERNS  (target = 1)
# ---------------------------------------------------------------------------
GO_VULNERABLE = [
    # ---- SQL Injection (CWE-89) ----
    {
        "func": """func getUser(db *sql.DB, username string) (string, error) {
    query := "SELECT name FROM users WHERE name='" + username + "'"
    row := db.QueryRow(query)
    var name string
    err := row.Scan(&name)
    return name, err
}""",
        "cwe": ["CWE-89"], "language": "go", "category": "sql_injection"
    },
    {
        "func": """func deleteRecord(db *sql.DB, id string) error {
    _, err := db.Exec("DELETE FROM records WHERE id=" + id)
    return err
}""",
        "cwe": ["CWE-89"], "language": "go", "category": "sql_injection"
    },
    {
        "func": """func login(db *sql.DB, user, pass string) bool {
    query := fmt.Sprintf(
        "SELECT id FROM accounts WHERE user='%s' AND pass='%s'", user, pass)
    row := db.QueryRow(query)
    var id int
    return row.Scan(&id) == nil
}""",
        "cwe": ["CWE-89"], "language": "go", "category": "sql_injection"
    },
    {
        "func": """func searchProducts(db *sql.DB, keyword string) (*sql.Rows, error) {
    return db.Query(
        "SELECT name FROM products WHERE name LIKE '%" + keyword + "%'")
}""",
        "cwe": ["CWE-89"], "language": "go", "category": "sql_injection"
    },

    # ---- Command Injection (CWE-78) ----
    {
        "func": """func checkHost(hostname string) error {
    cmd := exec.Command("sh", "-c", "ping -c 1 "+hostname)
    return cmd.Run()
}""",
        "cwe": ["CWE-78"], "language": "go", "category": "command_injection"
    },
    {
        "func": """func runDiagnostic(target string) (string, error) {
    out, err := exec.Command("sh", "-c", "nmap -sV "+target).Output()
    return string(out), err
}""",
        "cwe": ["CWE-78"], "language": "go", "category": "command_injection"
    },
    {
        "func": """func compressFile(filename string) error {
    cmd := exec.Command("bash", "-c", "gzip "+filename)
    return cmd.Run()
}""",
        "cwe": ["CWE-78"], "language": "go", "category": "command_injection"
    },

    # ---- Path Traversal (CWE-22) ----
    {
        "func": """func serveFile(filename string) ([]byte, error) {
    path := "/var/www/files/" + filename
    return os.ReadFile(path)
}""",
        "cwe": ["CWE-22"], "language": "go", "category": "path_traversal"
    },
    {
        "func": """func loadConfig(name string) ([]byte, error) {
    filepath := fmt.Sprintf("/etc/app/%s.conf", name)
    return os.ReadFile(filepath)
}""",
        "cwe": ["CWE-22"], "language": "go", "category": "path_traversal"
    },
    {
        "func": """func deleteLog(logname string) error {
    return os.Remove("/var/log/app/" + logname)
}""",
        "cwe": ["CWE-22"], "language": "go", "category": "path_traversal"
    },

    # ---- Weak Cryptography (CWE-327) ----
    {
        "func": """func hashPassword(password string) string {
    h := md5.New()
    io.WriteString(h, password)
    return fmt.Sprintf("%x", h.Sum(nil))
}""",
        "cwe": ["CWE-327"], "language": "go", "category": "weak_crypto"
    },
    {
        "func": """func generateToken(userID int64) string {
    h := sha1.New()
    io.WriteString(h, strconv.FormatInt(userID, 10))
    return fmt.Sprintf("%x", h.Sum(nil))
}""",
        "cwe": ["CWE-327"], "language": "go", "category": "weak_crypto"
    },
    {
        "func": """func createSessionID() string {
    return fmt.Sprintf("%d", rand.Int63())
}""",
        "cwe": ["CWE-327"], "language": "go", "category": "weak_crypto"
    },

    # ---- Format String (CWE-134) ----
    {
        "func": """func logRequest(format string, args ...interface{}) {
    fmt.Printf(format, args...)
}""",
        "cwe": ["CWE-134"], "language": "go", "category": "format_string"
    },
    {
        "func": """func renderMessage(template string, name string) string {
    return fmt.Sprintf(template, name)
}""",
        "cwe": ["CWE-134"], "language": "go", "category": "format_string"
    },

    # ---- TOCTOU Race Condition (CWE-367) ----
    {
        "func": """func writeIfNotExists(path, data string) error {
    if _, err := os.Stat(path); os.IsNotExist(err) {
        return os.WriteFile(path, []byte(data), 0644)
    }
    return nil
}""",
        "cwe": ["CWE-367"], "language": "go", "category": "race_condition"
    },
    {
        "func": """func processUpload(filepath string) error {
    info, err := os.Stat(filepath)
    if err != nil {
        return err
    }
    if info.Size() < maxSize {
        data, _ := os.ReadFile(filepath)
        return process(data)
    }
    return nil
}""",
        "cwe": ["CWE-367"], "language": "go", "category": "race_condition"
    },

    # ---- Insecure File Permissions (CWE-732) ----
    {
        "func": """func createTempFile(name string) error {
    f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0777)
    if err != nil {
        return err
    }
    return f.Close()
}""",
        "cwe": ["CWE-732"], "language": "go", "category": "insecure_permissions"
    },
    {
        "func": """func saveCredentials(path, creds string) error {
    return os.WriteFile(path, []byte(creds), 0666)
}""",
        "cwe": ["CWE-732"], "language": "go", "category": "insecure_permissions"
    },

    # ---- Hardcoded Credentials (CWE-798) ----
    {
        "func": """func connectDB() *sql.DB {
    db, _ := sql.Open("mysql", "root:rootpassword123@tcp(db.internal)/prod")
    return db
}""",
        "cwe": ["CWE-798"], "language": "go", "category": "hardcoded_credentials"
    },
    {
        "func": """func verifyToken(token string) bool {
    const secret = "hardcoded_jwt_secret_key"
    return validateJWT(token, secret)
}""",
        "cwe": ["CWE-798"], "language": "go", "category": "hardcoded_credentials"
    },
    {
        "func": """func getAPIKey() string {
    const apiKey = "sk-1234567890abcdef"
    return apiKey
}""",
        "cwe": ["CWE-798"], "language": "go", "category": "hardcoded_credentials"
    },
]

# ---------------------------------------------------------------------------
# GO SAFE PATTERNS  (target = 0)
# ---------------------------------------------------------------------------
GO_SAFE = [
    # ---- Safe SQL ----
    {
        "func": """func getUser(db *sql.DB, username string) (string, error) {
    row := db.QueryRow("SELECT name FROM users WHERE name=?", username)
    var name string
    err := row.Scan(&name)
    return name, err
}""",
        "cwe": [], "language": "go", "category": "sql_safe"
    },
    {
        "func": """func deleteRecord(db *sql.DB, id int) error {
    _, err := db.Exec("DELETE FROM records WHERE id=?", id)
    return err
}""",
        "cwe": [], "language": "go", "category": "sql_safe"
    },
    {
        "func": """func login(db *sql.DB, user, pass string) bool {
    row := db.QueryRow(
        "SELECT id FROM accounts WHERE user=? AND pass=?", user, pass)
    var id int
    return row.Scan(&id) == nil
}""",
        "cwe": [], "language": "go", "category": "sql_safe"
    },

    # ---- Safe Commands ----
    {
        "func": """func checkHost(hostname string) error {
    matched, _ := regexp.MatchString(`^[a-zA-Z0-9.\-]+$`, hostname)
    if !matched {
        return fmt.Errorf("invalid hostname")
    }
    return exec.Command("ping", "-c", "1", hostname).Run()
}""",
        "cwe": [], "language": "go", "category": "command_safe"
    },
    {
        "func": """func runDiagnostic(target string) (string, error) {
    matched, _ := regexp.MatchString(`^[a-zA-Z0-9.\-]+$`, target)
    if !matched {
        return "", fmt.Errorf("invalid target")
    }
    out, err := exec.Command("nmap", "-sV", target).Output()
    return string(out), err
}""",
        "cwe": [], "language": "go", "category": "command_safe"
    },

    # ---- Safe Paths ----
    {
        "func": """func serveFile(filename string) ([]byte, error) {
    base, _ := filepath.Abs("/var/www/files/")
    full, err := filepath.Abs(filepath.Join(base, filename))
    if err != nil || !strings.HasPrefix(full, base+string(os.PathSeparator)) {
        return nil, fmt.Errorf("invalid path")
    }
    return os.ReadFile(full)
}""",
        "cwe": [], "language": "go", "category": "path_safe"
    },
    {
        "func": """func loadConfig(name string) ([]byte, error) {
    matched, _ := regexp.MatchString(`^[a-zA-Z0-9_\-]+$`, name)
    if !matched {
        return nil, fmt.Errorf("invalid config name")
    }
    return os.ReadFile("/etc/app/" + name + ".conf")
}""",
        "cwe": [], "language": "go", "category": "path_safe"
    },

    # ---- Safe Cryptography ----
    {
        "func": """func hashPassword(password string) (string, error) {
    hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    return string(hash), err
}""",
        "cwe": [], "language": "go", "category": "crypto_safe"
    },
    {
        "func": """func generateToken(userID int64) string {
    b := make([]byte, 32)
    cryptorand.Read(b)
    return base64.URLEncoding.EncodeToString(b)
}""",
        "cwe": [], "language": "go", "category": "crypto_safe"
    },
    {
        "func": """func createSessionID() string {
    b := make([]byte, 16)
    cryptorand.Read(b)
    return fmt.Sprintf("%x", b)
}""",
        "cwe": [], "language": "go", "category": "crypto_safe"
    },

    # ---- Safe Format ----
    {
        "func": """func logRequest(method, path string) {
    fmt.Printf("%s %s\\n", method, path)
}""",
        "cwe": [], "language": "go", "category": "format_safe"
    },
    {
        "func": """func renderMessage(templateName, name string) (string, error) {
    templates := map[string]string{
        "welcome": "Hello, %s!",
        "bye":     "Goodbye, %s!",
    }
    tmpl, ok := templates[templateName]
    if !ok {
        return "", fmt.Errorf("unknown template")
    }
    return fmt.Sprintf(tmpl, name), nil
}""",
        "cwe": [], "language": "go", "category": "format_safe"
    },

    # ---- Safe File Ops ----
    {
        "func": """func writeIfNotExists(path, data string) error {
    f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
    if err != nil {
        return err
    }
    _, err = f.WriteString(data)
    f.Close()
    return err
}""",
        "cwe": [], "language": "go", "category": "file_safe"
    },
    {
        "func": """func processUpload(filepath string) error {
    f, err := os.Open(filepath)
    if err != nil {
        return err
    }
    defer f.Close()
    data := make([]byte, maxSize)
    n, _ := f.Read(data)
    if n >= maxSize {
        return fmt.Errorf("file too large")
    }
    return process(data[:n])
}""",
        "cwe": [], "language": "go", "category": "file_safe"
    },

    # ---- Safe Permissions ----
    {
        "func": """func createTempFile(name string) error {
    f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
    if err != nil {
        return err
    }
    return f.Close()
}""",
        "cwe": [], "language": "go", "category": "permissions_safe"
    },
    {
        "func": """func saveCredentials(path, creds string) error {
    return os.WriteFile(path, []byte(creds), 0600)
}""",
        "cwe": [], "language": "go", "category": "permissions_safe"
    },

    # ---- Safe Credentials ----
    {
        "func": """func connectDB() (*sql.DB, error) {
    dsn := os.Getenv("DB_DSN")
    if dsn == "" {
        return nil, fmt.Errorf("DB_DSN not set")
    }
    return sql.Open("mysql", dsn)
}""",
        "cwe": [], "language": "go", "category": "credentials_safe"
    },
    {
        "func": """func verifyToken(token string) (bool, error) {
    secret := os.Getenv("JWT_SECRET")
    if secret == "" {
        return false, fmt.Errorf("JWT_SECRET not configured")
    }
    return validateJWT(token, secret), nil
}""",
        "cwe": [], "language": "go", "category": "credentials_safe"
    },
]


# ---------------------------------------------------------------------------
# VARIATION ENGINE — adds realistic diversity to each sample
# ---------------------------------------------------------------------------

# Variable name pools per language
C_VAR_NAMES = {
    "buffer": ["buffer", "buf", "tmpbuf", "data_buf", "local_buf", "recv_buf", "out_buf"],
    "input": ["input", "user_input", "raw_input", "incoming", "payload", "data"],
    "result": ["result", "output", "retval", "response", "ret"],
    "index": ["i", "j", "idx", "pos", "offset", "cursor"],
    "length": ["len", "length", "sz", "size", "n", "count", "num"],
}

PY_VAR_NAMES = {
    "query": ["query", "sql", "stmt", "sql_query", "statement"],
    "data": ["data", "payload", "content", "body", "raw_data"],
    "result": ["result", "output", "response", "ret", "res"],
    "path": ["path", "filepath", "file_path", "fpath", "full_path"],
}

# Comment pools
C_COMMENTS = [
    "",
    "    /* initialise local state */\n",
    "    /* update internal counters */\n",
    "    /* flush pending writes */\n",
    "    /* propagate to caller */\n",
    "",
    "    /* apply configuration */\n",
    "    /* normalise output */\n",
    "",
    "    /* retry on transient error */\n",
    "",
]

PY_COMMENTS = [
    "",
    "    # initialise local state\n",
    "    # update internal counters\n",
    "    # propagate to caller\n",
    "    # apply configuration\n",
    "",
    "    # normalise output\n",
    "    # retry on transient error\n",
    "",
]

JAVA_COMMENTS = [
    "",
    "    // initialise local state\n",
    "    // update internal counters\n",
    "    // flush pending writes\n",
    "    // propagate to caller\n",
    "",
    "    // apply configuration\n",
    "    // normalise output\n",
    "",
]

JS_COMMENTS = [
    "",
    "    // initialise local state\n",
    "    // update internal counters\n",
    "    // flush pending writes\n",
    "    // propagate to caller\n",
    "",
    "    // apply configuration\n",
    "    // normalise output\n",
    "",
]

GO_COMMENTS = [
    "",
    "\t// initialise local state\n",
    "\t// update internal counters\n",
    "\t// flush pending writes\n",
    "\t// propagate to caller\n",
    "",
    "\t// apply configuration\n",
    "\t// normalise output\n",
    "",
]

_COMMENT_POOLS = {
    "c":          C_COMMENTS,
    "python":     PY_COMMENTS,
    "java":       JAVA_COMMENTS,
    "javascript": JS_COMMENTS,
    "go":         GO_COMMENTS,
}

def wrap_in_context(func_str, language, rng):
    """
    Embed the vulnerable/safe core inside realistic surrounding code.
    Increases function length and nesting depth to closer match real-world code,
    which reduces the synthetic-to-real generalisation gap.
    """

    # ── C context wrappers ───────────────────────────────────────────────────
    if language == "c":
        # Prologue lines inserted at top of function body
        prologues = [
            ["    int status = 0;",
             "    log_debug(\"entering %s\", __func__);"],
            ["    if (!ctx) return -1;",
             "    metrics_inc(\"requests\");"],
            ["    size_t n = 0;",
             "    int rc = 0;",
             "    assert(len > 0);"],
            ["    pthread_mutex_lock(&g_lock);",
             "    int err = 0;"],
            ["    struct timeval tv;",
             "    gettimeofday(&tv, NULL);",
             "    int retval = 0;"],
        ]
        # Epilogue lines inserted before closing brace
        epilogues = [
            ["    return status;"],
            ["    return rc;"],
            ["    return retval;"],
            ["    pthread_mutex_unlock(&g_lock);",
             "    return err;"],
            ["    log_debug(\"done, status=%d\", status);",
             "    return status;"],
        ]
        # Optional conditional wrapper around the core body
        cond_wrappers = [
            ("    if (len > 0) {", "    }"),
            ("    if (ctx->ready) {", "    }"),
            ("    if (flags & FLAG_ENABLED) {", "    }"),
            ("    if (retries < MAX_RETRIES) {", "    }"),
            None, None, None,   # no wrapping most of the time
        ]

        # Extract signature line and body lines
        lines = func_str.split("\n")
        sig_end = next((i for i, l in enumerate(lines) if "{" in l), 0)
        body_lines = lines[sig_end + 1:]
        # Strip closing brace
        if body_lines and body_lines[-1].strip() == "}":
            body_lines = body_lines[:-1]

        prologue = rng.choice(prologues)
        epilogue = rng.choice(epilogues)
        cond     = rng.choice(cond_wrappers)

        new_body = prologue[:]
        if cond:
            new_body.append(cond[0])
            new_body += ["    " + l for l in body_lines]
            new_body.append(cond[1])
        else:
            new_body += body_lines
        new_body += epilogue

        sig = "\n".join(lines[:sig_end + 1])
        return sig + "\n" + "\n".join(new_body) + "\n}"

    # ── Python context wrappers ───────────────────────────────────────────────
    elif language == "python":
        prologues = [
            ["    if not ctx:",
             "        return None",
             "    logger.debug('processing request')"],
            ["    result = None",
             "    try:"],
            ["    metrics.inc('calls')",
             "    if not data:",
             "        raise ValueError('empty input')"],
            ["    start_time = time.monotonic()",
             "    logger.info(f'starting operation')"],
            ["    with db_lock:",
             "        retries = 0"],
        ]
        epilogues = [
            ["    return result"],
            ["    except Exception as e:",
             "        logger.error(f'error: {e}')",
             "        return None"],
            ["    logger.debug('done')",
             "    return result"],
            ["    elapsed = time.monotonic() - start_time",
             "    return result"],
            [],
        ]

        lines = func_str.split("\n")
        # Find the def line and body
        def_idx = next((i for i, l in enumerate(lines) if l.strip().startswith("def ")), 0)
        body_lines = lines[def_idx + 1:]

        prologue = rng.choice(prologues)
        epilogue = rng.choice(epilogues)

        # 30% chance: wrap core in an if block
        if rng.random() < 0.3:
            condition = rng.choice([
                "    if request.method in ('POST', 'PUT'):",
                "    if user.is_authenticated:",
                "    if feature_enabled('processing'):",
                "    if len(data) > 0:",
            ])
            body_lines = [condition] + ["    " + l for l in body_lines]

        new_lines = lines[:def_idx + 1] + prologue + body_lines + epilogue
        return "\n".join(new_lines)

    # ── Other languages — return unchanged ───────────────────────────────────
    return func_str


def make_variation(func_str, language, rng):
    """Apply realistic random variation to make each copy unique and harder to pattern-match."""
    code = func_str

    # ── Variable renaming ────────────────────────────────────────────────────
    # Swap out common placeholder names for realistic alternatives
    if language == "c":
        rename_pool = [
            ("buffer",     rng.choice(["buf", "tmp_buf", "recv_buf", "out_buf", "local_storage", "scratch"])),
            ("user_input", rng.choice(["input", "raw_data", "incoming", "payload", "req_data", "src"])),
            ("result",     rng.choice(["output", "retval", "response", "res", "out"])),
            ("cmd",        rng.choice(["command", "exec_str", "shell_cmd", "cmd_buf", "run_str"])),
            ("filename",   rng.choice(["fname", "file_path", "fpath", "target_file", "name"])),
            ("query",      rng.choice(["sql_str", "stmt", "db_query", "q", "sql_buf"])),
        ]
    elif language == "python":
        rename_pool = [
            ("query",    rng.choice(["sql", "stmt", "sql_query", "statement", "db_stmt"])),
            ("data",     rng.choice(["payload", "content", "body", "raw", "incoming"])),
            ("result",   rng.choice(["output", "response", "ret", "res", "out"])),
            ("path",     rng.choice(["filepath", "fpath", "full_path", "target", "dest"])),
            ("cmd",      rng.choice(["command", "shell_cmd", "exec_str", "run_str"])),
            ("filename", rng.choice(["fname", "file_path", "fpath", "name", "target"])),
        ]
    elif language == "java":
        rename_pool = [
            ("query",    rng.choice(["sqlStr", "stmt", "dbQuery", "sqlQuery", "statement"])),
            ("input",    rng.choice(["userInput", "rawData", "incoming", "payload", "reqData"])),
            ("cmd",      rng.choice(["command", "shellCmd", "execStr", "runStr"])),
            ("path",     rng.choice(["filePath", "fpath", "targetPath", "destPath"])),
        ]
    elif language == "javascript":
        rename_pool = [
            ("query",    rng.choice(["sqlStr", "stmt", "dbQuery", "sqlQuery"])),
            ("input",    rng.choice(["userInput", "rawData", "incoming", "payload"])),
            ("cmd",      rng.choice(["command", "shellCmd", "execStr"])),
            ("path",     rng.choice(["filePath", "fpath", "targetPath"])),
        ]
    else:  # go
        rename_pool = [
            ("query",    rng.choice(["sqlStr", "stmt", "dbQuery", "q"])),
            ("input",    rng.choice(["userInput", "rawData", "incoming", "payload"])),
            ("cmd",      rng.choice(["command", "shellCmd", "execStr"])),
            ("path",     rng.choice(["filePath", "fpath", "targetPath"])),
        ]

    for old_name, new_name in rename_pool:
        if old_name != new_name and rng.random() < 0.5:
            # Whole-word replacement only
            import re as _re
            code = _re.sub(r'\b' + old_name + r'\b', new_name, code)

    # ── Insert neutral comment in the middle of the function body ────────────
    if rng.random() < 0.4:
        comments = _COMMENT_POOLS.get(language, PY_COMMENTS)
        comment = rng.choice([c for c in comments if c.strip()])
        if comment:
            lines = code.split("\n")
            # Insert somewhere after signature, not at the very end
            if len(lines) > 3:
                insert_at = rng.randint(2, max(2, len(lines) - 2))
                lines.insert(insert_at, comment.rstrip("\n"))
                code = "\n".join(lines)

    # ── Insert a dummy logging / metrics call ────────────────────────────────
    dummy_stmts = {
        "c":          ["    log_debug(\"entering function\");",
                       "    metrics_inc(\"calls\");",
                       "    trace_enter();",
                       "    assert(ctx != NULL);"],
        "python":     ["    logger.debug('entering function')",
                       "    metrics.inc('calls')",
                       "    assert ctx is not None",
                       "    logging.debug('processing request')"],
        "java":       ["    log.debug(\"entering method\");",
                       "    metrics.increment(\"calls\");",
                       "    Objects.requireNonNull(ctx);"],
        "javascript": ["    logger.debug('entering function');",
                       "    metrics.inc('calls');",
                       "    console.debug('processing');"],
        "go":         ["\tlog.Debug(\"entering function\")",
                       "\tmetrics.Inc(\"calls\")",
                       "\tdefer metrics.Track()()" ],
    }
    pool = dummy_stmts.get(language, dummy_stmts["python"])
    if rng.random() < 0.35:
        stmt = rng.choice(pool)
        lines = code.split("\n")
        if len(lines) > 2:
            insert_at = rng.randint(1, min(3, len(lines) - 1))
            lines.insert(insert_at, stmt)
            code = "\n".join(lines)

    # ── Whitespace variations ────────────────────────────────────────────────
    if rng.random() < 0.2:
        code = code + "\n"
    if rng.random() < 0.15:
        code = "\n" + code

    # ── Context wrapping (50% chance) — increases length & nesting depth ─────
    if rng.random() < 0.50:
        try:
            code = wrap_in_context(code, language, rng)
        except Exception:
            pass  # keep original if wrapping fails

    return code


# ---------------------------------------------------------------------------
# DATASET GENERATOR
# ---------------------------------------------------------------------------

def generate_dataset(
    output_dir="./Files",
    copies_per_pattern=40,
    train_ratio=0.70,
    valid_ratio=0.15,
    seed=42,
):
    """
    Build the unified multi-language dataset.
    Each base pattern is replicated `copies_per_pattern` times with small
    random variations so the model sees diversity without over-fitting on
    identical strings.
    """
    os.makedirs(output_dir, exist_ok=True)
    rng = random.Random(seed)

    logger.info("=" * 70)
    logger.info("Multi-Language Dataset Creator — C, Python, Java, JavaScript, Go")
    logger.info("=" * 70)

    # ---- Collect base patterns ----
    all_vuln_c      = [(p, "c")          for p in C_VULNERABLE]
    all_safe_c      = [(p, "c")          for p in C_SAFE]
    all_vuln_python = [(p, "python")     for p in PYTHON_VULNERABLE]
    all_safe_python = [(p, "python")     for p in PYTHON_SAFE]
    all_vuln_java   = [(p, "java")       for p in JAVA_VULNERABLE]
    all_safe_java   = [(p, "java")       for p in JAVA_SAFE]
    all_vuln_js     = [(p, "javascript") for p in JS_VULNERABLE]
    all_safe_js     = [(p, "javascript") for p in JS_SAFE]
    all_vuln_go     = [(p, "go")         for p in GO_VULNERABLE]
    all_safe_go     = [(p, "go")         for p in GO_SAFE]

    logger.info(f"Base C patterns          : {len(C_VULNERABLE)} vulnerable, {len(C_SAFE)} safe")
    logger.info(f"Base Python patterns     : {len(PYTHON_VULNERABLE)} vulnerable, {len(PYTHON_SAFE)} safe")
    logger.info(f"Base Java patterns       : {len(JAVA_VULNERABLE)} vulnerable, {len(JAVA_SAFE)} safe")
    logger.info(f"Base JavaScript patterns : {len(JS_VULNERABLE)} vulnerable, {len(JS_SAFE)} safe")
    logger.info(f"Base Go patterns         : {len(GO_VULNERABLE)} vulnerable, {len(GO_SAFE)} safe")
    logger.info(f"Copies per pattern       : {copies_per_pattern}")

    # ---- Expand with variations ----
    samples = []
    uid = 0

    def expand(patterns, target_label, lang_tag):
        nonlocal uid
        count = 0
        for pattern, lang in patterns:
            for copy_idx in range(copies_per_pattern):
                func_text = make_variation(pattern["func"], lang, rng)
                sample = {
                    "func": func_text,
                    "target": target_label,
                    "idx": f"{lang_tag}_{pattern['category']}_{uid}",
                    "language": pattern["language"],
                    "cwe": pattern.get("cwe", []),
                }
                samples.append(sample)
                uid += 1
                count += 1
        return count

    logger.info("")
    logger.info("Expanding patterns with variations …")

    n_vc = expand(all_vuln_c, 1, "c_vuln")
    logger.info(f"  C          vulnerable : {n_vc}")
    n_sc = expand(all_safe_c, 0, "c_safe")
    logger.info(f"  C          safe       : {n_sc}")

    n_vp = expand(all_vuln_python, 1, "py_vuln")
    logger.info(f"  Python     vulnerable : {n_vp}")
    n_sp = expand(all_safe_python, 0, "py_safe")
    logger.info(f"  Python     safe       : {n_sp}")

    n_vj = expand(all_vuln_java, 1, "java_vuln")
    logger.info(f"  Java       vulnerable : {n_vj}")
    n_sj = expand(all_safe_java, 0, "java_safe")
    logger.info(f"  Java       safe       : {n_sj}")

    n_vjs = expand(all_vuln_js, 1, "js_vuln")
    logger.info(f"  JavaScript vulnerable : {n_vjs}")
    n_sjs = expand(all_safe_js, 0, "js_safe")
    logger.info(f"  JavaScript safe       : {n_sjs}")

    n_vg = expand(all_vuln_go, 1, "go_vuln")
    logger.info(f"  Go         vulnerable : {n_vg}")
    n_sg = expand(all_safe_go, 0, "go_safe")
    logger.info(f"  Go         safe       : {n_sg}")

    total = len(samples)
    logger.info(f"\n  Total samples: {total}")

    # ---- Shuffle ----
    rng.shuffle(samples)

    # ---- Split ----
    train_end = int(train_ratio * total)
    valid_end = train_end + int(valid_ratio * total)

    train_data = samples[:train_end]
    valid_data = samples[train_end:valid_end]
    test_data  = samples[valid_end:]

    splits = {
        "multi_lang_train.jsonl": train_data,
        "multi_lang_valid.jsonl": valid_data,
        "multi_lang_test.jsonl":  test_data,
    }

    # ---- Write files ----
    logger.info("")
    logger.info("Writing dataset files …")
    for filename, data in splits.items():
        filepath = os.path.join(output_dir, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            for sample in data:
                json.dump(sample, f, ensure_ascii=False)
                f.write("\n")
        logger.info(f"  {filepath}: {len(data)} samples written")

    # ---- Print detailed statistics ----
    logger.info("")
    logger.info("=" * 70)
    logger.info("DATASET STATISTICS")
    logger.info("=" * 70)

    for filename, data in splits.items():
        vuln_count = sum(1 for d in data if d["target"] == 1)
        safe_count = len(data) - vuln_count
        lang_counter = Counter(d["language"] for d in data)

        logger.info(f"\n--- {filename} ---")
        logger.info(f"  Total       : {len(data)}")
        logger.info(f"  Vulnerable  : {vuln_count} ({vuln_count/len(data)*100:.1f}%)")
        logger.info(f"  Safe        : {safe_count} ({safe_count/len(data)*100:.1f}%)")
        for lang, cnt in sorted(lang_counter.items()):
            logger.info(f"  {lang:<12}: {cnt} ({cnt/len(data)*100:.1f}%)")

        # CWE distribution
        cwe_counter = Counter()
        for d in data:
            for cwe in d.get("cwe", []):
                cwe_counter[cwe] += 1
        if cwe_counter:
            logger.info(f"  CWE distribution (top 10):")
            for cwe, cnt in cwe_counter.most_common(10):
                logger.info(f"    {cwe}: {cnt}")

    logger.info("")
    logger.info("=" * 70)
    logger.info("DONE — dataset files are in: %s", output_dir)
    logger.info("=" * 70)
    logger.info("")
    logger.info("Next step: train your model with:")
    logger.info(
        "  python train.py \\\n"
        "    --train_data_file ./Files/multi_lang_train.jsonl \\\n"
        "    --eval_data_file  ./Files/multi_lang_valid.jsonl \\\n"
        "    --test_data_file  ./Files/multi_lang_test.jsonl  \\\n"
        "    --output_dir ./multi_lang_model \\\n"
        "    --do_train --do_eval --do_test --num_epochs 5 --train_batch_size 16"
    )

    return splits


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    generate_dataset()
