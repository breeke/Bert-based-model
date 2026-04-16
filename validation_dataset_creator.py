"""
validation_dataset_creator.py
==============================
Generates a HELD-OUT validation set with completely independent patterns
from the main training generator.

All patterns here are written from scratch with:
  - Different function names, variable names, coding contexts
  - Different structural complexity (multi-step, conditional, nested)
  - Same CWE categories but expressed in ways the model has never seen
  - Realistic surrounding code to hide the vulnerability

This prevents the model from scoring near 100% on validation simply by
memorising the training generator's templates.

Usage:
    python validation_dataset_creator.py

Output:
    ./Files/held_out_valid.jsonl   (balanced, ~600-800 samples)
"""

import json
import os
import random
import logging
from collections import Counter
from multi_language_dataset_creator import wrap_in_context

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


# ============================================================================
# C — VULNERABLE  (completely new patterns, same CWEs as training)
# ============================================================================

C_VULN = [

    # CWE-120 — Buffer overflow, hidden in a seemingly-safe wrapper
    {
        "func": """int build_greeting(const char *name, char *out) {
    const char *prefix = "Welcome, ";
    int plen = strlen(prefix);
    memcpy(out, prefix, plen);
    strcpy(out + plen, name);
    return plen + strlen(name);
}""",
        "cwe": ["CWE-120"], "language": "c"
    },
    {
        "func": """void log_event(const char *level, const char *msg) {
    char entry[128];
    strncpy(entry, level, sizeof(entry));
    strcat(entry, ": ");
    strcat(entry, msg);
    append_log(entry);
}""",
        "cwe": ["CWE-120"], "language": "c"
    },
    {
        "func": """int pack_fields(char *dst, const char *a, const char *b, const char *c) {
    int n = 0;
    n += sprintf(dst + n, "%s|", a);
    n += sprintf(dst + n, "%s|", b);
    n += sprintf(dst + n, "%s",  c);
    return n;
}""",
        "cwe": ["CWE-120"], "language": "c"
    },
    {
        "func": """void store_username(struct session *s, const char *name) {
    char tmp[32];
    int  i = 0;
    while (name[i] != '\\0') {
        tmp[i] = name[i];
        i++;
    }
    tmp[i] = '\\0';
    memcpy(s->username, tmp, i + 1);
}""",
        "cwe": ["CWE-120"], "language": "c"
    },

    # CWE-416 — Use-after-free, control-flow dependent
    {
        "func": """int write_response(struct conn *c, int status) {
    char *buf = malloc(512);
    format_response(buf, status);
    if (status >= 400) {
        log_error(buf);
        free(buf);
    }
    send_data(c->fd, buf, strlen(buf));
    return status;
}""",
        "cwe": ["CWE-416"], "language": "c"
    },
    {
        "func": """void evict_entry(struct cache *cache, int key) {
    struct entry *e = cache_lookup(cache, key);
    if (e) {
        cache_remove(cache, key);
        free(e);
    }
    if (e && e->refs > 0)
        notify_refs(e);
}""",
        "cwe": ["CWE-416"], "language": "c"
    },
    {
        "func": """struct node *merge_lists(struct node *a, struct node *b) {
    struct node *head = NULL;
    struct node *cur;
    while (a && b) {
        cur = (a->val < b->val) ? a : b;
        if (cur == a) a = a->next;
        else          b = b->next;
        if (cur->deleted) { free(cur); continue; }
        cur->next = head;
        head = cur;
    }
    return head;
}""",
        "cwe": ["CWE-416"], "language": "c"
    },

    # CWE-190 — Integer overflow hidden in allocation
    {
        "func": """void *dup_matrix(int rows, int cols, size_t elem) {
    size_t row_bytes = cols * elem;
    size_t total     = rows * row_bytes;
    void  *mat       = malloc(total);
    return mat;
}""",
        "cwe": ["CWE-190"], "language": "c"
    },
    {
        "func": """char *repeat_str(const char *s, unsigned int times) {
    unsigned int slen  = strlen(s);
    unsigned int total = slen * times + 1;
    char *out = malloc(total);
    for (unsigned int i = 0; i < times; i++)
        memcpy(out + i * slen, s, slen);
    out[total - 1] = '\\0';
    return out;
}""",
        "cwe": ["CWE-190"], "language": "c"
    },

    # CWE-476 — Null deref after missing error check
    {
        "func": """int validate_cert(const char *pem_path) {
    BIO  *bio  = BIO_new_file(pem_path, "r");
    X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    int   days = X509_get_days_until_expiry(cert);
    BIO_free(bio);
    return days;
}""",
        "cwe": ["CWE-476"], "language": "c"
    },
    {
        "func": """void apply_policy(struct user *u, const char *policy_name) {
    struct policy *p = policy_registry_get(policy_name);
    u->flags |= p->required_flags;
    u->level  = p->min_level;
    audit_apply(u->id, policy_name);
}""",
        "cwe": ["CWE-476"], "language": "c"
    },

    # CWE-78 — Command injection buried in helper
    {
        "func": """int verify_checksum(const char *file, const char *expected) {
    char cmd[512];
    char result[64] = {0};
    FILE *fp;
    snprintf(cmd, sizeof(cmd), "sha256sum %s", file);
    fp = popen(cmd, "r");
    fgets(result, sizeof(result), fp);
    pclose(fp);
    return strncmp(result, expected, strlen(expected)) == 0;
}""",
        "cwe": ["CWE-78"], "language": "c"
    },
    {
        "func": """void rotate_logs(const char *service, int keep) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
             "find /var/log/%s -mtime +%d -delete", service, keep);
    system(cmd);
}""",
        "cwe": ["CWE-78"], "language": "c"
    },

    # CWE-89 — SQL injection via multi-step construction
    {
        "func": """int count_records(sqlite3 *db, const char *tbl, const char *col, const char *val) {
    char sql[512];
    int  n = snprintf(sql, sizeof(sql),
                      "SELECT COUNT(*) FROM %s WHERE %s = '%s'", tbl, col, val);
    if (n <= 0) return -1;
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    sqlite3_step(stmt);
    int count = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return count;
}""",
        "cwe": ["CWE-89"], "language": "c"
    },
    {
        "func": """void fetch_audit(sqlite3 *db, const char *from_ts, const char *to_ts, const char *actor) {
    char query[768];
    snprintf(query, sizeof(query),
             "SELECT * FROM audit_log "
             "WHERE ts BETWEEN '%s' AND '%s' "
             "AND actor_id = '%s'",
             from_ts, to_ts, actor);
    sqlite3_exec(db, query, audit_cb, NULL, NULL);
}""",
        "cwe": ["CWE-89"], "language": "c"
    },

    # CWE-134 — Format string, indirect
    {
        "func": """void report_status(int code, char *detail) {
    char msg[512];
    snprintf(msg, sizeof(msg), detail);
    if (code >= 500)
        syslog(LOG_ERR, msg);
    else
        syslog(LOG_INFO, msg);
}""",
        "cwe": ["CWE-134"], "language": "c"
    },
    {
        "func": """void emit_trace(struct ctx *ctx, char *template) {
    if (ctx->trace_enabled)
        fprintf(ctx->trace_fp, template);
}""",
        "cwe": ["CWE-134"], "language": "c"
    },

    # CWE-22 — Path traversal with join logic
    {
        "func": """int open_resource(const char *base, const char *rel_path) {
    char full[512];
    snprintf(full, sizeof(full), "%s/%s", base, rel_path);
    return open(full, O_RDONLY);
}""",
        "cwe": ["CWE-22"], "language": "c"
    },
    {
        "func": """FILE *fetch_asset(const char *asset_name) {
    char path[256];
    snprintf(path, sizeof(path), "/srv/assets/%s", asset_name);
    return fopen(path, "rb");
}""",
        "cwe": ["CWE-22"], "language": "c"
    },

    # CWE-327 — Weak crypto
    {
        "func": """char *hash_token(const char *token) {
    unsigned char digest[16];
    MD5((unsigned char *)token, strlen(token), digest);
    return hex_encode(digest, 16);
}""",
        "cwe": ["CWE-327"], "language": "c"
    },

    # CWE-798 — Hardcoded credentials
    {
        "func": """int connect_db(PGconn **conn) {
    const char *dsn = "host=db.internal user=app password=Sup3rS3cr3t dbname=prod";
    *conn = PQconnectdb(dsn);
    return PQstatus(*conn) == CONNECTION_OK ? 0 : -1;
}""",
        "cwe": ["CWE-798"], "language": "c"
    },
    {
        "func": """CURL *init_api_client(void) {
    CURL *h = curl_easy_init();
    curl_easy_setopt(h, CURLOPT_USERPWD, "service_account:P@ssw0rd123");
    curl_easy_setopt(h, CURLOPT_URL, "https://api.internal/");
    return h;
}""",
        "cwe": ["CWE-798"], "language": "c"
    },

    # CWE-415 — Double free
    {
        "func": """void shutdown_worker(struct worker *w) {
    if (w->stack) free(w->stack);
    drain_queue(w->queue);
    free(w->stack);
    free(w);
}""",
        "cwe": ["CWE-415"], "language": "c"
    },

    # CWE-193 — Off-by-one in loop
    {
        "func": """int count_tokens(const char *str, char delim) {
    int count = 1;
    for (int i = 0; i <= (int)strlen(str); i++) {
        if (str[i] == delim)
            count++;
    }
    return count;
}""",
        "cwe": ["CWE-193"], "language": "c"
    },

    # CWE-367 — TOCTOU race condition (C)
    {
        "func": """int install_binary(const char *src, const char *dst) {
    if (access(src, R_OK) == 0) {
        rename(src, dst);
        chmod(dst, 0755);
        return 0;
    }
    return -1;
}""",
        "cwe": ["CWE-367"], "language": "c"
    },
    {
        "func": """void rotate_log(const char *logpath) {
    struct stat st;
    if (stat(logpath, &st) == 0 && st.st_size > MAX_LOG_SIZE) {
        char backup[256];
        snprintf(backup, sizeof(backup), "%s.bak", logpath);
        link(logpath, backup);
        unlink(logpath);
    }
}""",
        "cwe": ["CWE-367"], "language": "c"
    },
    {
        "func": """int exec_if_safe(const char *path) {
    struct stat st;
    lstat(path, &st);
    if (!S_ISLNK(st.st_mode)) {
        char *argv[] = {(char *)path, NULL};
        execve(path, argv, environ);
    }
    return 0;
}""",
        "cwe": ["CWE-367"], "language": "c"
    },

    # CWE-732 — Insecure file permissions (C)
    {
        "func": """int create_work_dir(const char *path) {
    if (mkdir(path, 0777) != 0)
        return -1;
    return 0;
}""",
        "cwe": ["CWE-732"], "language": "c"
    },
    {
        "func": """int write_pid_file(const char *path) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd < 0) return -1;
    dprintf(fd, "%d\n", getpid());
    close(fd);
    return 0;
}""",
        "cwe": ["CWE-732"], "language": "c"
    },
    {
        "func": """void save_audit_log(const char *entry) {
    umask(0);
    FILE *f = fopen("/var/log/audit.log", "a");
    if (f) {
        fprintf(f, "%s\n", entry);
        fclose(f);
    }
}""",
        "cwe": ["CWE-732"], "language": "c"
    },
]


# ============================================================================
# C — SAFE  (secure versions of the same contexts)
# ============================================================================

C_SAFE = [
    {
        "func": """int build_greeting(const char *name, char *out, size_t out_sz) {
    const char *prefix = "Welcome, ";
    int plen = strlen(prefix);
    if (plen + strlen(name) + 1 > out_sz) return -1;
    memcpy(out, prefix, plen);
    strncpy(out + plen, name, out_sz - plen - 1);
    out[out_sz - 1] = '\\0';
    return plen + strlen(name);
}""",
        "cwe": [], "language": "c"
    },
    {
        "func": """void log_event(const char *level, const char *msg) {
    char entry[128];
    snprintf(entry, sizeof(entry), "%s: %s", level, msg);
    append_log(entry);
}""",
        "cwe": [], "language": "c"
    },
    {
        "func": """int write_response(struct conn *c, int status) {
    char *buf = malloc(512);
    if (!buf) return -1;
    format_response(buf, status);
    if (status >= 400)
        log_error(buf);
    int ret = send_data(c->fd, buf, strlen(buf));
    free(buf);
    return ret;
}""",
        "cwe": [], "language": "c"
    },
    {
        "func": """void *dup_matrix(int rows, int cols, size_t elem) {
    if (rows <= 0 || cols <= 0 || elem == 0) return NULL;
    if ((size_t)cols > SIZE_MAX / elem) return NULL;
    size_t row_bytes = (size_t)cols * elem;
    if ((size_t)rows > SIZE_MAX / row_bytes) return NULL;
    return malloc((size_t)rows * row_bytes);
}""",
        "cwe": [], "language": "c"
    },
    {
        "func": """int verify_checksum(const char *file, const char *expected) {
    unsigned char hash[32];
    if (sha256_file(file, hash) != 0) return -1;
    char hex[65];
    bin2hex(hash, 32, hex);
    return strncmp(hex, expected, 64) == 0;
}""",
        "cwe": [], "language": "c"
    },
    {
        "func": """int count_records(sqlite3 *db, const char *tbl, const char *col, const char *val) {
    const char *sql = "SELECT COUNT(*) FROM items WHERE category = ?";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_text(stmt, 1, val, -1, SQLITE_STATIC);
    sqlite3_step(stmt);
    int count = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return count;
}""",
        "cwe": [], "language": "c"
    },
    {
        "func": """void report_status(int code, char *detail) {
    char msg[512];
    snprintf(msg, sizeof(msg), "%s", detail);
    if (code >= 500)
        syslog(LOG_ERR, "%s", msg);
    else
        syslog(LOG_INFO, "%s", msg);
}""",
        "cwe": [], "language": "c"
    },
    {
        "func": """int open_resource(const char *base, const char *rel_path) {
    char full[512];
    char resolved[512];
    snprintf(full, sizeof(full), "%s/%s", base, rel_path);
    if (!realpath(full, resolved)) return -1;
    if (strncmp(resolved, base, strlen(base)) != 0) return -1;
    return open(resolved, O_RDONLY);
}""",
        "cwe": [], "language": "c"
    },
    {
        "func": """char *hash_token(const char *token) {
    unsigned char digest[32];
    SHA256((unsigned char *)token, strlen(token), digest);
    return hex_encode(digest, 32);
}""",
        "cwe": [], "language": "c"
    },
    {
        "func": """int connect_db(PGconn **conn) {
    const char *host = getenv("DB_HOST");
    const char *user = getenv("DB_USER");
    const char *pass = getenv("DB_PASS");
    if (!host || !user || !pass) return -1;
    char dsn[256];
    snprintf(dsn, sizeof(dsn), "host=%s user=%s password=%s dbname=prod", host, user, pass);
    *conn = PQconnectdb(dsn);
    return PQstatus(*conn) == CONNECTION_OK ? 0 : -1;
}""",
        "cwe": [], "language": "c"
    },
    {
        "func": """void shutdown_worker(struct worker *w) {
    if (w->stack) {
        free(w->stack);
        w->stack = NULL;
    }
    drain_queue(w->queue);
    free(w);
}""",
        "cwe": [], "language": "c"
    },
    {
        "func": """int count_tokens(const char *str, char delim) {
    int count = 1;
    for (int i = 0; i < (int)strlen(str); i++) {
        if (str[i] == delim)
            count++;
    }
    return count;
}""",
        "cwe": [], "language": "c"
    },
    {
        "func": """int validate_cert(const char *pem_path) {
    BIO  *bio  = BIO_new_file(pem_path, "r");
    if (!bio) return -1;
    X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (!cert) { BIO_free(bio); return -1; }
    int days = X509_get_days_until_expiry(cert);
    X509_free(cert);
    BIO_free(bio);
    return days;
}""",
        "cwe": [], "language": "c"
    },
    {
        "func": """void rotate_logs(const char *service, int keep) {
    if (strpbrk(service, ";|&`$(){}\\\\<>") != NULL) return;
    char age_str[16];
    snprintf(age_str, sizeof(age_str), "%d", keep);
    execlp("find", "find", "/var/log", "-name",
           service, "-mtime", age_str, "-delete", NULL);
}""",
        "cwe": [], "language": "c"
    },
]


# ============================================================================
# PYTHON — VULNERABLE  (completely new patterns)
# ============================================================================

PYTHON_VULN = [

    # CWE-89 — SQL injection, different contexts
    {
        "func": """def get_leaderboard(game_id, limit, sort_field):
    sql = (
        "SELECT user_id, score, rank FROM leaderboard "
        f"WHERE game_id = {game_id} "
        f"ORDER BY {sort_field} DESC "
        f"LIMIT {limit}"
    )
    return db.execute(sql).fetchall()""",
        "cwe": ["CWE-89"], "language": "python"
    },
    {
        "func": """def update_preferences(user_id, prefs: dict):
    set_clauses = ", ".join(f"{k} = '{v}'" for k, v in prefs.items())
    sql = f"UPDATE user_prefs SET {set_clauses} WHERE user_id = {user_id}"
    cursor.execute(sql)
    db.commit()""",
        "cwe": ["CWE-89"], "language": "python"
    },
    {
        "func": """def audit_query(table, filters: dict):
    where = " AND ".join(f"{k} = '{v}'" for k, v in filters.items())
    query = f"SELECT * FROM {table} WHERE {where}"
    return conn.execute(query).fetchall()""",
        "cwe": ["CWE-89"], "language": "python"
    },
    {
        "func": """def paginate(model_name, page, per_page, order_col):
    offset = (page - 1) * per_page
    sql = f"SELECT * FROM {model_name} ORDER BY {order_col} LIMIT {per_page} OFFSET {offset}"
    return db.execute(sql).fetchall()""",
        "cwe": ["CWE-89"], "language": "python"
    },

    # CWE-78 — Command injection, new contexts
    {
        "func": """def generate_thumbnail(image_path, size):
    import subprocess
    out = image_path.replace('.jpg', f'_thumb_{size}.jpg')
    subprocess.run(f"ffmpeg -i {image_path} -vf scale={size} {out}", shell=True)
    return out""",
        "cwe": ["CWE-78"], "language": "python"
    },
    {
        "func": """def deploy_artifact(artifact_url, target_env):
    import os
    script = f"deploy.sh {artifact_url} --env {target_env} --force"
    os.system(script)""",
        "cwe": ["CWE-78"], "language": "python"
    },
    {
        "func": """def backup_database(db_name, dest_path):
    import subprocess
    cmd = f"pg_dump {db_name} | gzip > {dest_path}"
    result = subprocess.run(cmd, shell=True, capture_output=True)
    return result.returncode""",
        "cwe": ["CWE-78"], "language": "python"
    },

    # CWE-22 — Path traversal, new contexts
    {
        "func": """def render_template(theme, template_name):
    import os
    path = os.path.join("themes", theme, template_name)
    with open(path) as f:
        return f.read()""",
        "cwe": ["CWE-22"], "language": "python"
    },
    {
        "func": """def export_data(user_id, export_format):
    import os
    filename = f"{user_id}.{export_format}"
    filepath = os.path.join("/exports", filename)
    with open(filepath, "w") as f:
        f.write(get_user_data(user_id))
    return filepath""",
        "cwe": ["CWE-22"], "language": "python"
    },
    {
        "func": """def load_plugin(plugin_name):
    plugin_path = f"plugins/{plugin_name}/main.py"
    with open(plugin_path) as f:
        source = f.read()
    exec(compile(source, plugin_path, 'exec'))""",
        "cwe": ["CWE-22"], "language": "python"
    },

    # CWE-95 — Eval injection
    {
        "func": """def evaluate_formula(formula, context: dict):
    return eval(formula, {"__builtins__": {}}, context)""",
        "cwe": ["CWE-95"], "language": "python"
    },
    {
        "func": """def apply_transform(data, transform_expr):
    result = eval(f"data.{transform_expr}")
    return result""",
        "cwe": ["CWE-95"], "language": "python"
    },

    # CWE-502 — Insecure deserialization
    {
        "func": """def restore_cache(cache_key):
    import pickle, redis
    r = redis.Redis()
    raw = r.get(cache_key)
    return pickle.loads(raw) if raw else None""",
        "cwe": ["CWE-502"], "language": "python"
    },
    {
        "func": """def load_model_state(state_bytes):
    import pickle
    state = pickle.loads(state_bytes)
    model.load_state_dict(state)
    return model""",
        "cwe": ["CWE-502"], "language": "python"
    },

    # CWE-798 — Hardcoded credentials
    {
        "func": """def get_storage_client():
    from google.cloud import storage
    return storage.Client.from_service_account_json(
        key_path="service-account.json",
        project="prod-project"
    )

SECRET_KEY   = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
SMTP_PASS    = "Mailpass#2024"
INTERNAL_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" """,
        "cwe": ["CWE-798"], "language": "python"
    },
    {
        "func": """import psycopg2

def get_connection():
    return psycopg2.connect(
        host="db.company.internal",
        user="analytics",
        password="An4lytics#Prod",
        dbname="warehouse"
    )""",
        "cwe": ["CWE-798"], "language": "python"
    },

    # CWE-327 — Weak crypto
    {
        "func": """def sign_payload(payload: str) -> str:
    import hashlib
    secret = "shared-secret-key"
    sig = hashlib.md5(f"{secret}:{payload}".encode()).hexdigest()
    return f"{payload}.{sig}" """,
        "cwe": ["CWE-327"], "language": "python"
    },
    {
        "func": """def store_password(plaintext: str) -> str:
    import hashlib
    return hashlib.sha1(plaintext.encode()).hexdigest()""",
        "cwe": ["CWE-327"], "language": "python"
    },

    # CWE-134 — Format/template injection
    {
        "func": """def render_notification(template: str, user_data: dict) -> str:
    return template.format(**user_data)""",
        "cwe": ["CWE-134"], "language": "python"
    },
    {
        "func": """from jinja2 import Environment

def build_email(body_template, context):
    env = Environment()
    tmpl = env.from_string(body_template)
    return tmpl.render(**context)""",
        "cwe": ["CWE-134"], "language": "python"
    },

    # CWE-918 — SSRF
    {
        "func": """def fetch_avatar(profile_url):
    import requests
    resp = requests.get(profile_url, timeout=5)
    return resp.content""",
        "cwe": ["CWE-918"], "language": "python"
    },
    {
        "func": """def proxy_request(target_url, headers):
    import urllib.request
    req = urllib.request.Request(target_url, headers=headers)
    with urllib.request.urlopen(req) as r:
        return r.read()""",
        "cwe": ["CWE-918"], "language": "python"
    },

    # CWE-367 — TOCTOU
    {
        "func": """def safe_write(filepath, content):
    import os
    if os.path.exists(filepath):
        raise FileExistsError(f"{filepath} already exists")
    with open(filepath, 'w') as f:
        f.write(content)""",
        "cwe": ["CWE-367"], "language": "python"
    },

    # CWE-732 — Insecure file permissions
    {
        "func": """def write_session_file(session_id, data):
    import os
    path = f"/tmp/sessions/{session_id}"
    with open(path, 'w') as f:
        f.write(data)
    os.chmod(path, 0o777)""",
        "cwe": ["CWE-732"], "language": "python"
    },
]


# ============================================================================
# PYTHON — SAFE
# ============================================================================

PYTHON_SAFE = [
    {
        "func": """def get_leaderboard(game_id, limit, sort_field):
    allowed_fields = {"score", "rank", "created_at"}
    if sort_field not in allowed_fields:
        raise ValueError(f"Invalid sort field: {sort_field}")
    sql = "SELECT user_id, score, rank FROM leaderboard WHERE game_id = ? ORDER BY " + sort_field + " DESC LIMIT ?"
    return db.execute(sql, (game_id, limit)).fetchall()""",
        "cwe": [], "language": "python"
    },
    {
        "func": """def update_preferences(user_id, prefs: dict):
    allowed_keys = {"theme", "language", "notifications"}
    safe_prefs = {k: v for k, v in prefs.items() if k in allowed_keys}
    for key, val in safe_prefs.items():
        cursor.execute(f"UPDATE user_prefs SET {key} = ? WHERE user_id = ?", (val, user_id))
    db.commit()""",
        "cwe": [], "language": "python"
    },
    {
        "func": """def generate_thumbnail(image_path, size):
    import subprocess, shlex, os
    if not os.path.isfile(image_path):
        return None
    out = image_path.replace('.jpg', f'_thumb_{int(size)}.jpg')
    subprocess.run(
        ["ffmpeg", "-i", image_path, "-vf", f"scale={int(size)}", out],
        check=True
    )
    return out""",
        "cwe": [], "language": "python"
    },
    {
        "func": """def render_template(theme, template_name):
    import os
    base = os.path.realpath("themes")
    full = os.path.realpath(os.path.join(base, theme, template_name))
    if not full.startswith(base + os.sep):
        raise PermissionError("Path traversal detected")
    with open(full) as f:
        return f.read()""",
        "cwe": [], "language": "python"
    },
    {
        "func": """def evaluate_formula(formula, context: dict):
    allowed_names = {"abs", "min", "max", "round", "sum"}
    safe_globals = {"__builtins__": {k: __builtins__[k] for k in allowed_names if k in __builtins__}}
    return eval(compile(formula, "<expr>", "eval"), safe_globals, context)""",
        "cwe": [], "language": "python"
    },
    {
        "func": """def restore_cache(cache_key):
    import json, redis
    r = redis.Redis()
    raw = r.get(cache_key)
    return json.loads(raw) if raw else None""",
        "cwe": [], "language": "python"
    },
    {
        "func": """def sign_payload(payload: str) -> str:
    import hmac, hashlib, os
    secret = os.environ["SIGNING_SECRET"].encode()
    sig = hmac.new(secret, payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{sig}" """,
        "cwe": [], "language": "python"
    },
    {
        "func": """def store_password(plaintext: str) -> str:
    import bcrypt
    return bcrypt.hashpw(plaintext.encode(), bcrypt.gensalt()).decode()""",
        "cwe": [], "language": "python"
    },
    {
        "func": """def render_notification(template_str: str, user_data: dict) -> str:
    from string import Template
    allowed_keys = {"name", "date", "amount"}
    safe_data = {k: str(v) for k, v in user_data.items() if k in allowed_keys}
    return Template(template_str).safe_substitute(safe_data)""",
        "cwe": [], "language": "python"
    },
    {
        "func": """def fetch_avatar(profile_url):
    import requests
    from urllib.parse import urlparse
    parsed = urlparse(profile_url)
    if parsed.scheme not in ("http", "https") or parsed.hostname in ("169.254.169.254", "localhost"):
        raise ValueError("Blocked URL")
    resp = requests.get(profile_url, timeout=5)
    return resp.content""",
        "cwe": [], "language": "python"
    },
    {
        "func": """def backup_database(db_name, dest_path):
    import subprocess, os
    if not re.match(r'^[a-zA-Z0-9_]+$', db_name):
        raise ValueError("Invalid database name")
    safe_dest = os.path.realpath(dest_path)
    with open(safe_dest, 'wb') as f:
        subprocess.run(["pg_dump", db_name], stdout=f, check=True)
    return 0""",
        "cwe": [], "language": "python"
    },
    {
        "func": """def safe_write(filepath, content):
    import os
    fd = os.open(filepath, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(content)""",
        "cwe": [], "language": "python"
    },
    {
        "func": """def write_session_file(session_id, data):
    import os, re
    if not re.match(r'^[a-f0-9]{32}$', session_id):
        raise ValueError("Invalid session ID")
    path = f"/tmp/sessions/{session_id}"
    fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(data)""",
        "cwe": [], "language": "python"
    },
    {
        "func": """def get_connection():
    import os, psycopg2
    return psycopg2.connect(
        host=os.environ["DB_HOST"],
        user=os.environ["DB_USER"],
        password=os.environ["DB_PASS"],
        dbname=os.environ["DB_NAME"]
    )""",
        "cwe": [], "language": "python"
    },
]


# ============================================================================
# Variation engine — lighter than training, just enough to avoid exact dupes
# ============================================================================

C_DUMMY = [
    "    assert(ctx != NULL);",
    "    log_debug(\"entering\");",
    "    metrics_inc(\"calls\");",
    "    trace_start();",
]

PY_DUMMY = [
    "    logger.debug('entering')",
    "    metrics.inc('calls')",
    "    assert ctx is not None",
]

def make_variation(func_str, language, rng):
    code = func_str

    # Light variable renaming
    if language == "c":
        swaps = [("buf", rng.choice(["tbuf", "out_buf", "local_buf", "scratch_buf"])),
                 ("sql", rng.choice(["stmt", "query_str", "db_stmt"])),
                 ("cmd", rng.choice(["command", "shell_cmd", "exec_buf"]))]
    else:
        swaps = [("sql",  rng.choice(["stmt", "query_str", "db_stmt"])),
                 ("cmd",  rng.choice(["command", "shell_cmd"])),
                 ("path", rng.choice(["filepath", "dest_path", "fpath"]))]

    import re as _re
    for old, new in swaps:
        if rng.random() < 0.4:
            code = _re.sub(r'\b' + old + r'\b', new, code)

    # Insert one dummy statement
    pool = C_DUMMY if language == "c" else PY_DUMMY
    if rng.random() < 0.3:
        stmt = rng.choice(pool)
        lines = code.split("\n")
        if len(lines) > 2:
            pos = rng.randint(1, min(3, len(lines) - 1))
            lines.insert(pos, stmt)
            code = "\n".join(lines)

    # Minor whitespace
    if rng.random() < 0.15:
        code = "\n" + code

    return code


# ============================================================================
# Generator
# ============================================================================

def generate(output_dir="./Files", copies=15, seed=99):
    """
    Generates:
      held_out_valid.jsonl         — combined C + Python
      held_out_c_valid.jsonl       — C only
      held_out_python_valid.jsonl  — Python only

    Uses seed=99 (training uses seed=42) and copies=15 (training uses 40)
    to ensure maximum divergence from training data.
    """
    os.makedirs(output_dir, exist_ok=True)
    rng = random.Random(seed)
    uid = 0

    c_samples      = []
    python_samples = []

    def expand(patterns, label, bucket):
        nonlocal uid
        for p in patterns:
            for _ in range(copies):
                code = make_variation(p["func"], p["language"], rng)
                if random.random() < 0.5:
                    code = wrap_in_context(code, p["language"], rng)
                bucket.append({
                    "func":     code,
                    "target":   label,
                    "idx":      f"hov_{uid}",
                    "language": p["language"],
                    "cwe":      p.get("cwe", []),
                })
                uid += 1

    expand(C_VULN,      1, c_samples)
    expand(C_SAFE,      0, c_samples)
    expand(PYTHON_VULN, 1, python_samples)
    expand(PYTHON_SAFE, 0, python_samples)

    rng.shuffle(c_samples)
    rng.shuffle(python_samples)
    all_samples = c_samples + python_samples
    rng.shuffle(all_samples)

    def write_file(samples, filename):
        path = os.path.join(output_dir, filename)
        with open(path, "w", encoding="utf-8") as f:
            for s in samples:
                json.dump(s, f, ensure_ascii=False)
                f.write("\n")
        total = len(samples)
        vuln  = sum(1 for s in samples if s["target"] == 1)
        cwes  = Counter(c for s in samples for c in s["cwe"])
        logger.info(f"Written {total} samples to {path}")
        logger.info(f"  Vulnerable : {vuln} ({vuln/total*100:.1f}%)")
        logger.info(f"  Safe       : {total-vuln} ({(total-vuln)/total*100:.1f}%)")
        logger.info(f"  Top CWEs   : {cwes.most_common(5)}")

    logger.info("\n--- Combined (C + Python) ---")
    write_file(all_samples, "held_out_valid.jsonl")

    logger.info("\n--- C only ---")
    write_file(c_samples, "held_out_c_valid.jsonl")

    logger.info("\n--- Python only ---")
    write_file(python_samples, "held_out_python_valid.jsonl")


if __name__ == "__main__":
    generate()
