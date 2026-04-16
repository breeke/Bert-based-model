"""
test.py — Cross-Language Vulnerability Detection Equivalence Test
=================================================================
For each of the 8 shared CWEs, runs the model on the same vulnerability
written in C, Python, Java, JavaScript, and Go.

Pass conditions:
  Vulnerable code  → score > threshold  (model flags it)
  Safe equivalent  → score < threshold  (model does not false-alarm)

Usage:
    python test.py --model_dir ./multi_lang_model
    python test.py --model_dir ./multi_lang_model --threshold 0.3 --verbose
"""

import argparse
import sys
import torch
from transformers import RobertaConfig, RobertaForSequenceClassification, RobertaTokenizer

from model import Model
from dataset import convert_examples_to_features


# ---------------------------------------------------------------------------
# Test cases: same vulnerability in every supported language
# Format: { "cwe": ..., "description": ...,
#           "vulnerable": { lang: code, ... },
#           "safe":       { lang: code, ... } }
# ---------------------------------------------------------------------------
TEST_CASES = [
    # ------------------------------------------------------------------ #
    {
        "cwe": "CWE-89",
        "description": "SQL Injection",
        "vulnerable": {
            "c": """int get_user(sqlite3 *db, const char *username) {
    char query[512];
    snprintf(query, sizeof(query),
             "SELECT * FROM users WHERE name='%s'", username);
    return sqlite3_exec(db, query, NULL, NULL, NULL);
}""",
            "python": """def get_user(username):
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()""",
            "java": """String getUser(Connection conn, String username) throws SQLException {
    Statement stmt = conn.createStatement();
    ResultSet rs = stmt.executeQuery(
        "SELECT * FROM users WHERE name='" + username + "'");
    return rs.next() ? rs.getString("name") : null;
}""",
            "javascript": """async function getUser(db, username) {
    const result = await db.query(
        "SELECT * FROM users WHERE name='" + username + "'");
    return result.rows[0];
}""",
            "go": """func getUser(db *sql.DB, username string) (string, error) {
    query := "SELECT name FROM users WHERE name='" + username + "'"
    row := db.QueryRow(query)
    var name string
    err := row.Scan(&name)
    return name, err
}""",
        },
        "safe": {
            "c": """int get_user(sqlite3 *db, const char *username) {
    sqlite3_stmt *stmt;
    const char *query = "SELECT * FROM users WHERE name=?";
    if (sqlite3_prepare_v2(db, query, -1, &stmt, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_ROW ? 1 : 0;
}""",
            "python": """def get_user(username):
    query = "SELECT * FROM users WHERE name = %s"
    cursor.execute(query, (username,))
    return cursor.fetchone()""",
            "java": """String getUser(Connection conn, String username) throws SQLException {
    PreparedStatement ps = conn.prepareStatement(
        "SELECT * FROM users WHERE name=?");
    ps.setString(1, username);
    ResultSet rs = ps.executeQuery();
    return rs.next() ? rs.getString("name") : null;
}""",
            "javascript": """async function getUser(db, username) {
    const result = await db.query(
        "SELECT * FROM users WHERE name=$1", [username]);
    return result.rows[0];
}""",
            "go": """func getUser(db *sql.DB, username string) (string, error) {
    row := db.QueryRow("SELECT name FROM users WHERE name=?", username)
    var name string
    err := row.Scan(&name)
    return name, err
}""",
        },
    },
    # ------------------------------------------------------------------ #
    {
        "cwe": "CWE-78",
        "description": "Command Injection",
        "vulnerable": {
            "c": """int check_host(const char *hostname) {
    char cmd[256];
    sprintf(cmd, "ping -c 1 %s", hostname);
    return system(cmd);
}""",
            "python": """def ping_host(host):
    import os
    os.system("ping -c 4 " + host)""",
            "java": """void checkHost(String hostname) throws Exception {
    Runtime.getRuntime().exec("ping -c 1 " + hostname);
}""",
            "javascript": """function pingHost(host) {
    const { exec } = require('child_process');
    exec('ping -c 1 ' + host);
}""",
            "go": """func checkHost(hostname string) error {
    cmd := exec.Command("sh", "-c", "ping -c 1 "+hostname)
    return cmd.Run()
}""",
        },
        "safe": {
            "c": """int check_host(const char *hostname) {
    for (int i = 0; hostname[i]; i++) {
        char c = hostname[i];
        if (!isalnum(c) && c != '.' && c != '-')
            return -1;
    }
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ping -c 1 %s", hostname);
    return system(cmd);
}""",
            "python": """def ping_host(host):
    import subprocess, re
    if not re.match(r'^[a-zA-Z0-9.\\-]+$', host):
        raise ValueError("Invalid hostname")
    subprocess.run(["ping", "-c", "4", host], check=True)""",
            "java": """void checkHost(String hostname) throws Exception {
    if (!hostname.matches("[a-zA-Z0-9.\\\\-]+"))
        throw new IllegalArgumentException("Invalid hostname");
    new ProcessBuilder("ping", "-c", "1", hostname).start().waitFor();
}""",
            "javascript": """function pingHost(host) {
    if (!/^[a-zA-Z0-9.\\-]+$/.test(host))
        throw new Error('Invalid hostname');
    const { spawn } = require('child_process');
    spawn('ping', ['-c', '1', host]);
}""",
            "go": """func checkHost(hostname string) error {
    matched, _ := regexp.MatchString(`^[a-zA-Z0-9.\\-]+$`, hostname)
    if !matched {
        return fmt.Errorf("invalid hostname")
    }
    return exec.Command("ping", "-c", "1", hostname).Run()
}""",
        },
    },
    # ------------------------------------------------------------------ #
    {
        "cwe": "CWE-22",
        "description": "Path Traversal",
        "vulnerable": {
            "c": """void serve_file(const char *filename) {
    char path[512];
    snprintf(path, sizeof(path), "/var/www/files/%s", filename);
    FILE *f = fopen(path, "r");
    if (f) { send_file(f); fclose(f); }
}""",
            "python": """def read_file(filename):
    filepath = "/var/www/uploads/" + filename
    with open(filepath, "r") as f:
        return f.read()""",
            "java": """byte[] serveFile(String filename) throws IOException {
    File f = new File("/var/www/files/" + filename);
    return Files.readAllBytes(f.toPath());
}""",
            "javascript": """function readFile(filename) {
    const fs = require('fs');
    return fs.readFileSync('/var/www/uploads/' + filename, 'utf8');
}""",
            "go": """func serveFile(filename string) ([]byte, error) {
    path := "/var/www/files/" + filename
    return os.ReadFile(path)
}""",
        },
        "safe": {
            "c": """void serve_file(const char *filename) {
    char resolved[PATH_MAX];
    char path[512];
    snprintf(path, sizeof(path), "/var/www/files/%s", filename);
    if (!realpath(path, resolved)) return;
    if (strncmp(resolved, "/var/www/files/", 15) != 0) return;
    FILE *f = fopen(resolved, "r");
    if (f) { send_file(f); fclose(f); }
}""",
            "python": """def read_file(filename):
    import os
    base = "/var/www/uploads/"
    filepath = os.path.realpath(os.path.join(base, filename))
    if not filepath.startswith(base):
        raise ValueError("Path traversal detected")
    with open(filepath, "r") as f:
        return f.read()""",
            "java": """byte[] serveFile(String filename) throws IOException {
    Path base = Paths.get("/var/www/files/").toRealPath();
    Path full = base.resolve(filename).normalize();
    if (!full.startsWith(base))
        throw new SecurityException("Path traversal detected");
    return Files.readAllBytes(full);
}""",
            "javascript": """function readFile(filename) {
    const fs = require('fs'), path = require('path');
    const base = path.resolve('/var/www/uploads/');
    const full = path.resolve(base, filename);
    if (!full.startsWith(base + path.sep))
        throw new Error('Path traversal detected');
    return fs.readFileSync(full, 'utf8');
}""",
            "go": """func serveFile(filename string) ([]byte, error) {
    base, _ := filepath.Abs("/var/www/files/")
    full, err := filepath.Abs(filepath.Join(base, filename))
    if err != nil || !strings.HasPrefix(full, base+string(os.PathSeparator)) {
        return nil, fmt.Errorf("invalid path")
    }
    return os.ReadFile(full)
}""",
        },
    },
    # ------------------------------------------------------------------ #
    {
        "cwe": "CWE-327",
        "description": "Weak Cryptography",
        "vulnerable": {
            "c": """void hash_password(const char *password, unsigned char *digest) {
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, password, strlen(password));
    MD5_Final(digest, &ctx);
}""",
            "python": """def hash_password(password):
    import hashlib
    return hashlib.md5(password.encode()).hexdigest()""",
            "java": """String hashPassword(String password) throws Exception {
    MessageDigest md = MessageDigest.getInstance("MD5");
    byte[] digest = md.digest(password.getBytes());
    return Base64.getEncoder().encodeToString(digest);
}""",
            "javascript": """function hashPassword(password) {
    const crypto = require('crypto');
    return crypto.createHash('md5').update(password).digest('hex');
}""",
            "go": """func hashPassword(password string) string {
    h := md5.New()
    io.WriteString(h, password)
    return fmt.Sprintf("%x", h.Sum(nil))
}""",
        },
        "safe": {
            "c": """void hash_password(const char *password, unsigned char *digest) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, password, strlen(password));
    SHA256_Final(digest, &ctx);
}""",
            "python": """def hash_password(password):
    import bcrypt
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt)""",
            "java": """String hashPassword(String password) throws Exception {
    byte[] salt = new byte[16];
    new SecureRandom().nextBytes(salt);
    MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
    sha256.update(salt);
    return Base64.getEncoder().encodeToString(
        sha256.digest(password.getBytes(StandardCharsets.UTF_8)));
}""",
            "javascript": """async function hashPassword(password) {
    const bcrypt = require('bcrypt');
    return bcrypt.hash(password, 12);
}""",
            "go": """func hashPassword(password string) (string, error) {
    hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    return string(hash), err
}""",
        },
    },
    # ------------------------------------------------------------------ #
    {
        "cwe": "CWE-134",
        "description": "Format String / Template Injection",
        "vulnerable": {
            "c": """void log_error(char *user_msg) {
    char logbuf[256];
    snprintf(logbuf, sizeof(logbuf), user_msg);
    write_log(logbuf);
}""",
            "python": """def render_greeting(template, username):
    return template % username""",
            "java": """String renderMessage(String template, Object... args) {
    return MessageFormat.format(template, args);
}""",
            "javascript": """function renderTemplate(template, data) {
    return new Function('data', `return \`${template}\``)(data);
}""",
            "go": """func logRequest(format string, args ...interface{}) {
    fmt.Printf(format, args...)
}""",
        },
        "safe": {
            "c": """void log_error(const char *user_msg) {
    char logbuf[256];
    snprintf(logbuf, sizeof(logbuf), "%s", user_msg);
    write_log(logbuf);
}""",
            "python": """def render_greeting(username):
    return "Hello, {}!".format(username)""",
            "java": """String renderMessage(String templateName, String username) {
    Map<String, String> templates = Map.of("hi", "Hello {0}!");
    String tmpl = templates.get(templateName);
    if (tmpl == null) throw new IllegalArgumentException("Unknown template");
    return MessageFormat.format(tmpl, username);
}""",
            "javascript": """function renderTemplate(templateName, data) {
    const templates = { welcome: 'Hello, {name}!' };
    const tmpl = templates[templateName];
    if (!tmpl) throw new Error('Unknown template');
    return tmpl.replace('{name}', String(data.name || ''));
}""",
            "go": """func logRequest(method, path string) {
    fmt.Printf("%s %s\\n", method, path)
}""",
        },
    },
    # ------------------------------------------------------------------ #
    {
        "cwe": "CWE-367",
        "description": "TOCTOU Race Condition",
        "vulnerable": {
            "c": """int safe_write(const char *path, const char *data) {
    if (access(path, W_OK) == 0) {
        FILE *f = fopen(path, "w");
        fputs(data, f);
        fclose(f);
        return 0;
    }
    return -1;
}""",
            "python": """def safe_read(filepath):
    if os.path.exists(filepath):
        if os.path.isfile(filepath):
            with open(filepath) as f:
                return f.read()
    return None""",
            "java": """boolean writeIfNotExists(String path, String data) throws IOException {
    File f = new File(path);
    if (!f.exists()) {
        Files.writeString(f.toPath(), data);
        return true;
    }
    return false;
}""",
            "javascript": """function writeIfNotExists(filepath, data) {
    const fs = require('fs');
    if (!fs.existsSync(filepath)) {
        fs.writeFileSync(filepath, data);
        return true;
    }
    return false;
}""",
            "go": """func writeIfNotExists(path, data string) error {
    if _, err := os.Stat(path); os.IsNotExist(err) {
        return os.WriteFile(path, []byte(data), 0644)
    }
    return nil
}""",
        },
        "safe": {
            "c": """int safe_write(const char *path, const char *data) {
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) return -1;
    write(fd, data, strlen(data));
    close(fd);
    return 0;
}""",
            "python": """def safe_read(filepath):
    try:
        with open(filepath) as f:
            return f.read()
    except (FileNotFoundError, PermissionError):
        return None""",
            "java": """boolean writeIfNotExists(String path, String data) throws IOException {
    try {
        Files.writeString(Paths.get(path), data, StandardOpenOption.CREATE_NEW);
        return true;
    } catch (FileAlreadyExistsException e) {
        return false;
    }
}""",
            "javascript": """function writeIfNotExists(filepath, data) {
    const fs = require('fs');
    try {
        fs.writeFileSync(filepath, data, { flag: 'wx' });
        return true;
    } catch (e) {
        if (e.code === 'EEXIST') return false;
        throw e;
    }
}""",
            "go": """func writeIfNotExists(path, data string) error {
    f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
    if err != nil {
        return err
    }
    _, err = f.WriteString(data)
    f.Close()
    return err
}""",
        },
    },
    # ------------------------------------------------------------------ #
    {
        "cwe": "CWE-732",
        "description": "Insecure File Permissions",
        "vulnerable": {
            "c": """void create_temp_file(const char *name) {
    int fd = open(name, O_WRONLY | O_CREAT | O_TRUNC, 0777);
    if (fd >= 0) close(fd);
}""",
            "python": """def save_credentials(username, token):
    with open("/etc/app/credentials.conf", "w") as f:
        f.write(f"{username}:{token}")
    os.chmod("/etc/app/credentials.conf", 0o777)""",
            "java": """void createTempFile(String name) throws IOException {
    File f = new File(name);
    f.createNewFile();
    f.setReadable(true, false);
    f.setWritable(true, false);
}""",
            "javascript": """function createTempFile(name) {
    const fs = require('fs');
    fs.writeFileSync(name, '');
    fs.chmodSync(name, 0o777);
}""",
            "go": """func createTempFile(name string) error {
    f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0777)
    if err != nil {
        return err
    }
    return f.Close()
}""",
        },
        "safe": {
            "c": """void create_temp_file(const char *name) {
    int fd = open(name, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd >= 0) close(fd);
}""",
            "python": """def save_credentials(username, token):
    import os
    path = "/etc/app/credentials.conf"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(f"{username}:{token}")""",
            "java": """void createTempFile(String name) throws IOException {
    File f = new File(name);
    f.createNewFile();
    f.setReadable(true, true);
    f.setWritable(true, true);
}""",
            "javascript": """function createTempFile(name) {
    const fs = require('fs');
    fs.writeFileSync(name, '', { mode: 0o600 });
}""",
            "go": """func createTempFile(name string) error {
    f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
    if err != nil {
        return err
    }
    return f.Close()
}""",
        },
    },
    # ------------------------------------------------------------------ #
    {
        "cwe": "CWE-798",
        "description": "Hardcoded Credentials",
        "vulnerable": {
            "c": """int authenticate(const char *username, const char *password) {
    if (strcmp(username, "admin") == 0 && strcmp(password, "s3cr3tP@ss") == 0)
        return 1;
    return 0;
}""",
            "python": """def connect_database():
    import mysql.connector
    conn = mysql.connector.connect(
        host="db.internal.company.com",
        user="admin",
        password="SuperSecret123!",
        database="production"
    )
    return conn""",
            "java": """Connection getConnection() throws SQLException {
    return DriverManager.getConnection(
        "jdbc:mysql://db.internal/prod", "root", "rootpassword123");
}""",
            "javascript": """function connectDatabase() {
    const mysql = require('mysql2');
    return mysql.createConnection({
        host: 'db.internal', user: 'admin',
        password: 'SuperSecret123!', database: 'production'
    });
}""",
            "go": """func connectDB() *sql.DB {
    db, _ := sql.Open("mysql", "root:rootpassword123@tcp(db.internal)/prod")
    return db
}""",
        },
        "safe": {
            "c": """int authenticate(const char *username, const char *password) {
    const char *expected_hash = get_stored_hash(username);
    if (!expected_hash) return 0;
    return verify_bcrypt(password, expected_hash);
}""",
            "python": """def connect_database():
    import os, mysql.connector
    conn = mysql.connector.connect(
        host=os.environ["DB_HOST"],
        user=os.environ["DB_USER"],
        password=os.environ["DB_PASSWORD"],
        database=os.environ["DB_NAME"]
    )
    return conn""",
            "java": """Connection getConnection() throws SQLException {
    String url  = System.getenv("DB_URL");
    String user = System.getenv("DB_USER");
    String pass = System.getenv("DB_PASS");
    return DriverManager.getConnection(url, user, pass);
}""",
            "javascript": """function connectDatabase() {
    const mysql = require('mysql2');
    return mysql.createConnection({
        host: process.env.DB_HOST, user: process.env.DB_USER,
        password: process.env.DB_PASS, database: process.env.DB_NAME
    });
}""",
            "go": """func connectDB() (*sql.DB, error) {
    dsn := os.Getenv("DB_DSN")
    if dsn == "" {
        return nil, fmt.Errorf("DB_DSN not set")
    }
    return sql.Open("mysql", dsn)
}""",
        },
    },
]

LANGUAGES = ["c", "python", "java", "javascript", "go"]


def load_model(model_dir, model_name="microsoft/unixcoder-base"):
    config = RobertaConfig.from_pretrained(model_name)
    config.num_labels = 1
    tokenizer = RobertaTokenizer.from_pretrained(model_name)
    base_model = RobertaForSequenceClassification.from_pretrained(
        model_name, config=config)

    class _Args:
        dropout_probability = 0.1
        block_size = 400

    model = Model(base_model, config, tokenizer, _Args())
    model.load_state_dict(
        torch.load(f"{model_dir}/best_model.bin", map_location="cpu"))
    model.eval()
    return model, tokenizer, _Args()


def score(model, tokenizer, args, code):
    sample = {"func": code, "target": 0, "idx": "test", "project": "test"}
    features = convert_examples_to_features(sample, tokenizer, args)
    input_ids = torch.tensor([features.input_ids])
    with torch.no_grad():
        prob = model(input_ids)
    return prob.item()


def run_tests(model_dir, threshold=0.3, model_name="microsoft/unixcoder-base",
              verbose=False):
    print(f"\nLoading model from: {model_dir}")
    print(f"Backbone           : {model_name}")
    print(f"Detection threshold: {threshold}\n")

    try:
        model, tokenizer, args = load_model(model_dir, model_name)
    except FileNotFoundError:
        print(f"ERROR: No model found at {model_dir}/best_model.bin")
        print("Train the model first:\n"
              "  python train.py --train_data_file ./Files/multi_lang_train.jsonl "
              "--eval_data_file ./Files/multi_lang_valid.jsonl "
              "--test_data_file ./Files/multi_lang_test.jsonl "
              "--output_dir ./multi_lang_model --do_train --do_eval --do_test")
        sys.exit(1)

    # ---- header ----
    col_w = 14
    header = f"{'CWE':<10} {'Description':<30} " + \
             " ".join(f"{lang.upper():>{col_w}}" for lang in LANGUAGES)
    print(header)
    print("-" * len(header))

    total_vuln = total_vuln_pass = 0
    total_safe = total_safe_pass = 0

    for tc in TEST_CASES:
        cwe  = tc["cwe"]
        desc = tc["description"]

        vuln_cells = []
        safe_cells = []

        for lang in LANGUAGES:
            vuln_code = tc["vulnerable"].get(lang)
            safe_code = tc["safe"].get(lang)

            if vuln_code is None:
                vuln_cells.append(f"{'N/A':>{col_w}}")
                safe_cells.append(f"{'N/A':>{col_w}}")
                continue

            v_score = score(model, tokenizer, args, vuln_code)
            s_score = score(model, tokenizer, args, safe_code)

            v_pass = v_score > threshold
            s_pass = s_score < threshold

            total_vuln += 1
            total_safe += 1
            if v_pass: total_vuln_pass += 1
            if s_pass: total_safe_pass += 1

            v_marker = "PASS" if v_pass else "FAIL"
            s_marker = "PASS" if s_pass else "FAIL"
            vuln_cells.append(f"{v_score:.2f}({v_marker}):>{col_w}"[:col_w].rjust(col_w))
            safe_cells.append(f"{s_score:.2f}({s_marker}):>{col_w}"[:col_w].rjust(col_w))

        row_vuln = f"{cwe:<10} {f'[VULN] {desc}':<30} " + " ".join(vuln_cells)
        row_safe = f"{'':10} {f'[SAFE] {desc}':<30} " + " ".join(safe_cells)

        print(row_vuln)
        if verbose:
            print(row_safe)

    print("-" * len(header))
    print(f"\nVulnerable detection : {total_vuln_pass}/{total_vuln} "
          f"({total_vuln_pass/total_vuln*100:.1f}%)")
    print(f"Safe non-detection   : {total_safe_pass}/{total_safe} "
          f"({total_safe_pass/total_safe*100:.1f}%)")

    overall = (total_vuln_pass + total_safe_pass) / (total_vuln + total_safe)
    print(f"Overall pass rate    : {overall*100:.1f}%\n")

    if overall >= 0.80:
        print("RESULT: PASS — model generalises across all 5 languages.")
    else:
        print("RESULT: PARTIAL — some language/CWE combinations need more training data.")

    return overall


def main():
    parser = argparse.ArgumentParser(
        description="Cross-language vulnerability detection equivalence test")
    parser.add_argument("--model_dir", default="./multi_lang_model",
                        help="Directory containing best_model.bin")
    parser.add_argument("--model_name", default="microsoft/unixcoder-base",
                        help="HuggingFace model identifier (must match training)")
    parser.add_argument("--threshold", type=float, default=0.3,
                        help="Vulnerability probability threshold (default 0.3)")
    parser.add_argument("--verbose", action="store_true",
                        help="Also show safe-code scores (false-positive check)")
    args = parser.parse_args()

    run_tests(args.model_dir, args.threshold, args.model_name, args.verbose)


if __name__ == "__main__":
    main()
