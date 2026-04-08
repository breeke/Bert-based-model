import json

raw = """[
{
"func": "int run_command(char *input) {\n    char cmd[256];\n    snprintf(cmd, sizeof(cmd), "ls %s", input);\n    int result = system(cmd);\n    if (result == -1) {\n        return -1;\n    }\n    return 0;\n}",
"target": 1,
"language": "c",
"cwe": ["CWE-78"]
},
{
"func": "int run_command_safe(char *input) {\n    char *args[3];\n    args[0] = "ls";\n    args[1] = input;\n    args[2] = NULL;\n    pid_t pid = fork();\n    if (pid == 0) {\n        execvp("ls", args);\n        exit(1);\n    } else {\n        wait(NULL);\n    }\n    return 0;\n}",
"target": 0,
"language": "c",
"cwe": ["CWE-78"]
},
{
"func": "def run_command(input_str):\n    import os\n    cmd = "ls " + input_str\n    result = os.system(cmd)\n    if result != 0:\n        return False\n    return True",
"target": 1,
"language": "python",
"cwe": ["CWE-78"]
},
{
"func": "def run_command_safe(input_str):\n    import subprocess\n    try:\n        result = subprocess.run(["ls", input_str], check=True)\n        return result.returncode == 0\n    except Exception:\n        return False",
"target": 0,
"language": "python",
"cwe": ["CWE-78"]
},
{
"func": "int get_user(char *username) {\n    char query[256];\n    sprintf(query, "SELECT * FROM users WHERE name='%s'", username);\n    MYSQL *conn = mysql_init(NULL);\n    if (!mysql_real_connect(conn, "localhost", "root", "", "db", 0, NULL, 0)) {\n        return -1;\n    }\n    if (mysql_query(conn, query)) {\n        mysql_close(conn);\n        return -1;\n    }\n    MYSQL_RES *res = mysql_store_result(conn);\n    mysql_free_result(res);\n    mysql_close(conn);\n    return 0;\n}",
"target": 1,
"language": "c",
"cwe": ["CWE-89"]
},
{
"func": "def get_user_safe(conn, username):\n    cursor = conn.cursor()\n    query = "SELECT * FROM users WHERE name=%s"\n    cursor.execute(query, (username,))\n    result = cursor.fetchall()\n    cursor.close()\n    if result:\n        return result\n    return []",
"target": 0,
"language": "python",
"cwe": ["CWE-89"]
},
{
"func": "int read_file(char *filename) {\n    char path[256];\n    sprintf(path, "/var/data/%s", filename);\n    FILE *f = fopen(path, "r");\n    if (!f) return -1;\n    char buf[128];\n    while (fgets(buf, sizeof(buf), f)) {\n        printf("%s", buf);\n    }\n    fclose(f);\n    return 0;\n}",
"target": 1,
"language": "c",
"cwe": ["CWE-22"]
},
{
"func": "def read_file_safe(base_dir, filename):\n    import os\n    safe_path = os.path.normpath(os.path.join(base_dir, filename))\n    if not safe_path.startswith(base_dir):\n        return None\n    try:\n        with open(safe_path, 'r') as f:\n            data = f.read()\n        return data\n    except Exception:\n        return None",
"target": 0,
"language": "python",
"cwe": ["CWE-22"]
},
{
"func": "int log_message(char *msg) {\n    FILE *f = fopen("log.txt", "a");\n    if (!f) return -1;\n    fprintf(f, msg);\n    fprintf(f, "\n");\n    fclose(f);\n    return 0;\n}",
"target": 1,
"language": "c",
"cwe": ["CWE-134"]
},
{
"func": "def log_message_safe(msg):\n    try:\n        with open("log.txt", "a") as f:\n            f.write("%s\n" % msg)\n        return True\n    except Exception:\n        return False",
"target": 0,
"language": "python",
"cwe": ["CWE-134"]
}
]
"""
samples = json.loads(raw)

with open("./Files/llm_generated_test.jsonl", "w") as f:
    for i, s in enumerate(samples):
        s["idx"] = f"llm_{i}"
        f.write(json.dumps(s) + "\n")
