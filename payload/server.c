#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

typedef struct notify_request {
    char useless1[45];
    char message[3075];
} notify_request_t;

int sceKernelSendNotificationRequest(int, notify_request_t*, size_t, int);
int sceSystemServiceGetAppIdOfRunningBigApp(void);
int sceSystemServiceGetAppTitleId(int, char*);

int sceNetInit(void);
int sceNetPoolCreate(const char*, int, int);
int sceSslInit(size_t);

int sceHttp2Init(int, int, size_t, int);
int sceHttp2CreateTemplate(int, const char*, int, int);
int sceHttp2CreateRequestWithURL(int, const char*, const char*, uint64_t);
int sceHttp2SendRequest(int, const void*, size_t);
int sceHttp2GetStatusCode(int, int*);
int sceHttp2DeleteRequest(int);

int sceHttpInit(int, int, size_t);
int sceHttpCreateTemplate(int, const char*, int, int);
int sceHttpCreateConnectionWithURL(int, const char*, int);
int sceHttpCreateRequestWithURL2(int, const char*, const char*, uint64_t);
int sceHttpAddRequestHeader(int, const char*, const char*, uint32_t);
int sceHttpSendRequest(int, const void*, size_t);
int sceHttpDeleteRequest(int);
int sceHttpDeleteConnection(int);
int sceHttpGetStatusCode(int, int*) __attribute__((weak));
int sceHttpsSetSslCallback(int, int (*)(int, unsigned int, void* const*, int, void*), void*);

#define API "https://discord.com/api/v9/users/@me"
#define UA "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"

static int g_t2 = -1, g_t1 = -1;
static char g_token[256];

static void notify(const char* m) {
    notify_request_t r;
    memset(&r, 0, sizeof r);
    strncpy(r.message, m, sizeof r.message - 1);
    sceKernelSendNotificationRequest(0, &r, sizeof r, 0);
}

static int load_token(void) {
    FILE* f = fopen("/data/discord_token.txt", "r");
    if (!f) return -1;
    if (!fgets(g_token, sizeof g_token, f)) { fclose(f); return -1; }
    fclose(f);
    size_t n = strlen(g_token);
    while (n && (g_token[n-1] == '\n' || g_token[n-1] == '\r' || g_token[n-1] == ' ')) g_token[--n] = 0;
    return n > 20 ? 0 : -1;
}

static int ssl_cb(int id, unsigned int err, void* const* certs, int n, void* arg) {
    (void)id; (void)err; (void)certs; (void)n; (void)arg;
    return 0;
}

static int net_init(void) {
    int mem, ssl, h2, h1;
    if (sceNetInit()) return -1;
    if ((mem = sceNetPoolCreate("presence", 64*1024, 0)) < 0) return -2;
    if ((ssl = sceSslInit(256*1024)) < 0) return -3;
    if ((h2 = sceHttp2Init(mem, ssl, 256*1024, 1)) < 0) return -4;
    if ((g_t2 = sceHttp2CreateTemplate(h2, UA, 3, 1)) < 0) return -5;
    if ((h1 = sceHttpInit(mem, ssl, 256*1024)) < 0) return -6;
    if ((g_t1 = sceHttpCreateTemplate(h1, UA, 2, 0)) < 0) return -7;
    sceHttpsSetSslCallback(g_t1, ssl_cb, NULL);
    return 0;
}

static int get_name(const char* tid, char* out, size_t n) {
    char path[128], buf[16384];
    snprintf(path, sizeof path, "/user/appmeta/%s/param.json", tid);
    FILE* f = fopen(path, "rb");
    if (!f) return -1;
    size_t len = fread(buf, 1, sizeof buf - 1, f);
    fclose(f);
    buf[len] = 0;
    char* p = strstr(buf, "\"titleName\"");
    if (!p) return -1;
    p = strchr(p + 11, ':');
    if (!p) return -1;
    p = strchr(p, '"');
    if (!p) return -1;
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i < n - 1 && i < 100) {
        unsigned char c = (unsigned char)*p++;
        if (c == '\\') { if (*p) p++; continue; }
        if (c < 0x20) continue;
        out[i++] = (char)c;
    }
    out[i] = 0;
    return i ? 0 : -1;
}

static int req_v2(const char* url, char* out, size_t n) {
    int req = sceHttp2CreateRequestWithURL(g_t2, "GET", url, 0);
    if (req < 0) { snprintf(out, n, "create=%x", (unsigned)req); return -1; }
    int sr = sceHttp2SendRequest(req, NULL, 0);
    int st = -1;
    if (sr == 0) sceHttp2GetStatusCode(req, &st);
    snprintf(out, n, "send=%x st=%d", (unsigned)sr, st);
    sceHttp2DeleteRequest(req);
    return st;
}

static int req_v1(const char* method, const char* url, const char* body, int auth, char* out, size_t n) {
    size_t bl = body ? strlen(body) : 0;
    int conn = sceHttpCreateConnectionWithURL(g_t1, url, 0);
    if (conn < 0) { snprintf(out, n, "conn=%x", (unsigned)conn); return -1; }
    int req = sceHttpCreateRequestWithURL2(conn, method, url, bl);
    if (req < 0) { snprintf(out, n, "req=%x", (unsigned)req); sceHttpDeleteConnection(conn); return -1; }
    if (auth) sceHttpAddRequestHeader(req, "Authorization", g_token, 0);
    if (body) sceHttpAddRequestHeader(req, "Content-Type", "application/json", 0);
    int sr = sceHttpSendRequest(req, body, bl);
    int st = -1, gs = 0x7777;
    if (sr >= 0 && sceHttpGetStatusCode) gs = sceHttpGetStatusCode(req, &st);
    snprintf(out, n, "send=%x gs=%x st=%d", (unsigned)sr, (unsigned)gs, st);
    sceHttpDeleteRequest(req);
    sceHttpDeleteConnection(conn);
    return st;
}

static int set_status(const char* name, char* out, size_t n) {
    char body[512];
    if (name)
        snprintf(body, sizeof body,
                 "{\"custom_status\":{\"text\":\"Jogando %s\",\"emoji_name\":\"🎮\"}}", name);
    else
        snprintf(body, sizeof body, "{\"custom_status\":null}");
    return req_v1("PATCH", API "/settings", body, 1, out, n);
}

int main(void) {
    if (load_token()) { notify("Discord: falta /data/discord_token.txt"); return 1; }
    int r = net_init();
    if (r) { char m[64]; snprintf(m, sizeof m, "Discord: erro de rede %d", r); notify(m); return 1; }

    char rep[700] = "DIAG2\n", res[120], line[160];
    req_v2("http://connectivitycheck.gstatic.com/generate_204", res, sizeof res);
    snprintf(line, sizeof line, "v2http: %s\n", res); strncat(rep, line, sizeof rep - strlen(rep) - 1);
    req_v1("GET", "http://connectivitycheck.gstatic.com/generate_204", NULL, 0, res, sizeof res);
    snprintf(line, sizeof line, "v1http: %s\n", res); strncat(rep, line, sizeof rep - strlen(rep) - 1);
    req_v1("GET", "https://www.google.com/generate_204", NULL, 0, res, sizeof res);
    snprintf(line, sizeof line, "v1g: %s\n", res); strncat(rep, line, sizeof rep - strlen(rep) - 1);
    req_v1("GET", API, NULL, 1, res, sizeof res);
    snprintf(line, sizeof line, "v1d: %s\n", res); strncat(rep, line, sizeof rep - strlen(rep) - 1);
    notify(rep);

    char cur[32] = "";
    for (;;) {
        char seen[32] = "";
        int id = sceSystemServiceGetAppIdOfRunningBigApp();
        if (id >= 0 && sceSystemServiceGetAppTitleId(id, seen) != 0) seen[0] = 0;

        if (strcmp(seen, cur) != 0) {
            strcpy(cur, seen);
            char name[128] = "", msg[300];
            if (cur[0]) {
                if (get_name(cur, name, sizeof name)) snprintf(name, sizeof name, "%s", cur);
                set_status(name, res, sizeof res);
            } else {
                set_status(NULL, res, sizeof res);
            }
            snprintf(msg, sizeof msg, "%s | %s", cur[0] ? name : "limpo", res);
            notify(msg);
        }
        sleep(5);
    }
    return 0;
}
