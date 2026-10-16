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
int sceHttp2AddRequestHeader(int, const char*, const char*, uint32_t);
int sceHttp2SendRequest(int, const void*, size_t);
int sceHttp2GetStatusCode(int, int*);
int sceHttp2DeleteRequest(int);
int sceHttp2SslDisableOption(int, uint32_t) __attribute__((weak));

#define API "https://discord.com/api/v9/users/@me"
#define UA "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"

static int g_tmpl = -1;
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

static int net_init(void) {
    int mem, ssl, http;
    if (sceNetInit()) return -1;
    if ((mem = sceNetPoolCreate("presence", 32*1024, 0)) < 0) return -2;
    if ((ssl = sceSslInit(256*1024)) < 0) return -3;
    if ((http = sceHttp2Init(mem, ssl, 256*1024, 1)) < 0) return -4;
    if ((g_tmpl = sceHttp2CreateTemplate(http, UA, 3, 1)) < 0) return -5;
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

static int do_req(const char* method, const char* url, const char* body, char* out, size_t n) {
    size_t bl = body ? strlen(body) : 0;
    int req = sceHttp2CreateRequestWithURL(g_tmpl, method, url, bl);
    if (req < 0) { snprintf(out, n, "create=%x", (unsigned)req); return -1; }
    if (strstr(url, "discord")) sceHttp2AddRequestHeader(req, "Authorization", g_token, 0);
    if (body) sceHttp2AddRequestHeader(req, "Content-Type", "application/json", 0);
    int sr = sceHttp2SendRequest(req, body, bl);
    int status = -1;
    if (sr == 0) sceHttp2GetStatusCode(req, &status);
    snprintf(out, n, "send=%x st=%d", (unsigned)sr, status);
    sceHttp2DeleteRequest(req);
    return status;
}

static int set_status(const char* name, char* out, size_t n) {
    char body[512];
    if (name)
        snprintf(body, sizeof body,
                 "{\"custom_status\":{\"text\":\"Jogando %s\",\"emoji_name\":\"🎮\"}}", name);
    else
        snprintf(body, sizeof body, "{\"custom_status\":null}");
    return do_req("PATCH", API "/settings", body, out, n);
}

int main(void) {
    if (load_token()) { notify("Discord: falta /data/discord_token.txt"); return 1; }
    int r = net_init();
    if (r) { char m[64]; snprintf(m, sizeof m, "Discord: erro de rede %d", r); notify(m); return 1; }

    char rep[900] = "DIAG\n", res[120], line[200];

    do_req("GET", "https://www.google.com/generate_204", NULL, res, sizeof res);
    snprintf(line, sizeof line, "google: %s\n", res);
    strncat(rep, line, sizeof rep - strlen(rep) - 1);

    static const uint32_t flags[] = {0x1F, 0x01, 0x0F, 0x11, 0x03};
    for (int i = 0; i < 5; i++) {
        int rc = sceHttp2SslDisableOption ? sceHttp2SslDisableOption(g_tmpl, flags[i]) : 0x7777;
        int st = do_req("GET", API, NULL, res, sizeof res);
        snprintf(line, sizeof line, "f=%x rc=%x %s\n", (unsigned)flags[i], (unsigned)rc, res);
        strncat(rep, line, sizeof rep - strlen(rep) - 1);
        if (st > 0) break;
    }
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
