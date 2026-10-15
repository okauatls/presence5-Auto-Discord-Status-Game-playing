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

#define URL "https://discord.com/api/v9/users/@me/settings"
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
    if (sceHttp2SslDisableOption) sceHttp2SslDisableOption(g_tmpl, 0xFF);
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

static int set_status(const char* name) {
    char body[512];
    if (name)
        snprintf(body, sizeof body,
                 "{\"custom_status\":{\"text\":\"Jogando %s\",\"emoji_name\":\"🎮\"}}", name);
    else
        snprintf(body, sizeof body, "{\"custom_status\":null}");

    int req = sceHttp2CreateRequestWithURL(g_tmpl, "PATCH", URL, strlen(body));
    if (req < 0) return req;
    sceHttp2AddRequestHeader(req, "Authorization", g_token, 0);
    sceHttp2AddRequestHeader(req, "Content-Type", "application/json", 0);
    int status = -1;
    int sr = sceHttp2SendRequest(req, body, strlen(body));
    if (sr == 0) {
        if (sceHttp2GetStatusCode(req, &status)) status = -2;
    } else {
        status = sr;
    }
    sceHttp2DeleteRequest(req);
    return status;
}

int main(void) {
    if (load_token()) { notify("Discord: falta /data/discord_token.txt"); return 1; }
    int r = net_init();
    if (r) { char m[64]; snprintf(m, sizeof m, "Discord: erro de rede %d", r); notify(m); return 1; }
    notify(sceHttp2SslDisableOption ? "Discord status: iniciado (ssl off)" : "Discord status: iniciado (sem ssl off)");

    char cur[32] = "";
    for (;;) {
        char seen[32] = "";
        int id = sceSystemServiceGetAppIdOfRunningBigApp();
        if (id >= 0 && sceSystemServiceGetAppTitleId(id, seen) != 0) seen[0] = 0;

        if (strcmp(seen, cur) != 0) {
            strcpy(cur, seen);
            char name[128] = "", msg[200];
            int st;
            if (cur[0]) {
                if (get_name(cur, name, sizeof name)) snprintf(name, sizeof name, "%s", cur);
                st = set_status(name);
            } else {
                st = set_status(NULL);
            }
            snprintf(msg, sizeof msg, "Discord: %s (%d / 0x%x)", cur[0] ? name : "status limpo", st, (unsigned)st);
            notify(msg);
        }
        sleep(5);
    }
    return 0;
}
