#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <poll.h>
#include <dirent.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/base64.h"
#include "psa/crypto.h"

typedef struct notify_request {
    char useless1[45];
    char message[3075];
} notify_request_t;

int sceKernelSendNotificationRequest(int, notify_request_t*, size_t, int);
int sceSystemServiceGetAppIdOfRunningBigApp(void);
int sceSystemServiceGetAppTitleId(int, char*);
int sceNetInit(void) __attribute__((weak));
int sceNetPoolCreate(const char*, int, int) __attribute__((weak));
int sceNetResolverCreate(const char*, int, int) __attribute__((weak));
int sceNetResolverStartNtoa(int, const char*, uint32_t*, int, int, int) __attribute__((weak));
int sceNetResolverDestroy(int) __attribute__((weak));

#define GW "gateway.discord.gg"

static char g_token[256], g_cur[32], g_name[128], g_last[160];
static char g_appid[40], g_asset[480], g_cover_for[32];
static time_t g_start;
static int g_fd = -1, g_err = 0, g_to = 200, g_pool = -1, g_inited = 0;
static mbedtls_ssl_context ssl;
static mbedtls_ssl_config conf;
static mbedtls_entropy_context ent;
static mbedtls_ctr_drbg_context drbg;

static void notify(const char* m) {
    notify_request_t r;
    memset(&r, 0, sizeof r);
    strncpy(r.message, m, sizeof r.message - 1);
    sceKernelSendNotificationRequest(0, &r, sizeof r, 0);
}

static void report(const char* stage, int code) {
    char m[160];
    snprintf(m, sizeof m, "RPC erro: %s cod=%d err=-0x%x", stage, code, (unsigned)(g_err < 0 ? -g_err : g_err));
    if (strcmp(m, g_last)) { strcpy(g_last, m); notify(m); }
}

int mbedtls_hardware_poll(void* d, unsigned char* out, size_t len, size_t* olen) {
    (void)d;
    size_t got = 0;
    FILE* f = fopen("/dev/urandom", "rb");
    if (f) { got = fread(out, 1, len, f); fclose(f); }
    static unsigned long c = 0x9e3779b9;
    while (got < len) {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        c = c * 6364136223846793005UL + 1442695040888963407UL;
        unsigned long v = (unsigned long)ts.tv_nsec ^ ((unsigned long)ts.tv_sec << 20) ^ c ^ (unsigned long)&ts;
        out[got++] = (unsigned char)(v ^ (v >> 8) ^ (v >> 17) ^ (v >> 29));
    }
    *olen = len;
    return 0;
}

static long long mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
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

static int read_appid(void) {
    FILE* f = fopen("/data/discord_appid.txt", "r");
    if (!f) return -1;
    if (!fgets(g_appid, sizeof g_appid, f)) { fclose(f); return -1; }
    fclose(f);
    size_t n = strlen(g_appid);
    while (n && (g_appid[n-1] < '0' || g_appid[n-1] > '9')) g_appid[--n] = 0;
    if (n < 15) { g_appid[0] = 0; return -1; }
    return 0;
}

static int get_name_json(const char* tid, char* out, size_t n) {
    static char buf[65536];
    char path[128];
    snprintf(path, sizeof path, "/user/appmeta/%s/param.json", tid);
    FILE* f = fopen(path, "rb");
    if (!f) return -1;
    size_t len = fread(buf, 1, sizeof buf - 1, f);
    fclose(f);
    buf[len] = 0;
    char* p = NULL;
    {
        static const char* langs[] = {"\"en-US\"", "\"en-GB\""};
        for (int li = 0; li < 2 && !p; li++) {
            char* k = buf;
            while ((k = strstr(k, langs[li])) != NULL) {
                char* e = k + strlen(langs[li]);
                while (*e == ' ' || *e == '\n' || *e == '\r' || *e == '\t') e++;
                if (*e == ':') { p = strstr(e, "\"titleName\""); break; }
                k = e;
            }
        }
        if (!p) p = strstr(buf, "\"titleName\"");
    }
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

static int get_name_sfo(const char* tid, char* out, size_t n) {
    static unsigned char buf[32768];
    char path[128];
    snprintf(path, sizeof path, "/system_data/priv/appmeta/%s/param.sfo", tid);
    FILE* f = fopen(path, "rb");
    if (!f) return -1;
    size_t len = fread(buf, 1, sizeof buf, f);
    fclose(f);
    if (len < 20 || buf[0] != 0 || buf[1] != 'P' || buf[2] != 'S' || buf[3] != 'F') return -1;
    uint32_t kt = buf[8] | (buf[9] << 8) | (buf[10] << 16) | ((uint32_t)buf[11] << 24);
    uint32_t dt = buf[12] | (buf[13] << 8) | (buf[14] << 16) | ((uint32_t)buf[15] << 24);
    uint32_t cnt = buf[16] | (buf[17] << 8) | (buf[18] << 16) | ((uint32_t)buf[19] << 24);
    for (uint32_t i = 0; i < cnt && 20 + (size_t)(i + 1) * 16 <= len; i++) {
        unsigned char* e = buf + 20 + (size_t)i * 16;
        uint32_t ko = e[0] | (e[1] << 8);
        uint32_t dl = e[4] | (e[5] << 8) | (e[6] << 16) | ((uint32_t)e[7] << 24);
        uint32_t doff = e[12] | (e[13] << 8) | (e[14] << 16) | ((uint32_t)e[15] << 24);
        if ((size_t)kt + ko + 6 > len) continue;
        if (strcmp((char*)buf + kt + ko, "TITLE")) continue;
        size_t k = 0;
        for (uint32_t j = 0; j < dl && (size_t)dt + doff + j < len && k < n - 1 && k < 100; j++) {
            unsigned char c = buf[dt + doff + j];
            if (!c) break;
            if (c == '"' || c == '\\' || c < 0x20) c = ' ';
            out[k++] = (char)c;
        }
        out[k] = 0;
        return k ? 0 : -1;
    }
    return -1;
}

static int get_name(const char* tid, char* out, size_t n) {
    if (get_name_json(tid, out, n) == 0) return 0;
    return get_name_sfo(tid, out, n);
}

static void poll_game(void) {
    char seen[32] = "";
    int id = sceSystemServiceGetAppIdOfRunningBigApp();
    if (id >= 0 && sceSystemServiceGetAppTitleId(id, seen) != 0) seen[0] = 0;
    if (strcmp(seen, g_cur)) {
        strcpy(g_cur, seen);
        g_start = time(NULL);
        g_name[0] = 0;
        if (g_cur[0] && get_name(g_cur, g_name, sizeof g_name)) snprintf(g_name, sizeof g_name, "%s", g_cur);
    }
}

static int resolve(const char* host, uint32_t* addr) {
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, "443", &hints, &res) == 0 && res) {
        *addr = ((struct sockaddr_in*)res->ai_addr)->sin_addr.s_addr;
        freeaddrinfo(res);
        return 0;
    }
    if (sceNetResolverCreate && sceNetResolverStartNtoa && g_pool >= 0) {
        int rid = sceNetResolverCreate("rpc", g_pool, 0);
        if (rid >= 0) {
            uint32_t a = 0;
            int r = sceNetResolverStartNtoa(rid, host, &a, 2, 3, 0);
            if (sceNetResolverDestroy) sceNetResolverDestroy(rid);
            if (r >= 0 && a) { *addr = a; return 0; }
            g_err = r;
        }
    }
    return -1;
}

static int tcp_open(const char* host) {
    uint32_t a;
    if (resolve(host, &a)) return -1;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -2;
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons(443);
    sa.sin_addr.s_addr = a;
    if (connect(fd, (struct sockaddr*)&sa, sizeof sa)) { g_err = errno; close(fd); return -3; }
    g_fd = fd;
    return 0;
}

static int bio_send(void* c, const unsigned char* b, size_t n) {
    (void)c;
    ssize_t r = send(g_fd, b, n, MSG_NOSIGNAL);
    if (r < 0) return (errno == EAGAIN || errno == EINTR) ? MBEDTLS_ERR_SSL_WANT_WRITE : -1;
    return (int)r;
}

static int bio_recv(void* c, unsigned char* b, size_t n) {
    (void)c;
    struct pollfd p;
    p.fd = g_fd; p.events = POLLIN; p.revents = 0;
    int pr = poll(&p, 1, g_to);
    if (pr == 0) return MBEDTLS_ERR_SSL_WANT_READ;
    if (pr < 0) return errno == EINTR ? MBEDTLS_ERR_SSL_WANT_READ : -1;
    ssize_t r = recv(g_fd, b, n, 0);
    if (r < 0) return (errno == EAGAIN || errno == EINTR) ? MBEDTLS_ERR_SSL_WANT_READ : -1;
    if (r == 0) return -2;
    return (int)r;
}

static void tls_close(void) {
    if (g_inited) { mbedtls_ssl_free(&ssl); mbedtls_ssl_config_free(&conf); g_inited = 0; }
    if (g_fd >= 0) { close(g_fd); g_fd = -1; }
}

static int tls_open(const char* host) {
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    g_inited = 1;
    if (mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) return -11;
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &drbg);
    mbedtls_ssl_conf_max_tls_version(&conf, MBEDTLS_SSL_VERSION_TLS1_2);
    if (mbedtls_ssl_setup(&ssl, &conf)) return -12;
    mbedtls_ssl_set_hostname(&ssl, host);
    mbedtls_ssl_set_bio(&ssl, NULL, bio_send, bio_recv, NULL);
    g_to = 1000;
    int r = 0;
    for (int i = 0; i < 30; i++) {
        r = mbedtls_ssl_handshake(&ssl);
        if (r == 0) { g_to = 200; return 0; }
        if (r != MBEDTLS_ERR_SSL_WANT_READ && r != MBEDTLS_ERR_SSL_WANT_WRITE) { g_err = r; return -13; }
    }
    g_err = r;
    return -14;
}

static int tls_write_all(const unsigned char* b, size_t n) {
    size_t o = 0; int tries = 0;
    while (o < n) {
        int r = mbedtls_ssl_write(&ssl, b + o, n - o);
        if (r > 0) { o += r; tries = 0; continue; }
        if ((r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE) && ++tries < 100) continue;
        g_err = r;
        return -1;
    }
    return 0;
}

static int rd(unsigned char* b, size_t n, int ms) {
    size_t o = 0; int waited = 0;
    while (o < n) {
        int r = mbedtls_ssl_read(&ssl, b + o, n - o);
        if (r > 0) { o += r; waited = 0; continue; }
        if (r == MBEDTLS_ERR_SSL_WANT_READ || r == MBEDTLS_ERR_SSL_WANT_WRITE) {
            waited += g_to;
            if (waited >= ms) return o == 0 ? 0 : -1;
            continue;
        }
        g_err = r;
        return -1;
    }
    return 1;
}

static int https_req(const char* host, const char* req, size_t rl, char* resp, size_t rsz) {
    resp[0] = 0;
    if (tcp_open(host)) return -1;
    if (tls_open(host)) { tls_close(); return -2; }
    if (tls_write_all((const unsigned char*)req, rl)) { tls_close(); return -3; }
    size_t o = 0; int waited = 0;
    while (o < rsz - 1) {
        int n = mbedtls_ssl_read(&ssl, (unsigned char*)resp + o, rsz - 1 - o);
        if (n > 0) { o += n; waited = 0; continue; }
        if (n == MBEDTLS_ERR_SSL_WANT_READ || n == MBEDTLS_ERR_SSL_WANT_WRITE) {
            waited += g_to;
            if (waited >= 8000) break;
            continue;
        }
        break;
    }
    resp[o] = 0;
    tls_close();
    return (int)o;
}

static int http_status(const char* resp) {
    int st = 0;
    sscanf(resp, "HTTP/%*s %d", &st);
    return st;
}

static void urlenc(const char* s, char* o, size_t n) {
    static const char* hex = "0123456789ABCDEF";
    size_t j = 0;
    for (size_t i = 0; s[i] && j + 4 < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == 0xE2 && (unsigned char)s[i+1] == 0x84 && (unsigned char)s[i+2] == 0xA2) { i += 2; continue; }
        if (c == 0xC2 && (unsigned char)s[i+1] == 0xAE) { i += 1; continue; }
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') o[j++] = (char)c;
        else if (c == ' ') o[j++] = '+';
        else { o[j++] = '%'; o[j++] = hex[c >> 4]; o[j++] = hex[c & 15]; }
    }
    o[j] = 0;
}

static void norm(const char* s, char* o, size_t n) {
    size_t j = 0;
    for (size_t i = 0; s[i] && j < n - 1; i++) {
        if (s[i] == '\\' && s[i+1] == 'u') { i += 5; continue; }
        unsigned char c = (unsigned char)s[i];
        if (isalnum(c)) o[j++] = (char)tolower(c);
    }
    o[j] = 0;
}

static int register_asset(const char* url) {
    char body[700], req[1500], resp[3000];
    g_asset[0] = 0;
    int bl = snprintf(body, sizeof body, "{\"urls\":[\"%s\"]}", url);
    int n = snprintf(req, sizeof req,
        "POST /api/v9/applications/%s/external-assets HTTP/1.0\r\nHost: discord.com\r\nAuthorization: %s\r\n"
        "Content-Type: application/json\r\nContent-Length: %d\r\nUser-Agent: Mozilla/5.0\r\n\r\n%s",
        g_appid, g_token, bl, body);
    https_req("discord.com", req, n, resp, sizeof resp);
    int st = http_status(resp);
    char* p = strstr(resp, "\"external_asset_path\":\"");
    if (p) {
        p += 23;
        strcpy(g_asset, "mp:");
        size_t j = 3;
        while (*p && *p != '"' && j < sizeof g_asset - 1) g_asset[j++] = *p++;
        g_asset[j] = 0;
    }
    return st;
}

static int load_override(const char* tid, char* url, size_t un, char* name, size_t nn) {
    FILE* f = fopen("/data/discord_covers.txt", "r");
    if (!f) return 0;
    char line[700];
    int found = 0;
    while (fgets(line, sizeof line, f)) {
        size_t L = strlen(line);
        while (L && (line[L-1] == '\n' || line[L-1] == '\r' || line[L-1] == ' ')) line[--L] = 0;
        char* bar = strchr(line, '|');
        if (!bar) continue;
        *bar = 0;
        if (strcmp(line, tid)) continue;
        char* u = bar + 1;
        char* bar2 = strchr(u, '|');
        if (bar2) {
            *bar2 = 0;
            snprintf(name, nn, "%s", bar2 + 1);
            for (char* c = name; *c; c++) if (*c == '"' || *c == '\\') *c = ' ';
        }
        snprintf(url, un, "%s", u);
        found = 1;
        break;
    }
    fclose(f);
    return found;
}

static void list_dir(const char* path, char* out, size_t n) {
    size_t l = strlen(out);
    DIR* d = opendir(path);
    if (!d) { snprintf(out + l, n - l, " [%s: x]", path); return; }
    l += snprintf(out + l, n - l, " [%s:", path);
    struct dirent* e;
    int c = 0;
    while ((e = readdir(d)) && c < 12) {
        if (e->d_name[0] == '.') continue;
        l += snprintf(out + l, n - l, " %s", e->d_name);
        c++;
    }
    closedir(d);
    snprintf(out + strlen(out), n - strlen(out), "]");
}

static int g_last_st = 0;
static char g_cdbg[96];

static int url_ok(const char* url) {
    g_last_st = -1;
    if (strncmp(url, "https://", 8)) return 0;
    char host[100], req[1000];
    const char* h = url + 8;
    const char* sl = strchr(h, '/');
    if (!sl) return 0;
    size_t hl = (size_t)(sl - h);
    if (hl >= sizeof host) return 0;
    memcpy(host, h, hl);
    host[hl] = 0;
    int n = snprintf(req, sizeof req,
        "GET %s HTTP/1.0\r\nHost: %s\r\nRange: bytes=0-0\r\nUser-Agent: Mozilla/5.0\r\n\r\n", sl, host);
    static char resp[1024];
    https_req(host, req, n, resp, sizeof resp);
    g_last_st = http_status(resp);
    return g_last_st == 200 || g_last_st == 206;
}

static int steam_url2(const char* name, char* out, size_t on) {
    static char resp[40000];
    static char big[300000];
    char enc[400], req[800], want[160], got[160], raw[200], cand[512];
    out[0] = 0;
    urlenc(name, enc, sizeof enc);
    int n = snprintf(req, sizeof req,
        "GET /api/storesearch/?term=%s&l=english&cc=us HTTP/1.0\r\nHost: store.steampowered.com\r\n"
        "User-Agent: Mozilla/5.0\r\nAccept: application/json\r\n\r\n", enc);
    https_req("store.steampowered.com", req, n, resp, sizeof resp);
    int st = http_status(resp);
    norm(name, want, sizeof want);
    long id = 0;
    char* p = resp;
    while ((p = strstr(p, "\"name\":\"")) != NULL) {
        p += 8;
        size_t j = 0;
        while (*p && *p != '"' && j < sizeof raw - 2) {
            if (*p == '\\' && p[1]) raw[j++] = *p++;
            raw[j++] = *p++;
        }
        raw[j] = 0;
        norm(raw, got, sizeof got);
        if (strcmp(got, want)) continue;
        char* nx = strstr(p, "\"name\":\"");
        char* idp = strstr(p, "\"id\":");
        if (idp && (!nx || idp < nx)) id = strtol(idp + 5, NULL, 10);
        break;
    }
    if (id <= 0) return st;

    int sa = 0, sb = 0, sc = 0;
    snprintf(cand, sizeof cand, "https://cdn.cloudflare.steamstatic.com/steam/apps/%ld/library_600x900.jpg", id);
    if (url_ok(cand)) snprintf(out, on, "%s", cand);
    sa = g_last_st;

    if (!out[0]) {
        n = snprintf(req, sizeof req,
            "GET /api/appdetails?appids=%ld&filters=basic&l=english&cc=us HTTP/1.0\r\nHost: store.steampowered.com\r\n"
            "User-Agent: Mozilla/5.0\r\n\r\n", id);
        https_req("store.steampowered.com", req, n, big, sizeof big);
        char* h = strstr(big, "\"header_image\":\"");
        if (h) {
            h += 16;
            size_t k = 0;
            while (*h && *h != '"' && k < sizeof cand - 2) {
                if (*h == '\\' && h[1] == '/') h++;
                cand[k++] = *h++;
            }
            cand[k] = 0;
            if (url_ok(cand)) snprintf(out, on, "%s", cand);
            sb = g_last_st;
        } else {
            sb = -1;
        }
    }

    if (!out[0]) {
        snprintf(cand, sizeof cand, "https://cdn.cloudflare.steamstatic.com/steam/apps/%ld/header.jpg", id);
        if (url_ok(cand)) snprintf(out, on, "%s", cand);
        sc = g_last_st;
    }

    snprintf(g_cdbg, sizeof g_cdbg, "id=%ld lib=%d det=%d hdr=%d", id, sa, sb, sc);
    notify(g_cdbg);
    return st;
}

static void prepare_cover(void) {
    char url[512] = "", nm[128] = "", msg[600], path[96];
    strcpy(g_cover_for, g_cur);
    g_asset[0] = 0;
    int ov = load_override(g_cur, url, sizeof url, nm, sizeof nm);
    if (nm[0]) snprintf(g_name, sizeof g_name, "%s", nm);
    if (!ov && !strcmp(g_name, g_cur)) {
        snprintf(msg, sizeof msg, "DIR %s", g_cur);
        snprintf(path, sizeof path, "/user/appmeta/%s", g_cur);
        list_dir(path, msg, sizeof msg);
        snprintf(path, sizeof path, "/system_data/priv/appmeta/%s", g_cur);
        list_dir(path, msg, sizeof msg);
        notify(msg);
    }
    if (!g_appid[0]) return;
    int wst = -1, dst = -1;
    if (!url[0]) wst = steam_url2(g_name, url, sizeof url);
    if (url[0]) dst = register_asset(url);
    snprintf(msg, sizeof msg, "Capa %s [%s]: busca=%d discord=%d %s ...%s", g_name, g_cur, wst, dst,
             g_asset[0] ? "ok" : "sem capa", strlen(url) > 28 ? url + strlen(url) - 28 : url);
    notify(msg);
}

static int ws_upgrade(void) {
    unsigned char k[16];
    mbedtls_ctr_drbg_random(&drbg, k, 16);
    char b64[40]; size_t ol = 0;
    mbedtls_base64_encode((unsigned char*)b64, sizeof b64, &ol, k, 16);
    b64[ol] = 0;
    char req[512];
    int n = snprintf(req, sizeof req,
        "GET /?v=10&encoding=json HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nUpgrade: websocket\r\n"
        "Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n", GW, b64);
    if (tls_write_all((unsigned char*)req, n)) return -1;
    char resp[1024]; size_t o = 0;
    while (o < sizeof resp - 1) {
        unsigned char c;
        if (rd(&c, 1, 10000) != 1) return -2;
        resp[o++] = (char)c; resp[o] = 0;
        if (o >= 4 && !memcmp(resp + o - 4, "\r\n\r\n", 4)) break;
    }
    return strstr(resp, " 101 ") ? 0 : -3;
}

static int ws_send(int op, const char* p, size_t n) {
    static unsigned char buf[4096];
    if (n > sizeof buf - 20) return -1;
    size_t h = 0;
    buf[h++] = 0x80 | op;
    if (n < 126) buf[h++] = 0x80 | (unsigned char)n;
    else { buf[h++] = 0x80 | 126; buf[h++] = (unsigned char)(n >> 8); buf[h++] = (unsigned char)(n & 255); }
    unsigned char m[4];
    mbedtls_ctr_drbg_random(&drbg, m, 4);
    memcpy(buf + h, m, 4); h += 4;
    for (size_t i = 0; i < n; i++) buf[h + i] = (unsigned char)p[i] ^ m[i & 3];
    return tls_write_all(buf, h + n);
}

static int ws_recv(char* head, size_t hsz, int* op, size_t* plen) {
    unsigned char h[2], tmp[1024];
    int r = rd(h, 1, 200);
    if (r <= 0) return r;
    if (rd(h + 1, 1, 15000) != 1) return -1;
    *op = h[0] & 0x0f;
    uint64_t len = h[1] & 0x7f;
    if (len == 126) { unsigned char e[2]; if (rd(e, 2, 15000) != 1) return -1; len = ((uint64_t)e[0] << 8) | e[1]; }
    else if (len == 127) { unsigned char e[8]; if (rd(e, 8, 15000) != 1) return -1; len = 0; for (int i = 0; i < 8; i++) len = (len << 8) | e[i]; }
    size_t cap = 0, remaining = (size_t)len;
    *plen = remaining;
    while (remaining) {
        size_t c = remaining > sizeof tmp ? sizeof tmp : remaining;
        if (rd(tmp, c, 15000) != 1) return -1;
        if (cap < hsz - 1) { size_t k = hsz - 1 - cap; if (k > c) k = c; memcpy(head + cap, tmp, k); cap += k; }
        remaining -= c;
    }
    head[cap] = 0;
    return 1;
}

static long json_num(const char* s, const char* key) {
    const char* p = strstr(s, key);
    if (!p) return -1;
    p += strlen(key);
    while (*p == ' ') p++;
    if (*p < '0' || *p > '9') return -1;
    return strtol(p, NULL, 10);
}

static void act_json(char* out, size_t n) {
    if (!g_cur[0]) { snprintf(out, n, "[]"); return; }
    if (g_asset[0] && g_appid[0] && !strcmp(g_cover_for, g_cur))
        snprintf(out, n,
            "[{\"name\":\"%s\",\"type\":0,\"application_id\":\"%s\",\"timestamps\":{\"start\":%lld},"
            "\"assets\":{\"large_image\":\"%s\",\"large_text\":\"%s\"}}]",
            g_name, g_appid, (long long)g_start * 1000, g_asset, g_name);
    else
        snprintf(out, n, "[{\"name\":\"%s\",\"type\":0,\"timestamps\":{\"start\":%lld}}]", g_name, (long long)g_start * 1000);
}

static int send_presence(void) {
    char a[1000], b[1400];
    act_json(a, sizeof a);
    snprintf(b, sizeof b, "{\"op\":3,\"d\":{\"since\":0,\"activities\":%s,\"status\":\"online\",\"afk\":false}}", a);
    return ws_send(1, b, strlen(b));
}

static int send_identify(void) {
    char a[1000], b[2400];
    act_json(a, sizeof a);
    snprintf(b, sizeof b,
        "{\"op\":2,\"d\":{\"token\":\"%s\",\"properties\":{\"os\":\"Windows\",\"browser\":\"Chrome\",\"device\":\"\"},"
        "\"presence\":{\"status\":\"online\",\"since\":0,\"activities\":%s,\"afk\":false},\"compress\":false}}", g_token, a);
    return ws_send(1, b, strlen(b));
}

static int session(void) {
    int r;
    if (g_cur[0] && strcmp(g_cover_for, g_cur)) prepare_cover();
    if ((r = tcp_open(GW))) { report("conexao", r); return -1; }
    if ((r = tls_open(GW))) { report("tls", r); tls_close(); return -1; }
    if ((r = ws_upgrade())) { report("websocket", r); tls_close(); return -1; }

    char head[512]; int op; size_t len;
    long interval = 0;
    long long t0 = mono_ms();
    while (mono_ms() - t0 < 15000) {
        r = ws_recv(head, sizeof head, &op, &len);
        if (r < 0) break;
        if (r == 1 && op == 1 && json_num(head, "\"op\":") == 10) { interval = json_num(head, "\"heartbeat_interval\":"); break; }
    }
    if (interval <= 0) { report("hello", 0); tls_close(); return -1; }
    if (send_identify()) { report("identify", 0); tls_close(); return -1; }

    char sent[32];
    strcpy(sent, g_cur);
    long long next_hb = mono_ms() + interval / 2, lastpoll = 0;
    int ack = 1, ready = 0;
    long seq = -1;

    for (;;) {
        long long now = mono_ms();
        if (now >= next_hb) {
            if (!ack) { report("sem ack", 0); break; }
            char hb[64];
            if (seq >= 0) snprintf(hb, sizeof hb, "{\"op\":1,\"d\":%ld}", seq);
            else snprintf(hb, sizeof hb, "{\"op\":1,\"d\":null}");
            if (ws_send(1, hb, strlen(hb))) { report("heartbeat", 0); break; }
            ack = 0;
            next_hb = now + interval;
        }
        r = ws_recv(head, sizeof head, &op, &len);
        if (r < 0) { report("leitura", 0); break; }
        if (r == 1) {
            if (op == 9) { ws_send(10, head, len > 125 ? 125 : len); }
            else if (op == 8) { report("fechado", ((unsigned char)head[0] << 8) | (unsigned char)head[1]); break; }
            else if (op == 1) {
                long g = json_num(head, "\"op\":"), s = json_num(head, "\"s\":");
                if (s >= 0) seq = s;
                if (g == 11) ack = 1;
                else if (g == 7 || g == 9) break;
                else if (g == 0 && !ready && strstr(head, "\"READY\"")) { ready = 1; g_last[0] = 0; notify("Discord RPC: conectado"); }
            }
        }
        if (now - lastpoll >= 3000) {
            lastpoll = now;
            poll_game();
            if (strcmp(g_cur, sent)) {
                if (!g_cur[0]) { send_presence(); ws_send(8, "\x03\xe8", 2); }
                break;
            }
        }
    }
    tls_close();
    return 0;
}

int main(void) {
    while (load_token()) sleep(15);
    read_appid();
    if (sceNetInit) sceNetInit();
    if (sceNetPoolCreate) g_pool = sceNetPoolCreate("rpcpool", 64 * 1024, 0);
    psa_crypto_init();
    mbedtls_entropy_init(&ent);
    mbedtls_ctr_drbg_init(&drbg);
    if (mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &ent, (const unsigned char*)"rpc", 3)) { notify("RPC erro: rng"); return 1; }
    notify(g_appid[0] ? "Discord RPC: iniciado (com capa)" : "Discord RPC: iniciado (sem appid)");

    for (;;) {
        poll_game();
        if (g_cur[0]) {
            int r = session();
            sleep(r < 0 ? 20 : 2);
        } else {
            sleep(5);
        }
    }
    return 0;
}
