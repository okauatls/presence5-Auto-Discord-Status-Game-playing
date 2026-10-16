#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <poll.h>
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

#define HOST "gateway.discord.gg"

static char g_token[256], g_cur[32], g_name[128], g_last[160];
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

static int tcp_open(void) {
    uint32_t a;
    if (resolve(HOST, &a)) return -1;
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

static int tls_open(void) {
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    g_inited = 1;
    if (mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) return -11;
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &drbg);
    mbedtls_ssl_conf_max_tls_version(&conf, MBEDTLS_SSL_VERSION_TLS1_2);
    if (mbedtls_ssl_setup(&ssl, &conf)) return -12;
    mbedtls_ssl_set_hostname(&ssl, HOST);
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

static int ws_upgrade(void) {
    unsigned char k[16];
    mbedtls_ctr_drbg_random(&drbg, k, 16);
    char b64[40]; size_t ol = 0;
    mbedtls_base64_encode((unsigned char*)b64, sizeof b64, &ol, k, 16);
    b64[ol] = 0;
    char req[512];
    int n = snprintf(req, sizeof req,
        "GET /?v=10&encoding=json HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nUpgrade: websocket\r\n"
        "Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n", HOST, b64);
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

/* 1 = frame lido, 0 = nada (ocioso), -1 = erro */
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
    snprintf(out, n, "[{\"name\":\"%s\",\"type\":0,\"timestamps\":{\"start\":%lld}}]", g_name, (long long)g_start * 1000);
}

static int send_presence(void) {
    char a[400], b[900];
    act_json(a, sizeof a);
    snprintf(b, sizeof b, "{\"op\":3,\"d\":{\"since\":0,\"activities\":%s,\"status\":\"online\",\"afk\":false}}", a);
    return ws_send(1, b, strlen(b));
}

static int send_identify(void) {
    char a[400], b[1800];
    act_json(a, sizeof a);
    snprintf(b, sizeof b,
        "{\"op\":2,\"d\":{\"token\":\"%s\",\"properties\":{\"os\":\"Windows\",\"browser\":\"Chrome\",\"device\":\"\"},"
        "\"presence\":{\"status\":\"online\",\"since\":0,\"activities\":%s,\"afk\":false},\"compress\":false}}", g_token, a);
    return ws_send(1, b, strlen(b));
}

static int session(void) {
    int r;
    if ((r = tcp_open())) { report("conexao", r); return -1; }
    if ((r = tls_open())) { report("tls", r); tls_close(); return -1; }
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
                strcpy(sent, g_cur);
                send_presence();
                if (!g_cur[0]) { ws_send(8, "\x03\xe8", 2); break; }
            }
        }
    }
    tls_close();
    return 0;
}

int main(void) {
    while (load_token()) sleep(15);
    if (sceNetInit) sceNetInit();
    if (sceNetPoolCreate) g_pool = sceNetPoolCreate("rpcpool", 64 * 1024, 0);
    psa_crypto_init();
    mbedtls_entropy_init(&ent);
    mbedtls_ctr_drbg_init(&drbg);
    if (mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &ent, (const unsigned char*)"rpc", 3)) { notify("RPC erro: rng"); return 1; }
    notify("Discord RPC: iniciado");

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
