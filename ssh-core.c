#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <libssh2.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_LOG_PATH       "/tmp/etc/passwall-ssh.log"
#define AUTH_FAILED_FILE       "/tmp/etc/passwall-ssh.auth_failed"
#define KEX_FAILED_FILE        "/tmp/etc/passwall-ssh.kex_failed"
#define NEED_RESTART_FILE      "/tmp/etc/passwall-ssh.need_restart"
#define ROTATE_STATE_FILE      "/tmp/etc/passwall-rotate.tmp"
#define SSH_CLIENT_BANNER      "SSH-2.0-OpenSSH_9.6"
#define DEFAULT_UA             "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

#define MAX_HTTP_HEADER        16384
#define MAX_HTTP_SKIP_BODY     (16U * 1024U * 1024U)
#define RELAY_BUF_SIZE         32768
#define MAX_EVENTS             128
#define DEFAULT_MAX_CLIENTS    64
#define MAX_CLIENTS_LIMIT      256
#define DEFAULT_IDLE_TIMEOUT   600
#define HANDSHAKE_TIMEOUT_MS   15000
#define SOCKS_HS_TIMEOUT_SEC   15
#define SSH_OPEN_SOFT_TO_MS    15000
#define SSH_OPEN_HARD_TO_MS    30000

static volatile sig_atomic_t g_stop = 0;
static const char *g_log_path = DEFAULT_LOG_PATH;
static const char *g_kbd_password = "";

/* Sentinel tag untuk O(1) epoll dispatch */
static int g_listen_tag = 0;
static int g_upstream_tag = 0;

typedef struct {
    uint8_t *data;
    size_t   cap;
    size_t   head;
    size_t   tail;
    size_t   used;
} rb_t;

typedef struct {
    int      fd;
    SSL     *ssl;
    uint32_t ssl_want_events; /* EPOLLIN / EPOLLOUT jika OpenSSL WANT_READ/WANT_WRITE */
    uint64_t rx_seq;
    size_t   skip_ssh_banner_bytes;
    int      expect_connect_resp;
    int      tunnel_established;
    int      last_http_code;
    char     last_status[128];
    uint8_t  pre_buf[32768];
    size_t   pre_off;
    size_t   pre_len;
    size_t   http_skip_remaining;
    int      http_pending_tunnel;
    int      http_close_delimited;
    int      allow_http_200_tunnel;
    int      http_in_chunked;
    int      http_chunk_state; /* 0=size, 1=data, 2=delim, 3=trailers */
    size_t   http_chunk_rem;
    time_t   last_activity;
} upstream_ctx_t;

typedef enum {
    ST_SOCKS_GREETING = 0,
    ST_SOCKS_REQUEST,
    ST_SSH_OPENING,
    ST_RELAY,
    ST_CLOSING
} client_state_t;

typedef enum {
    PENDING_NONE = 0,
    PENDING_OPEN,
    PENDING_WRITE,
    PENDING_SEND_EOF,
    PENDING_READ,
    PENDING_FREE,
    PENDING_KEEPALIVE
} pending_op_t;

typedef struct client_conn {
    int            fd;
    int            in_epoll;
    client_state_t state;
    uint32_t       epoll_events;
    time_t         accepted_at;
    long long      open_started_ms;
    long long      ctrl_close_deadline_ms;
    long long      last_activity_ms;

    uint8_t  req_buf[512];
    size_t   req_len;
    uint8_t  ctrl_buf[16];
    size_t   ctrl_off;
    size_t   ctrl_len;
    int      close_after_ctrl;

    uint8_t  early_buf[512];
    size_t   early_len;

    char     target_host[256];
    uint16_t target_port;

    LIBSSH2_CHANNEL *channel;
    int              abort_on_open;
    int              abort_on_pending;
    int              need_send_eof;
    int              client_eof;
    int              client_dead;
    int              hup_pending;
    int              rdhup_pending;
    int              ssh_eof;

    /* Pin argumen (ptr, len) per-channel saat EAGAIN */
    int            write_pending;
    const uint8_t *write_pending_ptr;
    size_t         write_pending_len;
    int            write_waiting_window;
    uint64_t       write_wait_rx_seq;
    int            write_window_log_active;
    int            write_window_log_seen;
    int            write_window_eagain_logged;
    int            write_window_final_logged;
    size_t         c2s_peak_used;

    int            read_pending;
    uint8_t       *read_pending_ptr;
    size_t         read_pending_len;

    rb_t c2s;
    rb_t s2c;

    struct client_conn *prev;
    struct client_conn *next;
} client_conn_t;

static client_conn_t *g_clients = NULL;
static int            g_client_count = 0;
static client_conn_t *g_opening_client = NULL;
static client_conn_t *g_pending_client = NULL;
static pending_op_t   g_pending_op = PENDING_NONE;

/* ============================================================
 * RING BUFFER (ZERO MEMMOVE, LAZY ALLOCATION)
 * ============================================================ */
static int rb_init(rb_t *r, size_t cap) {
    if (r->data) return 0;
    r->data = malloc(cap);
    if (!r->data) return -1;
    r->cap = cap;
    r->head = 0;
    r->tail = 0;
    r->used = 0;
    return 0;
}

static void rb_free(rb_t *r) {
    free(r->data);
    r->data = NULL;
    r->cap = 0;
    r->head = 0;
    r->tail = 0;
    r->used = 0;
}

static inline size_t rb_free_space(const rb_t *r) {
    return r->cap - r->used;
}

static uint8_t *rb_write_slice(rb_t *r, size_t *avail) {
    if (!r->data || r->used >= r->cap) {
        *avail = 0;
        return NULL;
    }
    if (r->tail >= r->head) {
        *avail = r->cap - r->tail;
    } else {
        *avail = r->head - r->tail;
    }
    return r->data + r->tail;
}

static void rb_commit_write(rb_t *r, size_t n) {
    r->tail = (r->tail + n) % r->cap;
    r->used += n;
}

static const uint8_t *rb_read_slice(const rb_t *r, size_t *avail) {
    if (!r->data || r->used == 0) {
        *avail = 0;
        return NULL;
    }
    if (r->head < r->tail) {
        *avail = r->tail - r->head;
    } else {
        *avail = r->cap - r->head;
    }
    return r->data + r->head;
}

static void rb_commit_read(rb_t *r, size_t n, int keep_pos) {
    r->head = (r->head + n) % r->cap;
    r->used -= n;
    if (r->used == 0 && !keep_pos) {
        r->head = 0;
        r->tail = 0;
    }
}

static int rb_push(rb_t *r, const uint8_t *src, size_t len) {
    if (len == 0) return 0;
    if (rb_free_space(r) < len) return -1;
    size_t left = len;
    const uint8_t *p = src;
    while (left > 0) {
        size_t avail = 0;
        uint8_t *dst = rb_write_slice(r, &avail);
        if (!dst || avail == 0) return -1;
        size_t take = left < avail ? left : avail;
        memcpy(dst, p, take);
        rb_commit_write(r, take);
        p += take;
        left -= take;
    }
    return 0;
}

/* ============================================================
 * LOGGER & MARKERS
 * ============================================================ */
static void log_raw(const char *fmt, ...) {
    char buf[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    if (!g_log_path || strcmp(g_log_path, "-") == 0) {
        printf("%s\n", buf);
        fflush(stdout);
        return;
    }
    FILE *f = fopen(g_log_path, "a");
    if (f) {
        fprintf(f, "%s\n", buf);
        fclose(f);
    }
}

static void fmt_now(char *out, size_t sz) {
    time_t t = time(NULL);
    struct tm tm_now;
    localtime_r(&t, &tm_now);
    strftime(out, sz, "%Y-%m-%d %H:%M:%S", &tm_now);
}

static void log_blue(const char *fmt, ...) {
    char msg[1536], ts[32];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    fmt_now(ts, sizeof(ts));
    log_raw("<span color=\"#3C86AB\">[%s] %s</span>", ts, msg);
}

static void log_yellow(const char *fmt, ...) {
    char msg[1536], ts[32];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    fmt_now(ts, sizeof(ts));
    log_raw("<font color=\"#FFFF00\">[%s] %s</font>", ts, msg);
}

static void log_red(const char *fmt, ...) {
    char msg[1536], ts[32];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    fmt_now(ts, sizeof(ts));
    log_raw("<font color=\"#FF0000\">[%s] %s</font>", ts, msg);
}

static void note_c2s_buffer_peak(client_conn_t *c) {
    if (c && c->c2s.used > c->c2s_peak_used)
        c->c2s_peak_used = c->c2s.used;
}

/* Keep diagnostic state separate from write_waiting_window, which is reset
 * whenever inbound SSH traffic allows the relay loop to retry a blocked write. */
static void note_channel_window_blocked(client_conn_t *c, int eagain_zero) {
    if (!c) return;
    if (eagain_zero && !c->write_window_eagain_logged) {
        c->write_window_eagain_logged = 1;
        if (c->write_window_log_active) {
            log_yellow("SSH channel zero-window confirmed by EAGAIN (write_window=0) (%s:%u)",
                       c->target_host, (unsigned)c->target_port);
        }
    }
    if (c->write_window_log_active) return;
    c->write_window_log_active = 1;
    c->write_window_log_seen = 1;
    if (eagain_zero) {
        log_yellow("SSH channel window penuh (EAGAIN; write_window=0); menunggu window-adjust (%s:%u)",
                   c->target_host, (unsigned)c->target_port);
    } else {
        log_yellow("SSH channel window penuh; menunggu window-adjust (%s:%u)",
                   c->target_host, (unsigned)c->target_port);
    }
}

static void note_channel_window_recovered(client_conn_t *c) {
    if (!c || !c->write_window_log_active) return;
    log_blue("SSH channel window recovered; write resumed (%s:%u; c2s_pending=%zu/%zu)",
             c->target_host, (unsigned)c->target_port, c->c2s.used, c->c2s.cap);
    c->write_window_log_active = 0;
}

static void log_channel_buffer_final(client_conn_t *c) {
    if (!c || !c->write_window_log_seen || c->write_window_final_logged) return;
    note_c2s_buffer_peak(c);
    if (!c->write_window_log_active && c->c2s.used == 0) {
        log_blue("SSH channel buffer drained after window recovery (%s:%u; queued=0/%zu; peak=%zu/%zu)",
                 c->target_host, (unsigned)c->target_port,
                 c->c2s.cap, c->c2s_peak_used, c->c2s.cap);
    } else {
        log_yellow("SSH channel buffer not drained at close (%s:%u; queued=%zu/%zu; peak=%zu/%zu; window_blocked=%d)",
                   c->target_host, (unsigned)c->target_port,
                   c->c2s.used, c->c2s.cap, c->c2s_peak_used, c->c2s.cap,
                   c->write_window_log_active);
    }
    c->write_window_final_logged = 1;
}

static void write_marker(const char *path, const char *msg) {
    FILE *f = fopen(path, "w");
    if (f) {
        fprintf(f, "%s\n", msg ? msg : "");
        fclose(f);
    }
}

/* ============================================================
 * ENV, STRICT PARSING & PAYLOAD TRANSLATION
 * ============================================================ */
typedef struct {
    char transport[16];
    char host[256];
    char host_port[16];
    char username[128];
    char password[256];
    char proxy[256];
    char proxy_port[16];
    char sni[256];
    int  delay_ms;
    int  fix_crlf;
    char socks_addr[128];
    int  keepalive_sec;
    int  verify_tls;
    int  allow_remote_socks;
    int  allow_http_200_tunnel;
    int  idle_timeout_sec;
    char hostkey_fp[128]; /* Opsional: SHA256:<base64> atau 64-hex untuk pin host key */
    int  max_clients;
} app_cfg_t;

static void trim_ws(char *s) {
    size_t len = strlen(s);
    while (len > 0 && (s[len - 1] == '\n' || s[len - 1] == '\r' || s[len - 1] == ' ' || s[len - 1] == '\t'))
        s[--len] = '\0';
    char *p = s;
    while (*p == ' ' || *p == '\t') p++;
    if (p != s) memmove(s, p, strlen(p) + 1);
}

static int parse_int_range(const char *s, int min_val, int max_val, int *out) {
    if (!s || !*s || !out) return -1;
    errno = 0;
    char *end = NULL;
    long value = strtol(s, &end, 10);
    if (errno == ERANGE || end == s || *end != '\0' ||
        value < min_val || value > max_val) return -1;
    *out = (int)value;
    return 0;
}

static int parse_strict_dec_size(const char *s, size_t *out, size_t max_val) {
    if (!s || !isdigit((unsigned char)s[0])) return -1;
    size_t val = 0;
    for (const char *p = s; *p; p++) {
        if (!isdigit((unsigned char)*p)) return -1;
        size_t d = (size_t)(*p - '0');
        if (d > max_val || val > (max_val - d) / 10U) return -1;
        val = val * 10U + d;
    }
    *out = val;
    return 0;
}

static int parse_strict_hex_size(const char *s, size_t *out, size_t max_val) {
    if (!s || !isxdigit((unsigned char)s[0])) return -1;
    size_t val = 0;
    for (const char *p = s; *p; p++) {
        unsigned char ch = (unsigned char)*p;
        if (!isxdigit(ch)) {
            if (ch == ';' || ch == ' ' || ch == '\t') break;
            return -1;
        }
        size_t d;
        if (ch >= '0' && ch <= '9') d = (size_t)(ch - '0');
        else if (ch >= 'a' && ch <= 'f') d = (size_t)(ch - 'a' + 10);
        else d = (size_t)(ch - 'A' + 10);
        if (val > (max_val - d) / 16U) return -1;
        val = val * 16U + d;
    }
    *out = val;
    return 0;
}

static void load_env(const char *path, app_cfg_t *cfg) {
    FILE *f = fopen(path, "r");
    if (!f) { log_red("Gagal membuka env file: %s", path); exit(1); }
    char line[2048];
    while (fgets(line, sizeof(line), f)) {
        trim_ws(line);
        if (line[0] == '\0' || line[0] == '#') continue;
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        char *k = line, *v = eq + 1;
        trim_ws(k); trim_ws(v);
        size_t vlen = strlen(v);
        if (vlen >= 2 && ((v[0] == '\'' && v[vlen-1] == '\'') ||
                          (v[0] == '"' && v[vlen-1] == '"'))) { v[vlen-1] = '\0'; v++; }
        int n = 0;
        if (!strcmp(k,"TRANSPORT")) snprintf(cfg->transport,sizeof(cfg->transport),"%s",v);
        else if (!strcmp(k,"HOST")) snprintf(cfg->host,sizeof(cfg->host),"%s",v);
        else if (!strcmp(k,"HOST_PORT")) snprintf(cfg->host_port,sizeof(cfg->host_port),"%s",v);
        else if (!strcmp(k,"USERNAME")) snprintf(cfg->username,sizeof(cfg->username),"%s",v);
        else if (!strcmp(k,"PASSWORD")) snprintf(cfg->password,sizeof(cfg->password),"%s",v);
        else if (!strcmp(k,"PROXY")) snprintf(cfg->proxy,sizeof(cfg->proxy),"%s",v);
        else if (!strcmp(k,"PROXY_PORT")) snprintf(cfg->proxy_port,sizeof(cfg->proxy_port),"%s",v);
        else if (!strcmp(k,"SNI")) snprintf(cfg->sni,sizeof(cfg->sni),"%s",v);
        else if (!strcmp(k,"SOCKS_ADDR")) snprintf(cfg->socks_addr,sizeof(cfg->socks_addr),"%s",v);
        else if (!strcmp(k,"HOSTKEY")) snprintf(cfg->hostkey_fp,sizeof(cfg->hostkey_fp),"%s",v);
        else if (!strcmp(k,"DELAY")) {
            if(parse_int_range(v,0,600000,&n)==0) cfg->delay_ms=n; else log_yellow("DELAY tidak valid; diabaikan");
        } else if (!strcmp(k,"KEEPALIVE")) {
            if(parse_int_range(v,0,3600,&n)==0) cfg->keepalive_sec=n; else log_yellow("KEEPALIVE tidak valid; diabaikan");
        } else if (!strcmp(k,"FIX_CRLF")) {
            if(parse_int_range(v,0,1,&n)==0) cfg->fix_crlf=n; else log_yellow("FIX_CRLF harus 0 atau 1");
        } else if (!strcmp(k,"VERIFY_TLS")) {
            if(parse_int_range(v,0,1,&n)==0) cfg->verify_tls=n; else log_yellow("VERIFY_TLS harus 0 atau 1");
        } else if (!strcmp(k,"ALLOW_REMOTE_SOCKS")) {
            if(parse_int_range(v,0,1,&n)==0) cfg->allow_remote_socks=n; else log_yellow("ALLOW_REMOTE_SOCKS harus 0 atau 1");
        } else if (!strcmp(k,"HTTP_200_TUNNEL")) {
            if(parse_int_range(v,0,1,&n)==0) cfg->allow_http_200_tunnel=n; else log_yellow("HTTP_200_TUNNEL harus 0 atau 1");
        } else if (!strcmp(k,"IDLE_TIMEOUT")) {
            if(parse_int_range(v,0,86400,&n)==0) cfg->idle_timeout_sec=n; else log_yellow("IDLE_TIMEOUT harus 0..86400");
        } else if (!strcmp(k,"MAX_CLIENTS")) {
            if(parse_int_range(v,1,MAX_CLIENTS_LIMIT,&n)==0) cfg->max_clients=n;
            else log_yellow("MAX_CLIENTS harus 1..%d",MAX_CLIENTS_LIMIT);
        }
    }
    fclose(f);
}

static char *read_entire_file(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long sz = ftell(f);
    if (sz < 0 || fseek(f, 0, SEEK_SET) != 0) { fclose(f); return NULL; }
    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t n = fread(buf, 1, (size_t)sz, f);
    buf[n] = '\0';
    fclose(f);
    return buf;
}

typedef struct {
    char  *data;
    size_t len;
    size_t cap;
} sbuf_t;

static void sbuf_append(sbuf_t *sb, const char *s, size_t n) {
    if (n == 0) return;
    if (sb->len + n + 1 > sb->cap) {
        size_t ncap = (sb->cap == 0) ? 4096 : sb->cap * 2;
        while (ncap < sb->len + n + 1) ncap *= 2;
        char *p = realloc(sb->data, ncap);
        if (!p) abort();
        sb->data = p;
        sb->cap = ncap;
    }
    memcpy(sb->data + sb->len, s, n);
    sb->len += n;
    sb->data[sb->len] = '\0';
}

static char *replace_all_str(const char *src, const char *find, const char *repl) {
    size_t flen = strlen(find);
    size_t rlen = strlen(repl);
    sbuf_t sb = {0};
    const char *p = src;
    while (*p) {
        const char *hit = strstr(p, find);
        if (!hit) {
            sbuf_append(&sb, p, strlen(p));
            break;
        }
        sbuf_append(&sb, p, (size_t)(hit - p));
        sbuf_append(&sb, repl, rlen);
        p = hit + flen;
    }
    if (!sb.data) sb.data = strdup("");
    return sb.data;
}

static char *unescape_backslashes(const char *src) {
    sbuf_t sb = {0};
    for (const char *p = src; *p; p++) {
        if (p[0] == '\\' && p[1] != '\0') {
            if (p[1] == '\\') { sbuf_append(&sb, "\\", 1); p++; continue; }
            if (p[1] == 'r')  { sbuf_append(&sb, "\r", 1); p++; continue; }
            if (p[1] == 'n')  { sbuf_append(&sb, "\n", 1); p++; continue; }
        }
        sbuf_append(&sb, p, 1);
    }
    if (!sb.data) sb.data = strdup("");
    return sb.data;
}

static int gen_ws_key(char out[32]) {
    uint8_t rnd[16];
    if (RAND_bytes(rnd, sizeof(rnd)) != 1) return -1;
    if (EVP_EncodeBlock((unsigned char *)out, rnd, 16) != 24) return -1;
    return 0;
}
static int rand_idx(int max) {
    if (max <= 1) return 0;
    uint32_t v = 0;
    if (RAND_bytes((unsigned char *)&v, sizeof(v)) != 1) return -1;
    return (int)(v % (uint32_t)max);
}

static char *translate_payload(const char *raw, const app_cfg_t *cfg, int is_tls, int *embedded_banner_out) {
    *embedded_banner_out = 0;
    if (!raw || !*raw) return strdup("");

    char *cur = NULL;
    if (cfg->fix_crlf) {
        char *tmp = replace_all_str(raw, "\r\n", "\n");
        cur = replace_all_str(tmp, "\n", "\r\n");
        free(tmp);
    } else {
        cur = strdup(raw);
    }

    sbuf_t exp_sb = {0};
    const char *p = cur;
    while (*p) {
        if (*p == '[') {
            const char *star = strchr(p + 1, '*');
            const char *endb = strchr(p + 1, ']');
            if (star && endb && star < endb) {
                int valid_tok = 1;
                for (const char *c = p + 1; c < star; c++) {
                    if (!isalnum((unsigned char)*c) && *c != '_' && *c != '-') { valid_tok = 0; break; }
                }
                int valid_num = (star + 1 < endb);
                for (const char *c = star + 1; c < endb; c++) {
                    if (!isdigit((unsigned char)*c)) { valid_num = 0; break; }
                }
                if (valid_tok && valid_num) {
                    size_t num_len=(size_t)(endb-(star+1)); char num_buf[32]; int cnt=0;
                    if(num_len==0||num_len>=sizeof(num_buf)) valid_num=0;
                    else { memcpy(num_buf,star+1,num_len); num_buf[num_len]='\0';
                           if(parse_int_range(num_buf,0,INT_MAX,&cnt)<0)valid_num=0; }
                    if(valid_num) {
                        if (cnt < 1) cnt = 1;
                        if (cnt > 100) cnt = 100;
                        size_t tlen=(size_t)(star-(p+1));
                        for(int i=0;i<cnt;i++){sbuf_append(&exp_sb,"[",1);sbuf_append(&exp_sb,p+1,tlen);sbuf_append(&exp_sb,"]",1);}
                        p=endb+1; continue;
                    }
                }
            }
        }
        sbuf_append(&exp_sb, p, 1);
        p++;
    }
    free(cur);
    cur = exp_sb.data ? exp_sb.data : strdup("");

    char *unesc = unescape_backslashes(cur);
    free(cur);
    cur = unesc;

    const char *port = cfg->host_port[0] ? cfg->host_port : (is_tls ? "443" : "80");
    const char *pport = cfg->proxy_port[0] ? cfg->proxy_port : (is_tls ? "443" : "80");
    char host_port[300];
    snprintf(host_port, sizeof(host_port), "%s:%s", cfg->host, port);

    const char *pairs[][2] = {
        {"[crlf]", "\r\n"},
        {"[lf]", "\n"},
        {"[cr]", "\r"},
        {"[protocol]", "HTTP/1.1"},
        {"[ua]", DEFAULT_UA},
        {"[proxy]", cfg->proxy},
        {"[proxy_host]", cfg->proxy},
        {"[proxy_port]", pport},
        {"[sni]", cfg->sni},
        {"[sni_host]", cfg->sni},
        {"[sni_port]", "443"},
        {"[host]", cfg->host},
        {"[server]", cfg->host},
        {"[ssh]", cfg->host},
        {"[ssh_host]", cfg->host},
        {"[ip]", cfg->host},
        {"[host_no_port]", cfg->host},
        {"[port]", port},
        {"[ssh_port]", port},
        {"[host_port]", host_port},
        {"[ip_port]", host_port},
        {"[method]", "GET"},
        {NULL, NULL}
    };
    for (int i = 0; pairs[i][0]; i++) {
        char *next = replace_all_str(cur, pairs[i][0], pairs[i][1]);
        free(cur);
        cur = next;
    }

    const char *raw_tags[4] = {"[raw]", "[real_raw]", "[realData]", "[netData]"};
    for (int t = 0; t < 4; t++) {
        char *hit;
        while ((hit = strstr(cur, raw_tags[t])) != NULL) {
            const char *repl = (*embedded_banner_out == 0) ? (SSH_CLIENT_BANNER "\r\n") : "";
            *embedded_banner_out = 1;
            sbuf_t sb = {0};
            sbuf_append(&sb, cur, (size_t)(hit - cur));
            sbuf_append(&sb, repl, strlen(repl));
            sbuf_append(&sb, hit + strlen(raw_tags[t]), strlen(hit + strlen(raw_tags[t])));
            free(cur);
            cur = sb.data;
        }
    }

    const char *ws_tags[2] = {"[ws_key]", "[ws-key]"};
    for (int t = 0; t < 2; t++) {
        char *hit;
        while ((hit = strstr(cur, ws_tags[t])) != NULL) {
            char key[32];
            if(gen_ws_key(key)<0){log_red("RAND_bytes gagal saat membuat WebSocket key");free(cur);return NULL;}
            sbuf_t sb = {0};
            sbuf_append(&sb, cur, (size_t)(hit - cur));
            sbuf_append(&sb, key, strlen(key));
            sbuf_append(&sb, hit + strlen(ws_tags[t]), strlen(hit + strlen(ws_tags[t])));
            free(cur);
            cur = sb.data;
        }
    }

    int base_rotate_idx = 0;
    int rotate_loaded = 0;
    int rotate_tag_no = 0;

    for (int mode = 0; mode < 2; mode++) {
        const char *tag = (mode == 0) ? "[rotate=" : "[random=";
        char *hit;
        while ((hit = strstr(cur, tag)) != NULL) {
            char *endb = strchr(hit + strlen(tag), ']');
            if (!endb) break;
            size_t list_len = (size_t)(endb - (hit + strlen(tag)));
            char *list = malloc(list_len + 1);
            if (!list) abort();
            memcpy(list, hit + strlen(tag), list_len);
            list[list_len] = '\0';

            char *items[64];
            int nitems = 0;
            char *sp = list;
            while (nitems < 64) {
                char *semi = strchr(sp, ';');
                if (!semi) { items[nitems++] = sp; break; }
                *semi = '\0';
                items[nitems++] = sp;
                sp = semi + 1;
            }
            const char *chosen = "";
            if (nitems > 0) {
                if (mode == 0) {
                    if (!rotate_loaded) {
                        FILE *rf = fopen(ROTATE_STATE_FILE, "r");
                        if (rf) {
                            if (fscanf(rf, "%d", &base_rotate_idx) != 1 || base_rotate_idx < 0)
                                base_rotate_idx = 0;
                            fclose(rf);
                        }
                        rotate_loaded = 1;
                        int next_idx = (base_rotate_idx >= 1000000) ? 0 : (base_rotate_idx + 1);
                        FILE *wf = fopen(ROTATE_STATE_FILE, "w");
                        if (wf) { fprintf(wf, "%d", next_idx); fclose(wf); }
                    }
                    int sel = (base_rotate_idx + rotate_tag_no) % nitems;
                    if (sel < 0) sel = 0;
                    chosen = items[sel];
                    rotate_tag_no++;
                } else {
                    int idx=rand_idx(nitems);
                    if(idx<0){log_red("RAND_bytes gagal saat memilih payload random");free(list);free(cur);return NULL;}
                    chosen=items[idx];
                }
            }
            sbuf_t sb = {0};
            sbuf_append(&sb, cur, (size_t)(hit - cur));
            sbuf_append(&sb, chosen, strlen(chosen));
            sbuf_append(&sb, endb + 1, strlen(endb + 1));
            free(list);
            free(cur);
            cur = sb.data;
        }
    }
    return cur;
}

static int starts_with_http_request(const char *s) {
    while (*s == '\r' || *s == '\n' || *s == ' ') s++;
    static const char *methods[] = {
        "GET ", "POST ", "CONNECT ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", NULL
    };
    for (int i = 0; methods[i]; i++) {
        if (strncasecmp(s, methods[i], strlen(methods[i])) == 0) return 1;
    }
    return 0;
}

static int starts_with_connect_request(const char *s) {
    while (*s == '\r' || *s == '\n' || *s == ' ') s++;
    return strncasecmp(s, "CONNECT ", 8) == 0;
}

/* ============================================================
 * SSH HOST KEY DIAGNOSTICS & OPTIONAL SHA-256 PINNING
 * ============================================================ */
static int b64_val(unsigned char ch) {
    if (ch >= 'A' && ch <= 'Z') return ch - 'A';
    if (ch >= 'a' && ch <= 'z') return ch - 'a' + 26;
    if (ch >= '0' && ch <= '9') return ch - '0' + 52;
    if (ch == '+') return 62;
    if (ch == '/') return 63;
    return -1;
}

static int hex_nibble(unsigned char ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

static int parse_sha256_fp(const char *in, uint8_t out[32]) {
    if (!in || !*in) return -1;
    const char *p = in;
    if (strncasecmp(p, "SHA256:", 7) == 0) p += 7;
    size_t len = strlen(p);

    if (len == 64 || len == 95) {
        uint8_t tmp[32];
        size_t i = 0, j = 0;
        int ok = 1;
        while (i < len && j < 32) {
            int hi = hex_nibble((unsigned char)p[i]);
            int lo = (i + 1 < len) ? hex_nibble((unsigned char)p[i + 1]) : -1;
            if (hi < 0 || lo < 0) { ok = 0; break; }
            tmp[j++] = (uint8_t)((hi << 4) | lo);
            i += 2;
            if (len == 95 && j < 32) {
                if (p[i] != ':') { ok = 0; break; }
                i++;
            }
        }
        if (ok && i == len && j == 32) {
            memcpy(out, tmp, 32);
            return 0;
        }
    }

    if (len == 44 && p[43] == '=') len = 43;
    if (len != 43) return -1;

    int v[43];
    for (size_t i = 0; i < 43; i++) {
        v[i] = b64_val((unsigned char)p[i]);
        if (v[i] < 0) return -1;
    }
    size_t j = 0;
    for (size_t i = 0; i < 40; i += 4) {
        out[j++] = (uint8_t)((v[i] << 2) | (v[i + 1] >> 4));
        out[j++] = (uint8_t)(((v[i + 1] & 0x0F) << 4) | (v[i + 2] >> 2));
        out[j++] = (uint8_t)(((v[i + 2] & 0x03) << 6) | v[i + 3]);
    }
    if ((v[42] & 0x03) != 0) return -1;
    out[30] = (uint8_t)((v[40] << 2) | (v[41] >> 4));
    out[31] = (uint8_t)(((v[41] & 0x0F) << 4) | (v[42] >> 2));
    return 0;
}

static void format_sha256_fp(const uint8_t digest[32], char *out, size_t out_sz) {
    char b64[48];
    int elen = EVP_EncodeBlock((unsigned char *)b64, digest, 32);
    if (elen > 0 && b64[elen - 1] == '=') b64[elen - 1] = '\0';
    snprintf(out, out_sz, "SHA256:%s", b64);
}

static int verify_ssh_hostkey(LIBSSH2_SESSION *session, const app_cfg_t *cfg) {
    size_t hk_len = 0;
    int hk_type = LIBSSH2_HOSTKEY_TYPE_UNKNOWN;
    const char *hk = libssh2_session_hostkey(session, &hk_len, &hk_type);
    if (!hk || hk_len == 0) {
        log_red("SSH Host Key tidak tersedia dari server");
        write_marker(KEX_FAILED_FILE, "missing hostkey");
        return -1;
    }

    uint8_t digest[32];
    unsigned int dlen = 0;
    if (EVP_Digest(hk, hk_len, digest, &dlen, EVP_sha256(), NULL) != 1 || dlen != 32) {
        log_red("Gagal menghitung SHA-256 host key SSH");
        write_marker(KEX_FAILED_FILE, "hostkey hash error");
        return -1;
    }

    char fp_str[64];
    format_sha256_fp(digest, fp_str, sizeof(fp_str));

    const char *tname = "unknown";
    switch (hk_type) {
        case LIBSSH2_HOSTKEY_TYPE_RSA:       tname = "ssh-rsa";             break;
#ifdef LIBSSH2_HOSTKEY_TYPE_DSS
        case LIBSSH2_HOSTKEY_TYPE_DSS:       tname = "ssh-dss";             break;
#endif
        case LIBSSH2_HOSTKEY_TYPE_ECDSA_256: tname = "ecdsa-sha2-nistp256"; break;
        case LIBSSH2_HOSTKEY_TYPE_ECDSA_384: tname = "ecdsa-sha2-nistp384"; break;
        case LIBSSH2_HOSTKEY_TYPE_ECDSA_521: tname = "ecdsa-sha2-nistp521"; break;
#ifdef LIBSSH2_HOSTKEY_TYPE_ED25519
        case LIBSSH2_HOSTKEY_TYPE_ED25519:   tname = "ssh-ed25519";         break;
#endif
        default: break;
    }
    log_blue("SSH Host Key (%s): %s", tname, fp_str);

    if (cfg->hostkey_fp[0]) {
        uint8_t expected[32];
        if (parse_sha256_fp(cfg->hostkey_fp, expected) < 0) {
            log_red("Format HOSTKEY tidak valid: %s (gunakan SHA256:<base64> atau 64-hex)", cfg->hostkey_fp);
            write_marker(KEX_FAILED_FILE, "invalid hostkey config");
            return -1;
        }
        if (CRYPTO_memcmp(digest, expected, 32) != 0) {
            log_red("SSH Host Key MISMATCH! Server=%s, Diharapkan=%s", fp_str, cfg->hostkey_fp);
            write_marker(KEX_FAILED_FILE, "hostkey mismatch");
            return -1;
        }
        log_blue("SSH Host Key terverifikasi (SHA-256 pin)");
    } else {
        log_yellow("SSH Host Key tidak dipin (opsional: set HOSTKEY=%s untuk anti-MITM)", fp_str);
    }
    return 0;
}

/* ============================================================
 * SOCKET, POLL & RESUMABLE HTTP RESPONSE STRIPPER (NON-BLOCKING)
 * ============================================================ */
static int set_nonblock(int fd, int nb) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    if (nb) flags |= O_NONBLOCK;
    else flags &= ~O_NONBLOCK;
    return fcntl(fd, F_SETFL, flags);
}

static void tune_tcp_socket(int fd) {
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
}

static long long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

static int poll_fd_until(int fd, short events, long long deadline_ms) {
    while (!g_stop) {
        long long rem = deadline_ms - now_ms();
        if (rem <= 0) return 0;
        int to = (rem > 60000) ? 60000 : (int)rem;
        struct pollfd pfd = { .fd = fd, .events = events };
        int rc = poll(&pfd, 1, to);
        if (rc < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (rc == 0) continue;
        if (pfd.revents & (POLLERR | POLLNVAL)) return -1;
        return 1;
    }
    return -1;
}

static int tls_connect_nb(upstream_ctx_t *u, int timeout_ms) {
    long long deadline = now_ms() + timeout_ms;
    while (!g_stop) {
        int rc = SSL_connect(u->ssl);
        if (rc == 1) {
            u->ssl_want_events = 0;
            return 0;
        }
        int err = SSL_get_error(u->ssl, rc);
        short ev = 0;
        if (err == SSL_ERROR_WANT_READ) ev = POLLIN;
        else if (err == SSL_ERROR_WANT_WRITE) ev = POLLOUT;
        else {
            unsigned long ecode = ERR_get_error();
            log_red("TLS handshake gagal: %s", ecode ? ERR_reason_error_string(ecode) : strerror(errno));
            return -1;
        }
        int pr = poll_fd_until(u->fd, ev, deadline);
        if (pr <= 0) {
            log_red("TLS handshake %s", pr == 0 ? "timeout" : "error");
            return -1;
        }
    }
    return -1;
}

static int raw_write_all_nb(upstream_ctx_t *u, const void *data, size_t len, int timeout_ms) {
    const uint8_t *p = (const uint8_t *)data;
    size_t left = len;
    long long deadline = now_ms() + timeout_ms;

    while (left > 0 && !g_stop) {
        if (u->ssl) {
            int chunk = (int)(left > 16384U ? 16384U : left);
            int n = SSL_write(u->ssl, p, chunk);
            if (n > 0) {
                u->ssl_want_events = 0;
                u->last_activity = time(NULL);
                p += n;
                left -= (size_t)n;
                continue;
            }
            int err = SSL_get_error(u->ssl, n);
            short ev = 0;
            if (err == SSL_ERROR_WANT_READ) ev = POLLIN;
            else if (err == SSL_ERROR_WANT_WRITE) ev = POLLOUT;
            else return -1;
            if (poll_fd_until(u->fd, ev, deadline) <= 0) return -1;
        } else {
            ssize_t n = send(u->fd, p, left, MSG_NOSIGNAL);
            if (n > 0) {
                u->last_activity = time(NULL);
                p += n;
                left -= (size_t)n;
                continue;
            }
            if (n < 0 && errno == EINTR) continue;
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                if (poll_fd_until(u->fd, POLLOUT, deadline) <= 0) return -1;
                continue;
            }
            return -1;
        }
    }
    return left == 0 ? 0 : -1;
}

static const uint8_t *find_bytes(const uint8_t *hay, size_t hlen, const char *needle, size_t nlen) {
    if (hlen < nlen) return NULL;
    for (size_t i = 0; i <= hlen - nlen; i++) {
        if (memcmp(hay + i, needle, nlen) == 0) return hay + i;
    }
    return NULL;
}

/* Return: >0 bytes read, 0 EOF, -2 EAGAIN, -1 error */
static ssize_t pre_read_more(upstream_ctx_t *u) {
    if (u->pre_off > 0 && u->pre_off < u->pre_len) {
        memmove(u->pre_buf, u->pre_buf + u->pre_off, u->pre_len - u->pre_off);
        u->pre_len -= u->pre_off;
        u->pre_off = 0;
    } else if (u->pre_off >= u->pre_len) {
        u->pre_off = 0;
        u->pre_len = 0;
    }
    if (u->pre_len >= sizeof(u->pre_buf)) return -1;
    size_t space = sizeof(u->pre_buf) - u->pre_len;

    if (u->ssl) {
        int n = SSL_read(u->ssl, u->pre_buf + u->pre_len, (int)space);
        if (n > 0) {
            u->ssl_want_events = 0;
            u->pre_len += (size_t)n;
            u->last_activity = time(NULL);
            return n;
        }
        int err = SSL_get_error(u->ssl, n);
        if (err == SSL_ERROR_WANT_READ) { u->ssl_want_events = EPOLLIN; return -2; }
        if (err == SSL_ERROR_WANT_WRITE) { u->ssl_want_events = EPOLLOUT; return -2; }
        if (err == SSL_ERROR_ZERO_RETURN) return 0;
        unsigned long ecode = ERR_get_error();
        if (ecode) log_red("SSL_read error: %s", ERR_reason_error_string(ecode));
        else if (err == SSL_ERROR_SYSCALL && errno != 0) log_red("SSL_read syscall: %s", strerror(errno));
        return -1;
    }

    ssize_t n;
    do {
        n = recv(u->fd, u->pre_buf + u->pre_len, space, 0);
    } while (n < 0 && errno == EINTR);
    if (n > 0) {
        u->pre_len += (size_t)n;
        u->last_activity = time(NULL);
        return n;
    }
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return -2;
    if (n < 0) log_red("recv error: %s", strerror(errno));
    return n == 0 ? 0 : -1;
}

static void delay_wait_and_drain(upstream_ctx_t *u, int delay_ms) {
    if (delay_ms <= 0) return;
    long long deadline = now_ms() + delay_ms;
    while (!g_stop) {
        long long rem = deadline - now_ms();
        if (rem <= 0) break;
        int to = (rem > 60000) ? 60000 : (int)rem;
        short want = POLLIN;
        if (u->ssl && u->ssl_want_events == EPOLLOUT) want = POLLOUT;
        if (u->pre_len >= sizeof(u->pre_buf)) want = 0;
        struct pollfd pfd = { .fd = u->fd, .events = want };
        int rc = poll(&pfd, (nfds_t)(want ? 1 : 0), to);
        if (rc < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (rc == 0) break;
        if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) break;
        if (want && (pfd.revents & want)) {
            ssize_t r = pre_read_more(u);
            if (r == 0 || r == -1) break;
        }
    }
}

/* Return: 0 selesai 1 respons (atau masuk tunnel), -2 EAGAIN, -1 error */
static int http_header_has_token(const char *value,const char *token) {
    size_t token_len=strlen(token); const char *p=value;
    while(p&&*p){while(*p==' '||*p=='\t'||*p==',')p++;const char *end=p;while(*end&&*end!=',')end++;
        const char *trim=end;while(trim>p&&(trim[-1]==' '||trim[-1]=='\t'))trim--;
        if((size_t)(trim-p)==token_len&&strncasecmp(p,token,token_len)==0)return 1;
        p=*end?end+1:end;
    } return 0;
}
/* 0 parsed/non-tunnel, -2 EAGAIN, -1 malformed or closed. */
static int consume_one_http_response(upstream_ctx_t *u,int allow_non_tunnel) {
    if(u->tunnel_established)return 0;
    while(1){
        if(u->http_close_delimited){u->pre_off=u->pre_len;ssize_t r=pre_read_more(u);if(r==-2)return -2;if(r<=0)return -1;continue;}
        if(u->http_skip_remaining){
            while(u->http_skip_remaining){size_t a=u->pre_len-u->pre_off;if(a){size_t n=a<u->http_skip_remaining?a:u->http_skip_remaining;u->pre_off+=n;u->http_skip_remaining-=n;}
                else{ssize_t r=pre_read_more(u);if(r==-2)return -2;if(r<=0)return -1;}}
            if(u->http_pending_tunnel){u->http_pending_tunnel=0;u->tunnel_established=1;}return 0;
        }
        if(u->http_in_chunked){
            if(u->http_chunk_state==0){
                const uint8_t *nl=find_bytes(u->pre_buf+u->pre_off,u->pre_len-u->pre_off,"\n",1);
                if(!nl){if(u->pre_len-u->pre_off>1024)return -1;ssize_t r=pre_read_more(u);if(r==-2)return -2;if(r<=0)return -1;continue;}
                size_t len=(size_t)(nl-(u->pre_buf+u->pre_off));if(len>=256)return -1;
                char line[256];memcpy(line,u->pre_buf+u->pre_off,len);line[len]='\0';if(len&&line[len-1]=='\r')line[len-1]='\0';
                char *semi=strchr(line,';');if(semi)*semi='\0';trim_ws(line);
                size_t chunk=0;if(parse_strict_hex_size(line,&chunk,MAX_HTTP_SKIP_BODY)<0)return -1;
                u->pre_off+=len+1;if(chunk==0)u->http_chunk_state=3;else{u->http_chunk_rem=chunk;u->http_chunk_state=1;}
            } else if(u->http_chunk_state==1){
                size_t a=u->pre_len-u->pre_off;if(a){size_t n=a<u->http_chunk_rem?a:u->http_chunk_rem;u->pre_off+=n;u->http_chunk_rem-=n;if(!u->http_chunk_rem)u->http_chunk_state=2;}
                else{ssize_t r=pre_read_more(u);if(r==-2)return -2;if(r<=0)return -1;}
            } else if(u->http_chunk_state==2){
                size_t a=u->pre_len-u->pre_off;if(!a){ssize_t r=pre_read_more(u);if(r==-2)return -2;if(r<=0)return -1;continue;}
                if(u->pre_buf[u->pre_off]=='\r'){if(a<2){ssize_t r=pre_read_more(u);if(r==-2)return -2;if(r<=0)return -1;continue;}if(u->pre_buf[u->pre_off+1]!='\n')return -1;u->pre_off+=2;}
                else if (u->pre_buf[u->pre_off] == '\n') {
                    u->pre_off++;
                } else {
                    return -1;
                }
                u->http_chunk_state = 0;
            } else {
                const uint8_t *nl=find_bytes(u->pre_buf+u->pre_off,u->pre_len-u->pre_off,"\n",1);
                if(!nl){if(u->pre_len-u->pre_off>4096)return -1;ssize_t r=pre_read_more(u);if(r==-2)return -2;if(r<=0)return -1;continue;}
                size_t len=(size_t)(nl-(u->pre_buf+u->pre_off));int empty=!len||(len==1&&u->pre_buf[u->pre_off]=='\r');u->pre_off+=len+1;
                if(empty){u->http_in_chunked=0;u->http_chunk_state=0;if(u->http_pending_tunnel){u->http_pending_tunnel=0;u->tunnel_established=1;}return 0;}
            } continue;
        }
        while(1){
            size_t a=u->pre_len-u->pre_off;const uint8_t *cur=u->pre_buf+u->pre_off;
            if(a){size_t n=a<5?a:5;if(memcmp(cur,"HTTP/",n)!=0){
                if(!allow_non_tunnel&&u->last_http_code>=300){size_t sn=a<4?a:4;if(memcmp(cur,"SSH-",sn)!=0)return -1;if(a>=4){u->tunnel_established=1;return 0;}}
                else{u->tunnel_established=1;return 0;}
            }else if(a>=5)break;}
            ssize_t r=pre_read_more(u);if(r==-2)return -2;if(r==0){if(u->pre_len>u->pre_off&&(allow_non_tunnel||u->last_http_code<300)){u->tunnel_established=1;return 0;}return -1;}if(r<0)return -1;
        }
        const uint8_t *start=u->pre_buf+u->pre_off;size_t avail=u->pre_len-u->pre_off,delim=0;
        const uint8_t *endp=find_bytes(start,avail,"\r\n\r\n",4);if(endp)delim=4;else{endp=find_bytes(start,avail,"\n\n",2);if(endp)delim=2;}
        if(!endp){if(avail>MAX_HTTP_HEADER)return -1;ssize_t r=pre_read_more(u);if(r==-2)return -2;if(r<=0)return -1;continue;}
        size_t hlen=(size_t)(endp-start);if(hlen>MAX_HTTP_HEADER)return -1;char hdr[MAX_HTTP_HEADER+1];memcpy(hdr,start,hlen);hdr[hlen]='\0';u->pre_off+=hlen+delim;
        char status[256]={0};char *eol=strpbrk(hdr,"\r\n");size_t slen=eol?(size_t)(eol-hdr):strlen(hdr);
        if (!slen || slen >= sizeof(status)) return -1;
        memcpy(status, hdr, slen);
        /* Only accept syntactically valid HTTP/1.0 and HTTP/1.1 status lines. */
        if (strncmp(status, "HTTP/1.", 7) != 0 ||
            (status[7] != '0' && status[7] != '1') || status[8] != ' ') return -1;
        if(strcmp(u->last_status,status)){snprintf(u->last_status, sizeof(u->last_status), "%.127s", status);log_yellow("%s",status);}
        char *sp = status + 8;
        if (!isdigit((unsigned char)sp[1]) || !isdigit((unsigned char)sp[2]) ||
            !isdigit((unsigned char)sp[3]) || (sp[4] != '\0' && sp[4] != ' ')) return -1;
        int code=(sp[1]-'0')*100+(sp[2]-'0')*10+(sp[3]-'0');if(code<100||code>599)return -1;u->last_http_code=code;
        if(u->expect_connect_resp&&code>=200&&code<=299){u->tunnel_established=1;return 0;}
        int has_cl=0,has_te=0,chunked=0,upgrade=0,connection_upgrade=0;size_t body=0;
        char *p=eol?eol+1:hdr+hlen;
        while(*p){while(*p=='\r'||*p=='\n')p++;if(!*p)break;char *next=strpbrk(p,"\r\n");if(next)*next='\0';char *colon=strchr(p,':');if(!colon)return -1;*colon='\0';char *name=p,*val=colon+1;trim_ws(name);trim_ws(val);
            if(!strcasecmp(name,"content-length")){size_t n=0;if(parse_strict_dec_size(val,&n,MAX_HTTP_SKIP_BODY)<0)return -1;if(has_cl&&n!=body)return -1;has_cl=1;body=n;}
            else if(!strcasecmp(name,"transfer-encoding")){has_te=1;const char *last=strrchr(val,',');last=last?last+1:val;while(*last==' '||*last=='\t')last++;size_t n=strlen(last);while(n&&(last[n-1]==' '||last[n-1]=='\t'))n--;if(n!=7||strncasecmp(last,"chunked",7))return -1;chunked=1;}
            else if(!strcasecmp(name,"upgrade"))upgrade=(*val!='\0');
            else if(!strcasecmp(name,"connection"))connection_upgrade=http_header_has_token(val,"upgrade");
            if (!next) break;
            p = next + 1;
        }
        if(has_te&&has_cl)return -1;
        if(code==101){if(!upgrade||!connection_upgrade)return -1;u->tunnel_established=1;return 0;}
        if((code>=100&&code<200)||code==204||code==304)return 0;

        /* Legacy payloads may use a non-CONNECT 200 as the tunnel marker.
         * When explicitly enabled, consume framed HTTP bodies first so they
         * never leak into the SSH stream. */
        int legacy_200_tunnel=(code==200&&u->allow_http_200_tunnel);
        if(chunked){
            u->http_in_chunked=1;
            u->http_chunk_state=0;
            u->http_pending_tunnel=legacy_200_tunnel;
            continue;
        }
        if(has_cl){
            if(body==0){
                if(legacy_200_tunnel)u->tunnel_established=1;
                return 0;
            }
            u->http_skip_remaining=body;
            u->http_pending_tunnel=legacy_200_tunnel;
            continue;
        }
        if(legacy_200_tunnel){
            u->tunnel_established=1;
            return 0;
        }
        /* Without explicit framing, an ordinary HTTP response ends at EOF. */
        u->http_close_delimited=1;
    }
}

/* ============================================================
 * LIBSSH2 CUSTOM I/O CALLBACKS (TLS + TCP + PREBUF + BANNER SPLICE)
 * ============================================================ */
static ssize_t ssh_recv_cb(libssh2_socket_t sock, void *buffer, size_t length, int flags, void **abstract) {
    (void)flags;
    upstream_ctx_t *u = (upstream_ctx_t *)(*abstract);

    while (!u->tunnel_established) {
        int rc = consume_one_http_response(u, 0);
        if (rc == -2) return -EAGAIN;
        if (rc < 0) return -EIO;
    }

    if (u->pre_off < u->pre_len) {
        size_t avail = u->pre_len - u->pre_off;
        size_t take = avail < length ? avail : length;
        memcpy(buffer, u->pre_buf + u->pre_off, take);
        u->pre_off += take;
        if (u->pre_off == u->pre_len) { u->pre_off = 0; u->pre_len = 0; }
        u->last_activity = time(NULL);
        u->ssl_want_events = 0;
        u->rx_seq++;
        return (ssize_t)take;
    }

    if (u->ssl) {
        int rlen = (int)(length > 32768U ? 32768U : length);
        int r = SSL_read(u->ssl, buffer, rlen);
        if (r > 0) {
            u->ssl_want_events = 0;
            u->last_activity = time(NULL);
            u->rx_seq++;
            return (ssize_t)r;
        }
        int err = SSL_get_error(u->ssl, r);
        if (err == SSL_ERROR_WANT_READ) { u->ssl_want_events = EPOLLIN; return -EAGAIN; }
        if (err == SSL_ERROR_WANT_WRITE) { u->ssl_want_events = EPOLLOUT; return -EAGAIN; }
        if (err == SSL_ERROR_ZERO_RETURN) return 0;
        return -EIO;
    }

    ssize_t r;
    do {
        r = recv(sock, buffer, length, 0);
    } while (r < 0 && errno == EINTR);
    if (r > 0) {
        u->last_activity = time(NULL);
        u->rx_seq++;
        return r;
    }
    if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return -EAGAIN;
    return r < 0 ? -errno : 0;
}

static ssize_t ssh_send_cb(libssh2_socket_t sock, const void *buffer, size_t length, int flags, void **abstract) {
    (void)flags;
    upstream_ctx_t *u = (upstream_ctx_t *)(*abstract);

    if (u->skip_ssh_banner_bytes > 0) {
        size_t take = length < u->skip_ssh_banner_bytes ? length : u->skip_ssh_banner_bytes;
        u->skip_ssh_banner_bytes -= take;
        u->last_activity = time(NULL);
        return (ssize_t)take;
    }

    if (u->ssl) {
        int wlen = (int)(length > 32768U ? 32768U : length);
        int r = SSL_write(u->ssl, buffer, wlen);
        if (r > 0) {
            u->ssl_want_events = 0;
            u->last_activity = time(NULL);
            return (ssize_t)r;
        }
        int err = SSL_get_error(u->ssl, r);
        if (err == SSL_ERROR_WANT_READ) { u->ssl_want_events = EPOLLIN; return -EAGAIN; }
        if (err == SSL_ERROR_WANT_WRITE) { u->ssl_want_events = EPOLLOUT; return -EAGAIN; }
        return -EIO;
    }

    ssize_t r;
    do {
        r = send(sock, buffer, length, MSG_NOSIGNAL);
    } while (r < 0 && errno == EINTR);
    if (r > 0) {
        u->last_activity = time(NULL);
        return r;
    }
    if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return -EAGAIN;
    return r < 0 ? -errno : 0;
}

static void kbd_auth_cb(const char *name, int name_len, const char *instruction, int instruction_len,
                        int num_prompts, const LIBSSH2_USERAUTH_KBDINT_PROMPT *prompts,
                        LIBSSH2_USERAUTH_KBDINT_RESPONSE *responses, void **abstract) {
    (void)name; (void)name_len; (void)instruction; (void)instruction_len;
    (void)prompts; (void)abstract;
    for (int i = 0; i < num_prompts; i++) {
        responses[i].text = strdup(g_kbd_password);
        responses[i].length = (unsigned int)strlen(g_kbd_password);
    }
}

static int wait_ssh_nb(LIBSSH2_SESSION *session, upstream_ctx_t *u, long long deadline_ms) {
    if (now_ms() >= deadline_ms) return 0;
    if (u->ssl && SSL_pending(u->ssl) > 0) return 1;
    short ev = 0;
    if (u->ssl && u->ssl_want_events) {
        if (u->ssl_want_events & EPOLLIN) ev |= POLLIN;
        if (u->ssl_want_events & EPOLLOUT) ev |= POLLOUT;
    } else {
        int dirs = libssh2_session_block_directions(session);
        if (dirs & LIBSSH2_SESSION_BLOCK_INBOUND) ev |= POLLIN;
        if (dirs & LIBSSH2_SESSION_BLOCK_OUTBOUND) ev |= POLLOUT;
        if (ev == 0) ev = POLLIN;
    }
    return poll_fd_until(u->fd, ev, deadline_ms);
}

/* ============================================================
 * DIAL UPSTREAM (NON-BLOCKING CONNECT DENGAN TIMEOUT 10 DETIK)
 * ============================================================ */
static int tcp_connect_host(const char *host, const char *port) {
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    int rc = getaddrinfo(host, port, &hints, &res);
    if (rc != 0 || !res) return -1;

    int fd = -1;
    for (struct addrinfo *rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;

        tune_tcp_socket(fd);
        if (set_nonblock(fd, 1) < 0) {
            close(fd);
            fd = -1;
            continue;
        }

        int cr = connect(fd, rp->ai_addr, rp->ai_addrlen);
        if (cr == 0) break;
        if (errno == EINPROGRESS) {
            long long deadline = now_ms() + 10000;
            int pr = poll_fd_until(fd, POLLOUT, deadline);
            if (pr > 0) {
                int so_err = 0;
                socklen_t slen = sizeof(so_err);
                if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_err, &slen) == 0 && so_err == 0) {
                    break;
                }
            }
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

/* ============================================================
 * SOCKS5 & EPOLL MULTIPLEXER
 * ============================================================ */
static void update_epoll(int epfd, int fd, void *ptr, uint32_t *cur_ev, uint32_t want_ev) {
    if (fd < 0 || *cur_ev == want_ev) return;
    struct epoll_event ev = { .events = want_ev, .data.ptr = ptr };
    if (epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &ev) == 0) {
        *cur_ev = want_ev;
    }
}

static void update_client_epoll(int epfd, client_conn_t *c, uint32_t want_ev) {
    if (c->fd < 0) return;
    struct epoll_event ev = { .events = want_ev, .data.ptr = c };
    if (!c->in_epoll) {
        if (epoll_ctl(epfd, EPOLL_CTL_ADD, c->fd, &ev) == 0) {
            c->in_epoll = 1;
            c->epoll_events = want_ev;
        }
    } else if (c->epoll_events != want_ev) {
        if (epoll_ctl(epfd, EPOLL_CTL_MOD, c->fd, &ev) == 0) {
            c->epoll_events = want_ev;
        }
    }
}

static void suspend_client_epoll(int epfd, client_conn_t *c) {
    if (c->fd >= 0 && c->in_epoll) {
        epoll_ctl(epfd, EPOLL_CTL_DEL, c->fd, NULL);
        c->in_epoll = 0;
        c->epoll_events = 0;
    }
}

static void detach_client_fd(int epfd, client_conn_t *c) {
    if (c->fd >= 0) {
        if (c->in_epoll) {
            epoll_ctl(epfd, EPOLL_CTL_DEL, c->fd, NULL);
            c->in_epoll = 0;
        }
        close(c->fd);
        c->fd = -1;
        c->epoll_events = 0;
    }
    c->close_after_ctrl = 0;
    c->ctrl_len = 0;
    c->ctrl_off = 0;
    c->ctrl_close_deadline_ms = 0;
}

static void remove_client(int epfd, client_conn_t *c) {
    if (g_opening_client == c) g_opening_client = NULL;
    if (g_pending_client == c) {
        g_pending_client = NULL;
        g_pending_op = PENDING_NONE;
    }
    detach_client_fd(epfd, c);
    rb_free(&c->c2s);
    rb_free(&c->s2c);
    if (c->prev) c->prev->next = c->next;
    else g_clients = c->next;
    if (c->next) c->next->prev = c->prev;
    if (g_client_count > 0) g_client_count--;
    free(c);
}

static void start_closing_client(int epfd, client_conn_t *c) {
    if (c == g_pending_client && g_pending_op != PENDING_NONE) {
        c->abort_on_pending = 1;
        detach_client_fd(epfd, c);
        return;
    }
    if (c == g_opening_client && !c->channel) {
        c->abort_on_open = 1;
        detach_client_fd(epfd, c);
        return;
    }
    if (!c->channel) {
        remove_client(epfd, c);
        return;
    }
    detach_client_fd(epfd, c);
    c->write_pending = 0;
    c->write_pending_ptr = NULL;
    c->write_pending_len = 0;
    c->write_waiting_window = 0;
    c->write_wait_rx_seq = 0;
    c->read_pending = 0;
    c->read_pending_ptr = NULL;
    c->read_pending_len = 0;
    log_channel_buffer_final(c);
    rb_free(&c->c2s);
    rb_free(&c->s2c);
    c->state = ST_CLOSING;
}

static uint32_t client_rdhup_flag(const client_conn_t *c) {
    return (!c->client_eof && !c->rdhup_pending && !c->hup_pending && !c->client_dead)
               ? EPOLLRDHUP
               : 0U;
}

static int queue_ctrl_send(int epfd, client_conn_t *c, const uint8_t *data, size_t len) {
    ssize_t sent = 0;
    if (c->ctrl_len == 0) {
        do {
            sent = send(c->fd, data, len, MSG_NOSIGNAL);
        } while (sent < 0 && errno == EINTR);
        if (sent == (ssize_t)len) return 0;
        if (sent < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) return -1;
            sent = 0;
        }
    }
    size_t rem = len - (size_t)sent;
    if (c->ctrl_len - c->ctrl_off + rem > sizeof(c->ctrl_buf)) return -1;
    if (c->ctrl_off > 0 && c->ctrl_off < c->ctrl_len) {
        memmove(c->ctrl_buf, c->ctrl_buf + c->ctrl_off, c->ctrl_len - c->ctrl_off);
        c->ctrl_len -= c->ctrl_off;
        c->ctrl_off = 0;
    } else if (c->ctrl_off >= c->ctrl_len) {
        c->ctrl_off = 0;
        c->ctrl_len = 0;
    }
    memcpy(c->ctrl_buf + c->ctrl_len, data + (size_t)sent, rem);
    c->ctrl_len += rem;
    if (!c->hup_pending && !c->client_dead) {
        update_client_epoll(epfd, c, c->epoll_events | EPOLLOUT);
    }
    return 0;
}

static int flush_ctrl_send(int epfd, client_conn_t *c) {
    while (c->ctrl_off < c->ctrl_len) {
        ssize_t n = send(c->fd, c->ctrl_buf + c->ctrl_off, c->ctrl_len - c->ctrl_off, MSG_NOSIGNAL);
        if (n > 0) {
            c->ctrl_off += (size_t)n;
        } else if (n < 0 && errno == EINTR) {
            continue;
        } else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return 0;
        } else {
            return -1;
        }
    }
    c->ctrl_off = 0;
    c->ctrl_len = 0;
    if (c->close_after_ctrl) {
        return 2;
    }
    uint32_t want;
    if (c->state == ST_SOCKS_GREETING || c->state == ST_SOCKS_REQUEST) {
        want = EPOLLIN | client_rdhup_flag(c);
    } else {
        want = (c->epoll_events & ~(uint32_t)EPOLLOUT);
        if (c->state == ST_RELAY && c->s2c.used > 0) want |= EPOLLOUT;
    }
    if (!c->hup_pending && !c->client_dead) {
        update_client_epoll(epfd, c, want);
    }
    return 1;
}

static void send_ctrl_err_and_close(int epfd, client_conn_t *c, const uint8_t *msg, size_t len) {
    if (c->fd < 0 || c->hup_pending || c->client_dead) {
        start_closing_client(epfd, c);
        return;
    }
    if (queue_ctrl_send(epfd, c, msg, len) < 0 || c->ctrl_len == 0) {
        start_closing_client(epfd, c);
        return;
    }
    c->close_after_ctrl = 1;
    c->ctrl_close_deadline_ms = now_ms() + 3000;
    update_client_epoll(epfd, c, EPOLLOUT | client_rdhup_flag(c));
}

static void send_socks_err_and_close(int epfd, client_conn_t *c, uint8_t rep_code) {
    uint8_t err_rep[10] = {0x05, rep_code, 0x00, 0x01, 0,0,0,0, 0,0};
    send_ctrl_err_and_close(epfd, c, err_rep, sizeof(err_rep));
}

static int send_from_rb(int fd, rb_t *r, int keep_pos) {
    while (r->used > 0) {
        size_t avail = 0;
        const uint8_t *ptr = rb_read_slice(r, &avail);
        if (!ptr || avail == 0) break;
        ssize_t n = send(fd, ptr, avail, MSG_NOSIGNAL);
        if (n > 0) {
            rb_commit_read(r, (size_t)n, keep_pos);
            if ((size_t)n < avail) break;
        } else if (n < 0 && errno == EINTR) {
            continue;
        } else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return 0;
        } else {
            return -1;
        }
    }
    return 1;
}

/* Kuras socket sampai buffer penuh, EOF (n == 0), atau EAGAIN */
static int recv_to_rb(int fd, rb_t *r, int *eof_out, int *would_block_out) {
    *eof_out = 0;
    *would_block_out = 0;
    while (rb_free_space(r) > 0) {
        size_t avail = 0;
        uint8_t *ptr = rb_write_slice(r, &avail);
        if (!ptr || avail == 0) break;
        ssize_t n = recv(fd, ptr, avail, 0);
        if (n > 0) {
            rb_commit_write(r, (size_t)n);
            continue;
        }
        if (n == 0) {
            *eof_out = 1;
            break;
        }
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            *would_block_out = 1;
            break;
        }
        return -1;
    }
    return 0;
}

/* Kuras sisa socket untuk koneksi yang sebelumnya mengalami HUP/RDHUP saat c2s penuh */
static int drain_pending_eof_to_c2s(int epfd, client_conn_t *c) {
    if (!(c->hup_pending || c->rdhup_pending) || c->client_eof || c->fd < 0) return 0;
    if (rb_free_space(&c->c2s) == 0) return 0;

    size_t before = c->c2s.used;
    int eof_hit = 0;
    int would_block = 0;
    int rc = recv_to_rb(c->fd, &c->c2s, &eof_hit, &would_block);
    note_c2s_buffer_peak(c);
    if (c->c2s.used > before) c->last_activity_ms=now_ms();
    if (rc < 0 || eof_hit || would_block) {
        c->client_eof = 1;
        c->need_send_eof = 1;
        if (c->hup_pending || rc < 0) {
            c->client_dead = 1;
            detach_client_fd(epfd, c);
        }
        c->hup_pending = 0;
        c->rdhup_pending = 0;
    }
    return (c->c2s.used > before || c->client_eof) ? 1 : 0;
}

static int drain_socks_req_buf(client_conn_t *c, int *eof_out) {
    *eof_out = 0;
    while (c->req_len < sizeof(c->req_buf)) {
        ssize_t n = recv(c->fd, c->req_buf + c->req_len, sizeof(c->req_buf) - c->req_len, 0);
        if (n > 0) {
            c->req_len += (size_t)n;
            continue;
        }
        if (n == 0) {
            *eof_out = 1;
            break;
        }
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
        return -1;
    }
    return 0;
}

static void handle_client_io(int epfd, client_conn_t *c, uint32_t events) {
    if (c->state == ST_CLOSING || c->fd < 0) return;

    if ((events & EPOLLOUT) && c->ctrl_len > 0) {
        int frc = flush_ctrl_send(epfd, c);
        if (frc < 0 || frc == 2) {
            start_closing_client(epfd, c);
            return;
        }
    }

    if (c->close_after_ctrl) {
        if (events & (EPOLLERR | EPOLLHUP)) {
            start_closing_client(epfd, c);
        } else if ((events & EPOLLRDHUP) && c->state != ST_SSH_OPENING) {
            start_closing_client(epfd, c);
        } else if (events & EPOLLRDHUP) {
            c->rdhup_pending = 1;
            update_client_epoll(epfd, c, (c->ctrl_len > 0 ? EPOLLOUT : 0U));
        }
        return;
    }

    if (c->state == ST_SOCKS_GREETING) {
        int eof_hit = 0;
        if (events & (EPOLLIN | EPOLLHUP | EPOLLRDHUP)) {
            if (drain_socks_req_buf(c, &eof_hit) < 0) {
                remove_client(epfd, c);
                return;
            }
            if (c->req_len >= 2) {
                if (c->req_buf[0] != 0x05 || c->req_buf[1] == 0) {
                    remove_client(epfd, c);
                    return;
                }
                size_t need = 2 + (size_t)c->req_buf[1];
                if (c->req_len >= need) {
                    int has_noauth = 0;
                    for (size_t i = 2; i < need; i++) {
                        if (c->req_buf[i] == 0x00) { has_noauth = 1; break; }
                    }
                    if (!has_noauth) {
                        uint8_t deny[2] = {0x05, 0xFF};
                        send_ctrl_err_and_close(epfd, c, deny, sizeof(deny));
                        return;
                    }
                    uint8_t reply[2] = {0x05, 0x00};
                    if (queue_ctrl_send(epfd, c, reply, 2) < 0) {
                        remove_client(epfd, c);
                        return;
                    }
                    if (c->req_len > need) {
                        memmove(c->req_buf, c->req_buf + need, c->req_len - need);
                        c->req_len -= need;
                    } else {
                        c->req_len = 0;
                    }
                    c->state = ST_SOCKS_REQUEST;
                }
            }
        }
        if (c->state == ST_SOCKS_GREETING && (eof_hit || (events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)))) {
            remove_client(epfd, c);
            return;
        }
    }

    if (c->state == ST_SOCKS_REQUEST) {
        int eof_hit = 0;
        if ((events & (EPOLLIN | EPOLLHUP | EPOLLRDHUP)) && c->req_len < sizeof(c->req_buf)) {
            if (drain_socks_req_buf(c, &eof_hit) < 0) {
                remove_client(epfd, c);
                return;
            }
        }
        if (c->req_len < 4) {
            if (eof_hit || (events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP))) remove_client(epfd, c);
            return;
        }
        if (c->req_buf[0] != 0x05 || c->req_buf[1] != 0x01) {
            send_socks_err_and_close(epfd, c, 0x07);
            return;
        }
        uint8_t atyp = c->req_buf[3];
        size_t need = 0;
        if (atyp == 0x01) {
            need = 10;
        } else if (atyp == 0x03) {
            if (c->req_len < 5) {
                if (eof_hit || (events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP))) remove_client(epfd, c);
                return;
            }
            if (c->req_buf[4] == 0) {
                send_socks_err_and_close(epfd, c, 0x01);
                return;
            }
            need = 5 + (size_t)c->req_buf[4] + 2;
        } else if (atyp == 0x04) {
            need = 22;
        } else {
            send_socks_err_and_close(epfd, c, 0x08);
            return;
        }

        if (c->req_len < need) {
            if (eof_hit || (events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP))) remove_client(epfd, c);
            return;
        }

        if (events & (EPOLLERR | EPOLLHUP)) {
            remove_client(epfd, c);
            return;
        }

        if (atyp == 0x01) {
            inet_ntop(AF_INET, c->req_buf + 4, c->target_host, sizeof(c->target_host));
            c->target_port = (uint16_t)(((unsigned)c->req_buf[8] << 8) | (unsigned)c->req_buf[9]);
        } else if (atyp == 0x03) {
            size_t dlen = c->req_buf[4];
            memcpy(c->target_host, c->req_buf + 5, dlen);
            c->target_host[dlen] = '\0';
            c->target_port = (uint16_t)(((unsigned)c->req_buf[5 + dlen] << 8) | (unsigned)c->req_buf[6 + dlen]);
        } else {
            inet_ntop(AF_INET6, c->req_buf + 4, c->target_host, sizeof(c->target_host));
            c->target_port = (uint16_t)(((unsigned)c->req_buf[20] << 8) | (unsigned)c->req_buf[21]);
        }

        if (c->target_port == 0) {
            send_socks_err_and_close(epfd, c, 0x01);
            return;
        }

        if (c->req_len > need) {
            size_t rem = c->req_len - need;
            if (rem > sizeof(c->early_buf)) rem = sizeof(c->early_buf);
            memcpy(c->early_buf, c->req_buf + need, rem);
            c->early_len = rem;
        }
        c->req_len = 0;
        c->state = ST_SSH_OPENING;
        c->open_started_ms = 0;
        if (eof_hit) {
            c->client_eof = 1;
            c->need_send_eof = 1;
            c->rdhup_pending = 0;
        } else if (events & EPOLLRDHUP) {
            c->rdhup_pending = 1;
        }
        update_client_epoll(epfd, c, (c->ctrl_len > 0 ? EPOLLOUT : 0U) | client_rdhup_flag(c));
        return;
    }

    if (c->state == ST_SSH_OPENING) {
        if (events & (EPOLLERR | EPOLLHUP)) {
            start_closing_client(epfd, c);
            return;
        }
        if (events & EPOLLRDHUP) {
            if (!c->client_eof) c->rdhup_pending = 1;
            update_client_epoll(epfd, c, (c->ctrl_len > 0 ? EPOLLOUT : 0U));
        }
        return;
    }

    if (c->state == ST_RELAY) {
        int eof_hit = 0;
        int would_block = 0;

        /* Selalu coba kuras data socket saat EPOLLIN maupun EPOLLHUP/EPOLLRDHUP/EPOLLERR */
        if ((events & (EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLRDHUP)) &&
            !c->client_eof && rb_free_space(&c->c2s) > 0) {
            size_t c2s_before=c->c2s.used;
            int recv_rc = recv_to_rb(c->fd, &c->c2s, &eof_hit, &would_block);
            note_c2s_buffer_peak(c);
            if (recv_rc < 0) {
                c->client_eof = 1;
                c->need_send_eof = 1;
                c->client_dead = 1;
                c->hup_pending = 0;
                c->rdhup_pending = 0;
                detach_client_fd(epfd, c);
            } else if (eof_hit) {
                c->client_eof = 1;
                c->need_send_eof = 1;
                c->hup_pending = 0;
                c->rdhup_pending = 0;
            }
            if(c->c2s.used>c2s_before)c->last_activity_ms=now_ms();
        }

        if (c->fd >= 0 && (events & EPOLLOUT) && c->ctrl_len == 0 && c->s2c.used > 0) {
            size_t s2c_before=c->s2c.used;
            if (send_from_rb(c->fd, &c->s2c, c->read_pending) < 0) {
                c->client_dead = 1;
                c->client_eof = 1;
                c->need_send_eof = 1;
                c->hup_pending = 0;
                c->rdhup_pending = 0;
                detach_client_fd(epfd, c);
            } else {
                if(c->s2c.used<s2c_before)c->last_activity_ms=now_ms();
                if(c->s2c.used==0&&c->ssh_eof)shutdown(c->fd,SHUT_WR);
            }
        }

        if (c->fd >= 0 && (events & (EPOLLERR | EPOLLHUP)) && !c->client_dead) {
            if (c->client_eof || eof_hit || would_block) {
                c->client_eof = 1;
                c->need_send_eof = 1;
                c->client_dead = 1;
                c->hup_pending = 0;
                c->rdhup_pending = 0;
                detach_client_fd(epfd, c);
            } else {
                /* Buffer c2s penuh saat HUP/ERR: cabut fd dari epoll agar tidak CPU spin,
                 * tetapi pertahankan fd tetap terbuka untuk dikuras di pump_ssh_channels. */
                c->hup_pending = 1;
                c->rdhup_pending = 0;
                suspend_client_epoll(epfd, c);
            }
        } else if (c->fd >= 0 && (events & EPOLLRDHUP) && !c->client_eof) {
            if (eof_hit || would_block) {
                c->client_eof = 1;
                c->need_send_eof = 1;
                c->rdhup_pending = 0;
            } else {
                c->rdhup_pending = 1;
            }
        }

        if (c->fd >= 0 && !c->hup_pending && !c->client_dead) {
            uint32_t want = client_rdhup_flag(c);
            if (!c->client_eof && rb_free_space(&c->c2s) > 0) want |= EPOLLIN;
            if (c->s2c.used > 0 || c->ctrl_len > 0) want |= EPOLLOUT;
            update_client_epoll(epfd, c, want);
        }

        if ((c->client_dead && !c->hup_pending && c->c2s.used == 0 && !c->need_send_eof) ||
            (c->client_eof && c->ssh_eof && c->c2s.used == 0 && c->s2c.used == 0 && !c->need_send_eof)) {
            start_closing_client(epfd, c);
            return;
        }
    }
}

static int is_libssh2_socket_fatal(int err) {
    return (err == LIBSSH2_ERROR_SOCKET_RECV ||
            err == LIBSSH2_ERROR_SOCKET_SEND ||
            err == LIBSSH2_ERROR_SOCKET_DISCONNECT);
}

static void record_eagain(LIBSSH2_SESSION *session, upstream_ctx_t *u,
                          client_conn_t *c, pending_op_t op,
                          int *agg_dirs_out, int *stop_loop_out) {
    int d = libssh2_session_block_directions(session);
    *agg_dirs_out |= d;
    int need_out = (d & LIBSSH2_SESSION_BLOCK_OUTBOUND) || (u->ssl && u->ssl_want_events == EPOLLOUT);
    if (need_out || op == PENDING_KEEPALIVE) {
        g_pending_client = c;
        g_pending_op = op;
        *stop_loop_out = 1;
    }
}

static int finish_open_channel(int epfd, client_conn_t *c, LIBSSH2_CHANNEL *ch) {
    g_opening_client = NULL;
    c->channel = ch;
    if (c->close_after_ctrl && c->fd >= 0 && c->ctrl_len > 0) {
        c->abort_on_open = 0;
        c->abort_on_pending = 0;
        update_client_epoll(epfd, c, EPOLLOUT);
        return 1;
    }
    if (c->abort_on_open || c->abort_on_pending || c->close_after_ctrl || c->fd < 0) {
        c->abort_on_pending = 0;
        start_closing_client(epfd, c);
        return 1;
    }
    if (rb_init(&c->c2s, RELAY_BUF_SIZE) < 0 || rb_init(&c->s2c, RELAY_BUF_SIZE) < 0) {
        start_closing_client(epfd, c);
        return 1;
    }
    if (c->early_len > 0) {
        (void)rb_push(&c->c2s, c->early_buf, c->early_len);
        note_c2s_buffer_peak(c);
        c->early_len = 0;
    }
    uint8_t ok_rep[10] = {0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0};
    if (rb_push(&c->s2c, ok_rep, 10) < 0) {
        start_closing_client(epfd, c);
        return 1;
    }
    c->state = ST_RELAY;

    if (c->rdhup_pending && !c->client_eof) {
        drain_pending_eof_to_c2s(epfd, c);
    }

    if (c->fd >= 0 && c->ctrl_len == 0) {
        if (send_from_rb(c->fd, &c->s2c, 0) < 0) {
            c->client_dead = 1;
            c->client_eof = 1;
            c->need_send_eof = 1;
            c->hup_pending = 0;
            c->rdhup_pending = 0;
            start_closing_client(epfd, c);
            return 1;
        }
    }

    if (c->fd >= 0 && !c->hup_pending && !c->client_dead) {
        uint32_t want = client_rdhup_flag(c);
        if (!c->client_eof && rb_free_space(&c->c2s) > 0) want |= EPOLLIN;
        if (c->s2c.used > 0 || c->ctrl_len > 0) want |= EPOLLOUT;
        update_client_epoll(epfd, c, want);
    }
    return 1;
}

/* Return: 1 progres nyata, 2 pending dilepas tanpa progres data (lanjut scan),
 * 0 masih tertahan EAGAIN di op yang sama, -1 session fatal. */
static int resume_pending_op(int epfd, LIBSSH2_SESSION *session, upstream_ctx_t *u,
                             int *agg_dirs_out, int *did_ssh_read_out,
                             client_conn_t **retried_open_out) {
    *retried_open_out = NULL;
    client_conn_t *c = g_pending_client;
    pending_op_t op = g_pending_op;

    if (op == PENDING_KEEPALIVE) {
        int next_sec = 0;
        int rc = libssh2_keepalive_send(session, &next_sec);
        if (rc == 0) {
            u->last_activity = time(NULL);
            g_pending_op = PENDING_NONE;
            g_pending_client = NULL;
            return 1;
        }
        if (rc == LIBSSH2_ERROR_EAGAIN) {
            *agg_dirs_out |= libssh2_session_block_directions(session);
            return 0;
        }
        return -1;
    }

    if (!c) {
        g_pending_op = PENDING_NONE;
        return 2;
    }

    if (op == PENDING_OPEN) {
        LIBSSH2_CHANNEL *ch = libssh2_channel_direct_tcpip_ex(
            session, c->target_host, c->target_port, "127.0.0.1", 1080);
        if (ch) {
            g_pending_op = PENDING_NONE;
            g_pending_client = NULL;
            return finish_open_channel(epfd, c, ch);
        }
        int err = libssh2_session_last_errno(session);
        if (err == LIBSSH2_ERROR_EAGAIN) {
            int d = libssh2_session_block_directions(session);
            *agg_dirs_out |= d;
            *did_ssh_read_out = 1;
            if ((d & LIBSSH2_SESSION_BLOCK_OUTBOUND) || (u->ssl && u->ssl_want_events == EPOLLOUT)) {
                return 0;
            }
            if (c->abort_on_pending) {
                c->abort_on_open = 1;
                c->abort_on_pending = 0;
            }
            g_pending_op = PENDING_NONE;
            g_pending_client = NULL;
            *retried_open_out = c;
            return 2;
        }
        g_pending_op = PENDING_NONE;
        g_pending_client = NULL;
        g_opening_client = NULL;
        if (!c->abort_on_open && !c->abort_on_pending && !c->close_after_ctrl && c->fd >= 0) {
            send_socks_err_and_close(epfd, c, 0x05);
        } else if (!c->close_after_ctrl || c->fd < 0) {
            c->abort_on_pending = 0;
            remove_client(epfd, c);
        } else {
            c->abort_on_pending = 0;
        }
        return is_libssh2_socket_fatal(err) ? -1 : 1;
    }

    if (op == PENDING_WRITE) {
        const uint8_t *ptr = c->write_pending_ptr;
        size_t wlen = c->write_pending_len;
        if (!c->write_pending || !ptr || wlen == 0) {
            ptr = rb_read_slice(&c->c2s, &wlen);
        }
        ssize_t w = (ptr && wlen > 0) ? libssh2_channel_write(c->channel, (const char *)ptr, wlen) : 0;
        if (w > 0) {
            rb_commit_read(&c->c2s, (size_t)w, 0);
            note_channel_window_recovered(c);
            c->last_activity_ms=now_ms();
            c->write_pending = 0;
            c->write_pending_ptr = NULL;
            c->write_pending_len = 0;
            c->write_waiting_window = 0;
            c->write_wait_rx_seq = 0;
            g_pending_op = PENDING_NONE;
            g_pending_client = NULL;
            if (c->abort_on_pending) {
                c->abort_on_pending = 0;
                start_closing_client(epfd, c);
            } else {
                drain_pending_eof_to_c2s(epfd, c);
            }
            return 1;
        }
        if (w == 0) {
            int d=libssh2_session_block_directions(session);*agg_dirs_out|=d;
            c->write_pending=(ptr&&wlen>0);c->write_pending_ptr=ptr;c->write_pending_len=wlen;
            c->write_waiting_window=1;c->write_wait_rx_seq=u->rx_seq;
            if (ptr && wlen > 0) note_channel_window_blocked(c, 0);
            g_pending_op=PENDING_NONE;g_pending_client=NULL;
            if(c->abort_on_pending){c->abort_on_pending=0;start_closing_client(epfd,c);return 1;}
            return 2;
        }
        if (w == LIBSSH2_ERROR_EAGAIN) {
            if (libssh2_channel_window_write_ex(c->channel, NULL) == 0)
                note_channel_window_blocked(c, 1);
            c->write_waiting_window=0;
            int d = libssh2_session_block_directions(session);
            *agg_dirs_out |= d;
            if ((d & LIBSSH2_SESSION_BLOCK_OUTBOUND) || (u->ssl && u->ssl_want_events == EPOLLOUT)) {
                return 0;
            }
            g_pending_op = PENDING_NONE;
            g_pending_client = NULL;
            if (c->abort_on_pending) {
                c->abort_on_pending = 0;
                start_closing_client(epfd, c);
                return 1;
            }
            return 2;
        }
        c->write_pending = 0;
        c->write_pending_ptr = NULL;
        c->write_pending_len = 0;
        c->write_waiting_window = 0;
        c->write_wait_rx_seq = 0;
        g_pending_op = PENDING_NONE;
        g_pending_client = NULL;
        c->abort_on_pending = 0;
        start_closing_client(epfd, c);
        return (w < 0 && is_libssh2_socket_fatal((int)w)) ? -1 : 1;
    }

    if (op == PENDING_SEND_EOF) {
        int rc = libssh2_channel_send_eof(c->channel);
        if (rc == 0) {
            c->need_send_eof = 0;
            g_pending_op = PENDING_NONE;
            g_pending_client = NULL;
            if (c->abort_on_pending) {
                c->abort_on_pending = 0;
                start_closing_client(epfd, c);
            }
            return 1;
        }
        if (rc == LIBSSH2_ERROR_EAGAIN) {
            *agg_dirs_out |= libssh2_session_block_directions(session);
            return 0;
        }
        g_pending_op = PENDING_NONE;
        g_pending_client = NULL;
        c->abort_on_pending = 0;
        start_closing_client(epfd, c);
        return is_libssh2_socket_fatal(rc) ? -1 : 1;
    }

    if (op == PENDING_READ) {
        uint8_t *ptr = c->read_pending_ptr;
        size_t rlen = c->read_pending_len;
        if (!c->read_pending || !ptr || rlen == 0) {
            ptr = rb_write_slice(&c->s2c, &rlen);
        }
        ssize_t r = (ptr && rlen > 0) ? libssh2_channel_read(c->channel, (char *)ptr, rlen) : LIBSSH2_ERROR_EAGAIN;
        if (r > 0) {
            c->read_pending = 0;
            c->read_pending_ptr = NULL;
            c->read_pending_len = 0;
            rb_commit_write(&c->s2c, (size_t)r);
            c->last_activity_ms=now_ms();
            *did_ssh_read_out = 1;
            g_pending_op = PENDING_NONE;
            g_pending_client = NULL;
            if (c->abort_on_pending ||
                (c->fd >= 0 && c->ctrl_len == 0 && send_from_rb(c->fd, &c->s2c, 0) < 0)) {
                c->abort_on_pending = 0;
                start_closing_client(epfd, c);
            }
            return 1;
        }
        if (r == 0) {
            c->read_pending = 0;
            c->read_pending_ptr = NULL;
            c->read_pending_len = 0;
            if (c->s2c.used == 0) { c->s2c.head = 0; c->s2c.tail = 0; }
            if (libssh2_channel_eof(c->channel)) {
                c->ssh_eof = 1;
                *did_ssh_read_out = 1;
                if (c->s2c.used == 0 && c->ctrl_len == 0 && c->fd >= 0) shutdown(c->fd, SHUT_WR);
            }
            g_pending_op = PENDING_NONE;
            g_pending_client = NULL;
            if (c->abort_on_pending) {
                c->abort_on_pending = 0;
                start_closing_client(epfd, c);
            }
            return 1;
        }
        if (r == LIBSSH2_ERROR_EAGAIN) {
            int d = libssh2_session_block_directions(session);
            *agg_dirs_out |= d;
            *did_ssh_read_out = 1;
            if ((d & LIBSSH2_SESSION_BLOCK_OUTBOUND) || (u->ssl && u->ssl_want_events == EPOLLOUT)) {
                return 0;
            }
            g_pending_op = PENDING_NONE;
            g_pending_client = NULL;
            if (c->abort_on_pending) {
                c->abort_on_pending = 0;
                start_closing_client(epfd, c);
                return 1;
            }
            return 2;
        }
        c->read_pending = 0;
        c->read_pending_ptr = NULL;
        c->read_pending_len = 0;
        g_pending_op = PENDING_NONE;
        g_pending_client = NULL;
        c->abort_on_pending = 0;
        start_closing_client(epfd, c);
        return is_libssh2_socket_fatal((int)r) ? -1 : 1;
    }

    if (op == PENDING_FREE) {
        int rc = libssh2_channel_free(c->channel);
        if (rc == LIBSSH2_ERROR_EAGAIN) {
            *agg_dirs_out |= libssh2_session_block_directions(session);
            return 0;
        }
        c->channel = NULL;
        g_pending_op = PENDING_NONE;
        g_pending_client = NULL;
        remove_client(epfd, c);
        return 1;
    }

    g_pending_op = PENDING_NONE;
    g_pending_client = NULL;
    return 2;
}

/* Return: 1 ada progres nyata, 2 wire bytes ditarik libssh2 (ulangi pass), 0 idle/EAGAIN, -1 session fatal */
static int pump_ssh_channels(int epfd, LIBSSH2_SESSION *session, upstream_ctx_t *u,
                             int *agg_dirs_out, int *did_ssh_read_out) {
    int any_progress = 0;
    int agg_dirs = 0;
    int did_ssh_read = 0;
    int stop_loop = 0;
    uint64_t rx_before = u->rx_seq;
    client_conn_t *just_retried_open = NULL;

    if (g_pending_op != PENDING_NONE) {
        int pr = resume_pending_op(epfd, session, u, &agg_dirs, &did_ssh_read, &just_retried_open);
        if (pr < 0) {
            *agg_dirs_out = agg_dirs;
            *did_ssh_read_out = did_ssh_read;
            return -1;
        }
        if (pr == 0) {
            *agg_dirs_out = agg_dirs;
            *did_ssh_read_out = did_ssh_read;
            return 0;
        }
        if (pr == 1) any_progress = 1;
    }

    client_conn_t *c = g_clients;
    while (c && !stop_loop) {
        client_conn_t *next = c->next;

        if (c->state == ST_SSH_OPENING) {
            int opening_already_started = (g_opening_client == c);
            if ((opening_already_started ||
                 (g_opening_client == NULL &&
                  !c->close_after_ctrl &&
                  !c->abort_on_open &&
                  !c->abort_on_pending)) &&
                c != just_retried_open) {
                g_opening_client = c;
                if (c->open_started_ms == 0) c->open_started_ms = now_ms();
                LIBSSH2_CHANNEL *ch = libssh2_channel_direct_tcpip_ex(
                    session, c->target_host, c->target_port, "127.0.0.1", 1080);
                if (ch) {
                    any_progress = finish_open_channel(epfd, c, ch);
                } else {
                    int err = libssh2_session_last_errno(session);
                    if (err == LIBSSH2_ERROR_EAGAIN) {
                        did_ssh_read = 1;
                        record_eagain(session, u, c, PENDING_OPEN, &agg_dirs, &stop_loop);
                    } else {
                        g_opening_client = NULL;
                        if (!c->abort_on_open && !c->abort_on_pending && !c->close_after_ctrl && c->fd >= 0) {
                            send_socks_err_and_close(epfd, c, 0x05);
                        } else if (!c->close_after_ctrl || c->fd < 0) {
                            c->abort_on_pending = 0;
                            remove_client(epfd, c);
                        } else {
                            c->abort_on_pending = 0;
                        }
                        if (is_libssh2_socket_fatal(err)) {
                            *agg_dirs_out = agg_dirs;
                            *did_ssh_read_out = did_ssh_read;
                            return -1;
                        }
                    }
                }
            }
        } else if (c->state == ST_RELAY) {
            if (drain_pending_eof_to_c2s(epfd, c)) {
                any_progress = 1;
            }

            if (c->c2s.used > 0 &&
                (!c->write_waiting_window || u->rx_seq != c->write_wait_rx_seq)) {
                if (c->write_waiting_window) c->write_waiting_window=0;
                const uint8_t *ptr = NULL;
                size_t avail = 0;
                if (c->write_pending) {
                    ptr = c->write_pending_ptr;
                    avail = c->write_pending_len;
                } else {
                    ptr = rb_read_slice(&c->c2s, &avail);
                }
                if (ptr && avail > 0) {
                    ssize_t w = libssh2_channel_write(c->channel, (const char *)ptr, avail);
                    if (w > 0) {
                        c->write_pending = 0;
                        c->write_pending_ptr = NULL;
                        c->write_pending_len = 0;
                        c->write_waiting_window = 0;
                        c->write_wait_rx_seq = 0;
                        c->last_activity_ms = now_ms();
                        rb_commit_read(&c->c2s, (size_t)w, 0);
                        note_channel_window_recovered(c);
                        any_progress = 1;
                        if (c->abort_on_pending) {
                            c->abort_on_pending = 0;
                            start_closing_client(epfd, c);
                            c = next;
                            continue;
                        }
                        (void)drain_pending_eof_to_c2s(epfd, c);
                    } else if (w == 0) {
                        int d=libssh2_session_block_directions(session);agg_dirs|=d;
                        c->write_pending=1;c->write_pending_ptr=ptr;c->write_pending_len=avail;
                        c->write_waiting_window=1;c->write_wait_rx_seq=u->rx_seq;
                        note_channel_window_blocked(c, 0);
                        if(c->abort_on_pending){c->abort_on_pending=0;start_closing_client(epfd,c);c=next;continue;}
                    } else if (w == LIBSSH2_ERROR_EAGAIN) {
                        unsigned long write_window = libssh2_channel_window_write_ex(c->channel, NULL);
                        c->write_pending = 1;
                        c->write_pending_ptr = ptr;
                        c->write_pending_len = avail;
                        if (write_window == 0) {
                            /*
                             * libssh2 reports a depleted channel write window as EAGAIN
                             * when it has no inbound packet available to process. Query
                             * the channel window directly; the return code alone cannot
                             * distinguish this from socket-level EAGAIN.
                             */
                            c->write_waiting_window = 1;
                            c->write_wait_rx_seq = u->rx_seq;
                            note_channel_window_blocked(c, 1);
                        } else {
                            c->write_waiting_window = 0;
                            c->write_wait_rx_seq = 0;
                        }
                        record_eagain(session, u, c, PENDING_WRITE, &agg_dirs, &stop_loop);
                        if (stop_loop) break;
                    } else {
                        c->write_pending = 0;
                        c->write_pending_ptr = NULL;
                        c->write_pending_len = 0;
                        c->write_waiting_window = 0;
                        c->write_wait_rx_seq = 0;
                        c->abort_on_pending = 0;
                        start_closing_client(epfd, c);
                        if (w < 0 && is_libssh2_socket_fatal((int)w)) {
                            *agg_dirs_out = agg_dirs;
                            *did_ssh_read_out = did_ssh_read;
                            return -1;
                        }
                        c = next;
                        continue;
                    }
                }
            }

            if (c->need_send_eof && c->c2s.used == 0 && !c->write_pending) {
                int rc = libssh2_channel_send_eof(c->channel);
                if (rc == 0) {
                    c->need_send_eof = 0;
                    any_progress = 1;
                    if (c->abort_on_pending) {
                        c->abort_on_pending = 0;
                        start_closing_client(epfd, c);
                        c = next;
                        continue;
                    }
                } else if (rc == LIBSSH2_ERROR_EAGAIN) {
                    record_eagain(session, u, c, PENDING_SEND_EOF, &agg_dirs, &stop_loop);
                    if (stop_loop) break;
                } else {
                    c->abort_on_pending = 0;
                    start_closing_client(epfd, c);
                    if (is_libssh2_socket_fatal(rc)) {
                        *agg_dirs_out = agg_dirs;
                        *did_ssh_read_out = did_ssh_read;
                        return -1;
                    }
                    c = next;
                    continue;
                }
            }

            if (c->client_dead && !c->hup_pending && c->c2s.used == 0 && !c->need_send_eof) {
                c->abort_on_pending = 0;
                start_closing_client(epfd, c);
                c = next;
                continue;
            }

            if (!c->ssh_eof && !c->client_dead && (c->read_pending || rb_free_space(&c->s2c) > 0)) {
                uint8_t *ptr = NULL;
                size_t avail = 0;
                if (c->read_pending) {
                    ptr = c->read_pending_ptr;
                    avail = c->read_pending_len;
                } else {
                    ptr = rb_write_slice(&c->s2c, &avail);
                }
                if (ptr && avail > 0) {
                    ssize_t r = libssh2_channel_read(c->channel, (char *)ptr, avail);
                    if (r > 0) {
                        c->read_pending = 0;
                        c->read_pending_ptr = NULL;
                        c->read_pending_len = 0;
                        did_ssh_read = 1;
                        rb_commit_write(&c->s2c, (size_t)r);
                        c->last_activity_ms=now_ms();
                        any_progress = 1;
                        if (c->abort_on_pending ||
                            (c->fd >= 0 && c->ctrl_len == 0 && send_from_rb(c->fd, &c->s2c, 0) < 0)) {
                            c->abort_on_pending = 0;
                            c->client_dead = 1;
                            c->client_eof = 1;
                            c->need_send_eof = 1;
                            c->hup_pending = 0;
                            c->rdhup_pending = 0;
                            start_closing_client(epfd, c);
                            c = next;
                            continue;
                        }
                    } else if (r == 0) {
                        c->read_pending = 0;
                        c->read_pending_ptr = NULL;
                        c->read_pending_len = 0;
                        if (c->s2c.used == 0) { c->s2c.head = 0; c->s2c.tail = 0; }
                        if (libssh2_channel_eof(c->channel)) {
                            did_ssh_read = 1;
                            c->ssh_eof = 1;
                            if (c->s2c.used == 0 && c->ctrl_len == 0 && c->fd >= 0) {
                                shutdown(c->fd, SHUT_WR);
                            }
                            any_progress = 1;
                        }
                        if (c->abort_on_pending) {
                            c->abort_on_pending = 0;
                            start_closing_client(epfd, c);
                            c = next;
                            continue;
                        }
                    } else if (r == LIBSSH2_ERROR_EAGAIN) {
                        did_ssh_read = 1;
                        c->read_pending = 1;
                        c->read_pending_ptr = ptr;
                        c->read_pending_len = avail;
                        record_eagain(session, u, c, PENDING_READ, &agg_dirs, &stop_loop);
                        if (stop_loop) break;
                    } else {
                        c->read_pending = 0;
                        c->read_pending_ptr = NULL;
                        c->read_pending_len = 0;
                        c->abort_on_pending = 0;
                        start_closing_client(epfd, c);
                        if (is_libssh2_socket_fatal((int)r)) {
                            *agg_dirs_out = agg_dirs;
                            *did_ssh_read_out = did_ssh_read;
                            return -1;
                        }
                        c = next;
                        continue;
                    }
                }
            }

            if (c->client_eof && c->ssh_eof && c->c2s.used == 0 && c->s2c.used == 0 && !c->need_send_eof) {
                c->abort_on_pending = 0;
                start_closing_client(epfd, c);
                c = next;
                continue;
            }

            if (c->fd >= 0 && !c->hup_pending && !c->client_dead) {
                uint32_t want = client_rdhup_flag(c);
                if (!c->client_eof && rb_free_space(&c->c2s) > 0) want |= EPOLLIN;
                if (c->s2c.used > 0 || c->ctrl_len > 0) want |= EPOLLOUT;
                update_client_epoll(epfd, c, want);
            }
        } else if (c->state == ST_CLOSING) {
            int rc = libssh2_channel_free(c->channel);
            if (rc == LIBSSH2_ERROR_EAGAIN) {
                record_eagain(session, u, c, PENDING_FREE, &agg_dirs, &stop_loop);
                if (stop_loop) break;
            } else {
                c->channel = NULL;
                remove_client(epfd, c);
                any_progress = 1;
            }
        }

        c = next;
    }

    *agg_dirs_out = agg_dirs;
    *did_ssh_read_out = did_ssh_read;
    if (any_progress) return 1;
    if (!stop_loop && g_pending_op == PENDING_NONE && u->rx_seq != rx_before) return 2;
    return 0;
}

static int has_readable_relay_channel(void) {
    for (client_conn_t *c = g_clients; c; c = c->next) {
        if (c->state == ST_RELAY && !c->ssh_eof && !c->client_dead &&
            (c->read_pending || rb_free_space(&c->s2c) > 0)) {
            return 1;
        }
    }
    return 0;
}

static int check_upstream_eof_peek(upstream_ctx_t *u) {
    uint8_t tmp[1];
    if (u->ssl) {
        int r = SSL_peek(u->ssl, tmp, 1);
        if (r > 0) { u->ssl_want_events = 0; return 1; }
        int err = SSL_get_error(u->ssl, r);
        if (err == SSL_ERROR_WANT_READ) { u->ssl_want_events = EPOLLIN; return -2; }
        if (err == SSL_ERROR_WANT_WRITE) { u->ssl_want_events = EPOLLOUT; return -2; }
        return -1;
    }
    ssize_t n;
    do {
        n = recv(u->fd, tmp, 1, MSG_PEEK);
    } while (n < 0 && errno == EINTR);
    if (n > 0) return 1;
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return -2;
    return -1;
}

static void on_sig(int sig) {
    (void)sig;
    g_stop = 1;
}

#ifndef SSH_CORE_PARSER_TEST
int main(int argc, char **argv) {
    app_cfg_t cfg = {
        .transport = "TCP",
        .host_port = "",
        .proxy_port = "",
        .delay_ms = 1000,
        .fix_crlf = 1,
        .socks_addr = "127.0.0.1:1080",
        .keepalive_sec = 15,
        .verify_tls = 0,
        .allow_remote_socks = 0,
        .allow_http_200_tunnel = 0,
        .idle_timeout_sec = DEFAULT_IDLE_TIMEOUT,
        .hostkey_fp = "",
        .max_clients = DEFAULT_MAX_CLIENTS
    };
    const char *env_file = NULL;
    const char *payload_file = NULL;
    const char *payload_str = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [-env FILE] [-payload-file FILE] [-socks 127.0.0.1:1080] [-verify-tls 0|1] [-allow-remote-socks 0|1] [-http-200-tunnel 0|1] [-idle-timeout SEC] [-hostkey SHA256:...] [-max-clients 1..256] [-log FILE|-]\\n", argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-env") == 0 && i + 1 < argc) {
            env_file = argv[++i];
        } else if (strcmp(argv[i], "-log") == 0 && i + 1 < argc) {
            g_log_path = argv[++i];
        }
    }

    if (env_file) load_env(env_file, &cfg);

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-env") == 0 && i + 1 < argc) { i++; }
        else if (strcmp(argv[i], "-log") == 0 && i + 1 < argc) { i++; }
        else if (strcmp(argv[i], "-payload-file") == 0 && i + 1 < argc) payload_file = argv[++i];
        else if (strcmp(argv[i], "-payload") == 0 && i + 1 < argc) payload_str = argv[++i];
        else if (strcmp(argv[i], "-transport") == 0 && i + 1 < argc) snprintf(cfg.transport, sizeof(cfg.transport), "%s", argv[++i]);
        else if (strcmp(argv[i], "-host") == 0 && i + 1 < argc) snprintf(cfg.host, sizeof(cfg.host), "%s", argv[++i]);
        else if (strcmp(argv[i], "-port") == 0 && i + 1 < argc) snprintf(cfg.host_port, sizeof(cfg.host_port), "%s", argv[++i]);
        else if (strcmp(argv[i], "-user") == 0 && i + 1 < argc) snprintf(cfg.username, sizeof(cfg.username), "%s", argv[++i]);
        else if (strcmp(argv[i], "-pass") == 0 && i + 1 < argc) snprintf(cfg.password, sizeof(cfg.password), "%s", argv[++i]);
        else if (strcmp(argv[i], "-proxy") == 0 && i + 1 < argc) snprintf(cfg.proxy, sizeof(cfg.proxy), "%s", argv[++i]);
        else if (strcmp(argv[i], "-proxy-port") == 0 && i + 1 < argc) snprintf(cfg.proxy_port, sizeof(cfg.proxy_port), "%s", argv[++i]);
        else if (strcmp(argv[i], "-sni") == 0 && i + 1 < argc) snprintf(cfg.sni, sizeof(cfg.sni), "%s", argv[++i]);
        else if (strcmp(argv[i], "-socks") == 0 && i + 1 < argc) snprintf(cfg.socks_addr, sizeof(cfg.socks_addr), "%s", argv[++i]);
        else if (strcmp(argv[i], "-delay") == 0 && i + 1 < argc) { if(parse_int_range(argv[++i],0,600000,&cfg.delay_ms)<0){log_red("Nilai -delay tidak valid");return 1;} }
        else if (strcmp(argv[i], "-keepalive") == 0 && i + 1 < argc) { if(parse_int_range(argv[++i],0,3600,&cfg.keepalive_sec)<0){log_red("Nilai -keepalive tidak valid");return 1;} }
        else if (strcmp(argv[i], "-fix-crlf") == 0 && i + 1 < argc) { if(parse_int_range(argv[++i],0,1,&cfg.fix_crlf)<0){log_red("Nilai -fix-crlf tidak valid");return 1;} }
        else if (strcmp(argv[i], "-verify-tls") == 0 && i + 1 < argc) { if(parse_int_range(argv[++i],0,1,&cfg.verify_tls)<0){log_red("Nilai -verify-tls tidak valid");return 1;} }
        else if (strcmp(argv[i], "-allow-remote-socks") == 0 && i + 1 < argc) { if(parse_int_range(argv[++i],0,1,&cfg.allow_remote_socks)<0){log_red("Nilai -allow-remote-socks tidak valid");return 1;} }
        else if (strcmp(argv[i], "-http-200-tunnel") == 0 && i + 1 < argc) { if(parse_int_range(argv[++i],0,1,&cfg.allow_http_200_tunnel)<0){log_red("Nilai -http-200-tunnel tidak valid");return 1;} }
        else if (strcmp(argv[i], "-idle-timeout") == 0 && i + 1 < argc) { if(parse_int_range(argv[++i],0,86400,&cfg.idle_timeout_sec)<0){log_red("Nilai -idle-timeout tidak valid");return 1;} }
        else if (strcmp(argv[i], "-hostkey") == 0 && i + 1 < argc) snprintf(cfg.hostkey_fp,sizeof(cfg.hostkey_fp),"%s",argv[++i]);
        else if (strcmp(argv[i], "-max-clients") == 0 && i + 1 < argc) { if(parse_int_range(argv[++i],1,MAX_CLIENTS_LIMIT,&cfg.max_clients)<0){log_red("MAX_CLIENTS harus 1..%d",MAX_CLIENTS_LIMIT);return 1;} }
    }

    if (!cfg.host[0] || !cfg.username[0]) {
        fprintf(stderr, "Host dan Username wajib diisi\n");
        return 1;
    }

    char listen_ip[64] = "127.0.0.1";
    int listen_port = 1080;
    char *colon = strrchr(cfg.socks_addr, ':');
    if (colon) {
        size_t ilen = (size_t)(colon - cfg.socks_addr);
        if (ilen > 0) {
            if (ilen >= sizeof(listen_ip)) {
                log_red("Alamat SOCKS5 terlalu panjang: %s", cfg.socks_addr);
                return 1;
            }
            memcpy(listen_ip, cfg.socks_addr, ilen);
            listen_ip[ilen] = '\0';
        }
        char *pend = NULL;
        long p = strtol(colon + 1, &pend, 10);
        if (pend == colon + 1 || *pend != '\0' || p < 1 || p > 65535) {
            log_red("Port SOCKS5 tidak valid: %s", cfg.socks_addr);
            return 1;
        }
        listen_port = (int)p;
    } else if (cfg.socks_addr[0]) {
        snprintf(listen_ip, sizeof(listen_ip), "%s", cfg.socks_addr);
    }

    struct sockaddr_in laddr = {0};
    laddr.sin_family = AF_INET;
    laddr.sin_port = htons((uint16_t)listen_port);
    if (inet_pton(AF_INET, listen_ip, &laddr.sin_addr) != 1) {
        log_red("Alamat IPv4 SOCKS5 tidak valid: %s", listen_ip);
        return 1;
    }
    if (strcmp(listen_ip, "127.0.0.1") != 0) {
        if(!cfg.allow_remote_socks){log_red("Bind SOCKS5 non-loopback ditolak; set ALLOW_REMOTE_SOCKS=1 hanya jika firewall membatasi akses");return 1;}
        log_yellow("PERINGATAN: SOCKS5 tanpa autentikasi di-bind ke %s:%d; lindungi dengan firewall",listen_ip,listen_port);
    }

    char *raw_payload = NULL;
    if (payload_str) {
        raw_payload = strdup(payload_str);
    } else if (payload_file) {
        raw_payload = read_entire_file(payload_file);
        if (!raw_payload) log_yellow("Peringatan: gagal membaca payload file %s", payload_file);
    }
    if (!raw_payload) raw_payload = strdup("");

    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);

    unlink(AUTH_FAILED_FILE);
    unlink(KEX_FAILED_FILE);
    unlink(NEED_RESTART_FILE);

    int is_tls = (strcasecmp(cfg.transport, "TLS") == 0);
    const char *dial_host = cfg.host;
    const char *dial_port = cfg.host_port;

    if (is_tls) {
        if (cfg.proxy[0]) {
            dial_host = cfg.proxy;
            dial_port = cfg.proxy_port[0] ? cfg.proxy_port : "443";
            log_blue("Mode: Direct C TLS/SNI + Proxy -> %s:%s (SNI: %s)", dial_host, dial_port, cfg.sni);
        } else {
            dial_host = cfg.host;
            dial_port = (cfg.host_port[0] && strcmp(cfg.host_port, "22") != 0) ? cfg.host_port : "443";
            log_blue("Mode: Direct C TLS/SNI -> %s:%s (SNI: %s)", dial_host, dial_port, cfg.sni);
        }
    } else {
        if (cfg.proxy[0]) {
            dial_host = cfg.proxy;
            dial_port = cfg.proxy_port[0] ? cfg.proxy_port : "80";
            log_blue("Mode: C TCP via HTTP Proxy -> %s:%s", dial_host, dial_port);
        } else {
            dial_host = cfg.host;
            dial_port = cfg.host_port[0] ? cfg.host_port : "80";
            log_blue("Mode: C Direct TCP Injector -> %s:%s", dial_host, dial_port);
        }
    }

    int upstream_fd = tcp_connect_host(dial_host, dial_port);
    if (upstream_fd < 0) {
        log_red("Koneksi TCP upstream gagal ke %s:%s", dial_host, dial_port);
        write_marker(NEED_RESTART_FILE, "TCP connect failed");
        free(raw_payload);
        return 1;
    }

    upstream_ctx_t uctx = { .fd=upstream_fd, .last_activity=time(NULL), .allow_http_200_tunnel=cfg.allow_http_200_tunnel };
    SSL_CTX *ssl_ctx = NULL;
    LIBSSH2_SESSION *session = NULL;
    int listen_fd = -1;
    int epfd = -1;
    int exit_code = 1;

    if (is_tls) {
        static const unsigned char alpn_http11[] = { 8, 'h', 't', 't', 'p', '/', '1', '.', '1' };
        ssl_ctx = SSL_CTX_new(TLS_client_method());
        if (!ssl_ctx) {
            log_red("SSL_CTX_new gagal");
            write_marker(NEED_RESTART_FILE, "SSL_CTX_new failed");
            goto fail_cleanup;
        }
        SSL_CTX_set_mode(ssl_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
        SSL_CTX_set_alpn_protos(ssl_ctx, alpn_http11, sizeof(alpn_http11));
        if (cfg.verify_tls) {
            if (SSL_CTX_set_default_verify_paths(ssl_ctx) != 1) {
                log_red("SSL_CTX_set_default_verify_paths gagal");
                write_marker(NEED_RESTART_FILE, "TLS CA store failed");
                goto fail_cleanup;
            }
            SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
        }

        uctx.ssl = SSL_new(ssl_ctx);
        if (!uctx.ssl) {
            log_red("SSL_new gagal");
            write_marker(NEED_RESTART_FILE, "SSL_new failed");
            goto fail_cleanup;
        }
        const char *sni = cfg.sni[0] ? cfg.sni : dial_host;
        if (SSL_set_tlsext_host_name(uctx.ssl, sni) != 1) {
            log_red("SSL_set_tlsext_host_name gagal");
            write_marker(NEED_RESTART_FILE, "TLS SNI setup failed");
            goto fail_cleanup;
        }
        if (cfg.verify_tls && SSL_set1_host(uctx.ssl, sni) != 1) {
            log_red("SSL_set1_host gagal untuk %s", sni);
            write_marker(NEED_RESTART_FILE, "TLS hostname verify setup failed");
            goto fail_cleanup;
        }
        SSL_set_fd(uctx.ssl, upstream_fd);

        if (tls_connect_nb(&uctx, HANDSHAKE_TIMEOUT_MS) < 0) {
            write_marker(NEED_RESTART_FILE, "TLS handshake failed");
            goto fail_cleanup;
        }
        log_blue("TLS Connected: %s (%s)", SSL_get_version(uctx.ssl), SSL_get_cipher_name(uctx.ssl));
    }

    int has_embedded_banner = 0;
    char *translated = translate_payload(raw_payload, &cfg, is_tls, &has_embedded_banner);
    free(raw_payload);
    raw_payload = NULL;
    if (!translated) {
        log_red("Gagal membangun payload (alokasi atau generator random gagal)");
        write_marker(NEED_RESTART_FILE,"payload translation failed");
        goto fail_cleanup;
    }
    if (has_embedded_banner) {
        uctx.skip_ssh_banner_bytes = strlen(SSH_CLIENT_BANNER "\r\n");
    }

    char *split_ds = strstr(translated, "[delay_split]");
    char *split_s = strstr(translated, "[split]");
    if (split_ds) {
        log_blue("Sending HTTP Payload (delay_split)...");
        const char *p2 = split_ds + strlen("[delay_split]");
        if (split_ds > translated) {
            uctx.expect_connect_resp = starts_with_connect_request(translated);
            if (raw_write_all_nb(&uctx, translated, (size_t)(split_ds - translated), 10000) < 0) {
                log_red("Gagal mengirim payload part 1"); write_marker(NEED_RESTART_FILE, "payload write"); free(translated); goto fail_cleanup;
            }
        } else {
            uctx.expect_connect_resp = starts_with_connect_request(p2);
        }
        delay_wait_and_drain(&uctx, cfg.delay_ms);
        if (*p2 && raw_write_all_nb(&uctx, p2, strlen(p2), 10000) < 0) {
            log_red("Gagal mengirim payload part 2"); write_marker(NEED_RESTART_FILE, "payload write"); free(translated); goto fail_cleanup;
        }
    } else if (split_s) {
        log_blue("Sending HTTP Payload (split)...");
        const char *p2 = split_s + strlen("[split]");
        if (split_s > translated) {
            uctx.expect_connect_resp = starts_with_connect_request(translated);
            if (raw_write_all_nb(&uctx, translated, (size_t)(split_s - translated), 10000) < 0) {
                log_red("Gagal mengirim payload part 1"); write_marker(NEED_RESTART_FILE, "payload write"); free(translated); goto fail_cleanup;
            }
            long long deadline = now_ms() + HANDSHAKE_TIMEOUT_MS;
            int split_rc = 0;
            do {
                uctx.last_http_code = 0;
                while ((split_rc = consume_one_http_response(&uctx, 1)) == -2) {
                    short ev = (uctx.ssl && uctx.ssl_want_events == EPOLLOUT) ? POLLOUT : POLLIN;
                    if (poll_fd_until(upstream_fd, ev, deadline) <= 0) { split_rc = -1; break; }
                }
            } while (split_rc == 0 && !uctx.tunnel_established &&
                     uctx.last_http_code >= 100 && uctx.last_http_code < 200);
            if (split_rc < 0) {
                log_red("Gagal menerima respons HTTP split"); write_marker(NEED_RESTART_FILE, "split wait"); free(translated); goto fail_cleanup;
            }
        }
        if (*p2) {
            if (split_s == translated || starts_with_http_request(p2)) {
                uctx.tunnel_established = 0;
                uctx.last_http_code = 0;
                uctx.expect_connect_resp = starts_with_connect_request(p2);
            }
            if (raw_write_all_nb(&uctx, p2, strlen(p2), 10000) < 0) {
                log_red("Gagal mengirim payload part 2"); write_marker(NEED_RESTART_FILE, "payload write"); free(translated); goto fail_cleanup;
            }
        }
    } else if (*translated) {
        log_blue("Sending HTTP Payload...");
        uctx.expect_connect_resp = starts_with_connect_request(translated);
        if (raw_write_all_nb(&uctx, translated, strlen(translated), 10000) < 0) {
            log_red("Gagal mengirim payload"); write_marker(NEED_RESTART_FILE, "payload write"); free(translated); goto fail_cleanup;
        }
    }
    free(translated);

    if (libssh2_init(0) != 0) {
        log_red("libssh2_init gagal");
        goto fail_cleanup;
    }
    session = libssh2_session_init_ex(NULL, NULL, NULL, &uctx);
    if (!session) {
        log_red("libssh2_session_init gagal");
        goto fail_cleanup;
    }
    libssh2_session_callback_set2(session, LIBSSH2_CALLBACK_RECV, (libssh2_cb_generic *)ssh_recv_cb);
    libssh2_session_callback_set2(session, LIBSSH2_CALLBACK_SEND, (libssh2_cb_generic *)ssh_send_cb);
    libssh2_session_banner_set(session, SSH_CLIENT_BANNER);
    libssh2_session_flag(session, LIBSSH2_FLAG_SIGPIPE, 0);
    libssh2_session_set_blocking(session, 0);

    log_blue("SSH Client : %s (libssh2)", SSH_CLIENT_BANNER + 8);
    log_blue("Starting Key Exchange");

    libssh2_session_method_pref(session, LIBSSH2_METHOD_CRYPT_CS, "chacha20-poly1305@openssh.com,aes128-gcm@openssh.com,aes128-ctr,aes256-ctr");
    libssh2_session_method_pref(session, LIBSSH2_METHOD_CRYPT_SC, "chacha20-poly1305@openssh.com,aes128-gcm@openssh.com,aes128-ctr,aes256-ctr");

    {
        long long deadline = now_ms() + HANDSHAKE_TIMEOUT_MS;
        int hs_rc;
        while ((hs_rc = libssh2_session_handshake(session, upstream_fd)) == LIBSSH2_ERROR_EAGAIN) {
            if (wait_ssh_nb(session, &uctx, deadline) <= 0) { hs_rc = -1; break; }
        }
        if (hs_rc != 0) {
            char *emsg = NULL;
            libssh2_session_last_error(session, &emsg, NULL, 0);
            if (!uctx.tunnel_established && uctx.last_http_code >= 300) {
                log_red("HTTP/Proxy Rejected (%d): %s", uctx.last_http_code, uctx.last_status);
                write_marker(NEED_RESTART_FILE, uctx.last_status[0] ? uctx.last_status : "http rejected");
            } else {
                log_red("SSH Handshake/KEX Failed: %s", emsg ? emsg : "timeout/error");
                write_marker(KEX_FAILED_FILE, emsg ? emsg : "kex failed");
            }
            goto fail_cleanup;
        }
    }

    const char *srv_banner = libssh2_session_banner_get(session);
    if (srv_banner) {
        const char *sv = strncmp(srv_banner, "SSH-2.0-", 8) == 0 ? srv_banner + 8 : srv_banner;
        log_blue("SSH Server : %s", sv);
    }

    if (verify_ssh_hostkey(session, &cfg) < 0) {
        goto fail_cleanup;
    }

    const char *authlist = NULL;
    {
        long long deadline = now_ms() + HANDSHAKE_TIMEOUT_MS;
        int list_timed_out = 0;
        while (1) {
            authlist = libssh2_userauth_list(session, cfg.username, (unsigned int)strlen(cfg.username));
            if (authlist || libssh2_session_last_errno(session) != LIBSSH2_ERROR_EAGAIN) break;
            if (wait_ssh_nb(session, &uctx, deadline) <= 0) {
                list_timed_out = 1;
                break;
            }
        }
        if (list_timed_out) {
            log_red("Authentication Timeout (userauth_list)");
            write_marker(NEED_RESTART_FILE, "auth list timeout");
            goto fail_cleanup;
        }
    }

    int auth_ok = 0;
    if (!authlist || strstr(authlist, "password")) {
        long long deadline = now_ms() + HANDSHAKE_TIMEOUT_MS;
        int auth_rc;
        while ((auth_rc = libssh2_userauth_password(session, cfg.username, cfg.password)) == LIBSSH2_ERROR_EAGAIN) {
            if (wait_ssh_nb(session, &uctx, deadline) <= 0) {
                log_red("Authentication Timeout (password)");
                write_marker(NEED_RESTART_FILE, "password auth timeout");
                goto fail_cleanup;
            }
        }
        if (auth_rc == 0) auth_ok = 1;
    }
    if (!auth_ok && (!authlist || strstr(authlist, "keyboard-interactive"))) {
        g_kbd_password = cfg.password;
        long long deadline = now_ms() + HANDSHAKE_TIMEOUT_MS;
        int auth_rc;
        while ((auth_rc = libssh2_userauth_keyboard_interactive(session, cfg.username, kbd_auth_cb)) == LIBSSH2_ERROR_EAGAIN) {
            if (wait_ssh_nb(session, &uctx, deadline) <= 0) {
                log_red("Authentication Timeout (keyboard-interactive)");
                write_marker(NEED_RESTART_FILE, "kbdint auth timeout");
                goto fail_cleanup;
            }
        }
        if (auth_rc == 0) auth_ok = 1;
    }
    if (!auth_ok) {
        char *emsg = NULL;
        libssh2_session_last_error(session, &emsg, NULL, 0);
        log_red("Authentication Failed: %s", emsg ? emsg : "Permission denied");
        write_marker(AUTH_FAILED_FILE, emsg ? emsg : "Permission denied");
        goto fail_cleanup;
    }

    log_blue("Session Keys Established");
    {
        const char *cp = libssh2_session_methods(session, LIBSSH2_METHOD_CRYPT_SC);
        const char *mc = libssh2_session_methods(session, LIBSSH2_METHOD_MAC_SC);
        log_blue("SSH Cipher: %s | MAC: %s", cp ? cp : "?", mc ? mc : "?");
    }

    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        log_red("Gagal membuat socket SOCKS5: %s", strerror(errno));
        write_marker(NEED_RESTART_FILE, "SOCKS5 socket failed");
        goto fail_cleanup;
    }
    int one = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (set_nonblock(listen_fd, 1) < 0 ||
        bind(listen_fd, (struct sockaddr *)&laddr, sizeof(laddr)) < 0 ||
        listen(listen_fd, 128) < 0) {
        log_red("Gagal membuka SOCKS5 di %s:%d (%s)", listen_ip, listen_port, strerror(errno));
        write_marker(NEED_RESTART_FILE, "SOCKS5 bind failed");
        goto fail_cleanup;
    }
    log_blue("SOCKS5 Listening : %s:%d", listen_ip, listen_port);

    epfd = epoll_create1(0);
    if (epfd < 0) {
        log_red("epoll_create1 gagal: %s", strerror(errno));
        write_marker(NEED_RESTART_FILE, "epoll_create1 failed");
        goto fail_cleanup;
    }

    uint32_t upstream_ev = EPOLLIN | EPOLLRDHUP;
    struct epoll_event ev = { .events = EPOLLIN, .data.ptr = &g_listen_tag };
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, listen_fd, &ev) < 0) {
        log_red("epoll_ctl ADD listen_fd gagal: %s", strerror(errno));
        goto fail_cleanup;
    }
    ev.events = upstream_ev;
    ev.data.ptr = &g_upstream_tag;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, upstream_fd, &ev) < 0) {
        log_red("epoll_ctl ADD upstream_fd gagal: %s", strerror(errno));
        goto fail_cleanup;
    }

    if (cfg.keepalive_sec > 0) {
        libssh2_keepalive_config(session, 0, (unsigned int)cfg.keepalive_sec);
    }

    struct epoll_event events[MAX_EVENTS];
    int force_next_tick = 0;
    int idle_rx_paused = 0;
    time_t last_ka_try = 0;
    time_t last_emfile_log = 0;
    exit_code = 0;

    while (!g_stop) {
        int timeout_ms = force_next_tick ? 0 : 1000;
        int nfds = epoll_wait(epfd, events, MAX_EVENTS, timeout_ms);
        if (nfds < 0) {
            if (errno == EINTR) continue;
            exit_code = 1;
            break;
        }

        int upstream_readable = 0;

        for (int i = 0; i < nfds; i++) {
            void *ptr = events[i].data.ptr;
            uint32_t e = events[i].events;

            if (ptr == &g_listen_tag) {
                while (1) {
                    int cfd = accept(listen_fd, NULL, NULL);
                    if (cfd < 0) {
                        if (errno == EINTR) continue;
                        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                        if (errno == EMFILE || errno == ENFILE) {
                            time_t now_err = time(NULL);
                            if (now_err - last_emfile_log >= 5) {
                                log_yellow("Batas FD tercapai (%s), menolak koneksi baru sementara", strerror(errno));
                                last_emfile_log = now_err;
                            }
                            usleep(5000);
                        }
                        break;
                    }
                    if (g_client_count >= cfg.max_clients) {
                        close(cfd);
                        continue;
                    }
                    if (set_nonblock(cfd, 1) < 0) { close(cfd); continue; }
                    int nodelay = 1;
                    setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));

                    client_conn_t *nc = calloc(1, sizeof(client_conn_t));
                    if (!nc) { close(cfd); continue; }
                    nc->fd = cfd;
                    nc->state = ST_SOCKS_GREETING;
                    nc->epoll_events = EPOLLIN | EPOLLRDHUP;
                    nc->accepted_at = time(NULL);
                    nc->last_activity_ms = now_ms();

                    struct epoll_event cev = { .events = nc->epoll_events, .data.ptr = nc };
                    if (epoll_ctl(epfd, EPOLL_CTL_ADD, cfd, &cev) < 0) {
                        close(cfd);
                        free(nc);
                        continue;
                    }
                    nc->in_epoll = 1;
                    nc->next = g_clients;
                    if (g_clients) g_clients->prev = nc;
                    g_clients = nc;
                    g_client_count++;
                }
            } else if (ptr == &g_upstream_tag) {
                if(e&EPOLLERR){
                    int so_err=0;socklen_t so_len=sizeof(so_err);
                    if(getsockopt(upstream_fd,SOL_SOCKET,SO_ERROR,&so_err,&so_len)==0&&so_err){
                        log_red("Kesalahan upstream: %s",strerror(so_err));
                        write_marker(NEED_RESTART_FILE,"upstream socket error");exit_code=1;g_stop=1;break;
                    }
                    upstream_readable=1;
                }
                if(e&(EPOLLIN|EPOLLHUP|EPOLLRDHUP))upstream_readable=1;
            } else {
                client_conn_t *c = (client_conn_t *)ptr;
                handle_client_io(epfd, c, e);
            }
        }

        if (g_stop) break;

        time_t now_sec = time(NULL);
        long long now_msec = now_ms();
        for (client_conn_t *c = g_clients, *nxt = NULL; c; c = nxt) {
            nxt = c->next;
            if (c->close_after_ctrl && c->fd >= 0 && c->ctrl_close_deadline_ms > 0 &&
                now_msec >= c->ctrl_close_deadline_ms) {
                start_closing_client(epfd, c);
                continue;
            }
            if ((c->state == ST_SOCKS_GREETING || c->state == ST_SOCKS_REQUEST) &&
                (now_sec - c->accepted_at) >= SOCKS_HS_TIMEOUT_SEC) {
                start_closing_client(epfd, c);
            } else if (c->state == ST_RELAY && cfg.idle_timeout_sec > 0 &&
                       c->last_activity_ms > 0 &&
                       now_msec-c->last_activity_ms >= (long long)cfg.idle_timeout_sec*1000LL) {
                log_yellow("Menutup relay idle (%s:%u) setelah %d detik",c->target_host,(unsigned)c->target_port,cfg.idle_timeout_sec);
                start_closing_client(epfd,c);
            } else if (c->state == ST_SSH_OPENING && c == g_opening_client && c->open_started_ms > 0) {
                long long elapsed = now_msec - c->open_started_ms;
                if (elapsed >= SSH_OPEN_HARD_TO_MS) {
                    log_red("Pembukaan channel SSH macet >%d detik (%s:%u), memicu restart sesi",
                            SSH_OPEN_HARD_TO_MS / 1000, c->target_host, (unsigned)c->target_port);
                    write_marker(NEED_RESTART_FILE, "channel open hard timeout");
                    exit_code = 1;
                    g_stop = 1;
                    break;
                } else if (elapsed >= SSH_OPEN_SOFT_TO_MS && !c->abort_on_open && !c->close_after_ctrl && c->fd >= 0) {
                    c->abort_on_open = 1;
                    send_socks_err_and_close(epfd, c, 0x04);
                }
            }
        }

        if (g_stop) break;

        int rounds = 0;
        int agg_dirs = 0;
        int did_ssh_read = 0;
        force_next_tick = 0;

        while (!g_stop && rounds < 16) {
            int round_dirs = 0;
            int round_read = 0;
            int pump_rc = pump_ssh_channels(epfd, session, &uctx, &round_dirs, &round_read);
            agg_dirs |= round_dirs;
            did_ssh_read |= round_read;
            if (pump_rc < 0) {
                log_red("Sesi SSH terputus");
                write_marker(NEED_RESTART_FILE, "ssh session lost");
                exit_code = 1;
                g_stop = 1;
                break;
            }
            if (pump_rc == 0) break;
            rounds++;
        }

        if (g_stop) break;

        if (upstream_readable && !did_ssh_read && g_opening_client == NULL && g_pending_op == PENDING_NONE) {
            int pk = check_upstream_eof_peek(&uctx);
            if (pk == -1) {
                log_red("Koneksi upstream ditutup oleh server");
                write_marker(NEED_RESTART_FILE, "upstream eof");
                exit_code = 1;
                g_stop = 1;
                break;
            } else if (pk == 1) {
                idle_rx_paused = 1;
            }
        } else if (did_ssh_read || g_opening_client != NULL || has_readable_relay_channel()) {
            idle_rx_paused = 0;
        }

        if (g_pending_op == PENDING_NONE &&
            cfg.keepalive_sec > 0 &&
            (now_sec - uctx.last_activity) >= cfg.keepalive_sec &&
            (now_sec - last_ka_try) >= 1) {
            int next_sec = 0;
            last_ka_try = now_sec;
            int ka_rc = libssh2_keepalive_send(session, &next_sec);
            if (ka_rc == 0) {
                uctx.last_activity = now_sec;
            } else if (ka_rc == LIBSSH2_ERROR_EAGAIN) {
                int ka_dirs = libssh2_session_block_directions(session);
                agg_dirs |= ka_dirs;
                g_pending_op = PENDING_KEEPALIVE;
                g_pending_client = NULL;
            } else {
                log_red("Keepalive SSH gagal");
                write_marker(NEED_RESTART_FILE, "keepalive failed");
                exit_code = 1;
                g_stop = 1;
                break;
            }
        }

        if (rounds == 16 ||
            (uctx.ssl && SSL_pending(uctx.ssl) > 0 &&
             (g_opening_client != NULL || has_readable_relay_channel()))) {
            force_next_tick = 1;
        }

        uint32_t want_up = EPOLLRDHUP;
        if (uctx.ssl && uctx.ssl_want_events != 0) {
            want_up |= uctx.ssl_want_events;
        } else if (g_pending_op != PENDING_NONE) {
            if (agg_dirs & LIBSSH2_SESSION_BLOCK_OUTBOUND) want_up |= EPOLLOUT;
            if (agg_dirs & LIBSSH2_SESSION_BLOCK_INBOUND)  want_up |= EPOLLIN;
            if ((want_up & (EPOLLIN | EPOLLOUT)) == 0) want_up |= EPOLLOUT;
        } else {
            int need_read =
                !idle_rx_paused ||
                (g_opening_client != NULL) ||
                has_readable_relay_channel() ||
                (agg_dirs & LIBSSH2_SESSION_BLOCK_INBOUND);
            if (need_read) {
                idle_rx_paused = 0;
                want_up |= EPOLLIN;
            }
            if (agg_dirs & LIBSSH2_SESSION_BLOCK_OUTBOUND) {
                want_up |= EPOLLOUT;
            }
        }
        update_epoll(epfd, upstream_fd, &g_upstream_tag, &upstream_ev, want_up);
    }

    while (g_clients) {
        if (g_clients->channel) libssh2_channel_free(g_clients->channel);
        remove_client(epfd, g_clients);
    }
    if (epfd >= 0) close(epfd);
    if (listen_fd >= 0) close(listen_fd);
    if (session) {
        if (exit_code == 0) libssh2_session_disconnect(session, "Normal shutdown");
        libssh2_session_free(session);
        libssh2_exit();
    }
    if (uctx.ssl) {
        if (exit_code == 0) SSL_shutdown(uctx.ssl);
        SSL_free(uctx.ssl);
    }
    if (ssl_ctx) SSL_CTX_free(ssl_ctx);
    close(upstream_fd);
    return exit_code;

fail_cleanup:
    if (raw_payload) free(raw_payload);
    if (epfd >= 0) close(epfd);
    if (listen_fd >= 0) close(listen_fd);
    if (session) {
        libssh2_session_free(session);
        libssh2_exit();
    }
    if (uctx.ssl) SSL_free(uctx.ssl);
    if (ssl_ctx) SSL_CTX_free(ssl_ctx);
    close(upstream_fd);
    return 1;
}
#endif /* SSH_CORE_PARSER_TEST */
