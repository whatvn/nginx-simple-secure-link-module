#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <stddef.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>

#define NGX_DEFAULT_HASH_FUNCTION  "sha256"
#define FAVICON_URL "/favicon.ico"

typedef struct ngx_http_hmac_secure_link_srv_conf_t {
    ngx_http_complex_value_t *secure_link;
    ngx_http_complex_value_t *secure_link_hmac_secret;
    ngx_http_complex_value_t *secure_link_hmac_message;
} ngx_http_hmac_secure_link_srv_conf_t;

typedef struct ngx_http_hmac_secure_link_loc_conf_t {
    ngx_flag_t secure_link_enabled;
} ngx_http_hmac_secure_link_loc_conf_t;



static void *ngx_http_hmac_secure_link_create_loc_conf(ngx_conf_t *cf);
static void *ngx_http_hmac_secure_link_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_hmac_secure_link_merge_srv_conf(ngx_conf_t *cf, void *parent,
        void *child);
static char *ngx_http_hmac_secure_link_merge_loc_conf(ngx_conf_t *cf, void *parent,
        void *child);
static ngx_int_t ngx_http_hmac_secure_link_postconfig(ngx_conf_t *cf);
ngx_int_t ngx_http_hmac_secure_link_handler(ngx_http_request_t *r);


static ngx_command_t ngx_http_hmac_secure_link_commands[] = {


    { ngx_string("secure_link"),
        NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
        ngx_http_set_complex_value_slot,
        NGX_HTTP_SRV_CONF_OFFSET,
        offsetof(ngx_http_hmac_secure_link_srv_conf_t, secure_link),
        NULL},

    { ngx_string("secure_link_enabled"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_hmac_secure_link_loc_conf_t, secure_link_enabled),
        NULL},

    { ngx_string("secure_link_hmac_secret"),
        NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
        ngx_http_set_complex_value_slot,
        NGX_HTTP_SRV_CONF_OFFSET,
        offsetof(ngx_http_hmac_secure_link_srv_conf_t, secure_link_hmac_secret),
        NULL},

    { ngx_string("secure_link_hmac_message"),
        NGX_HTTP_SRV_CONF | NGX_CONF_TAKE1,
        ngx_http_set_complex_value_slot,
        NGX_HTTP_SRV_CONF_OFFSET,
        offsetof(ngx_http_hmac_secure_link_srv_conf_t, secure_link_hmac_message),
        NULL},

    ngx_null_command
};

static void *
ngx_http_hmac_secure_link_create_srv_conf(ngx_conf_t *cf) {
    ngx_http_hmac_secure_link_srv_conf_t *sscf;

    sscf = ngx_pcalloc(cf->pool, sizeof (ngx_http_hmac_secure_link_srv_conf_t));
    if (sscf == NULL)
        return NULL;


    return sscf;
}

static void *
ngx_http_hmac_secure_link_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_hmac_secure_link_loc_conf_t *scf;

    scf = ngx_pcalloc(cf->pool, sizeof (ngx_http_hmac_secure_link_loc_conf_t));
    if (scf == NULL)
        return NULL;

    scf->secure_link_enabled = NGX_CONF_UNSET;

    return scf;
}

static char *
ngx_http_hmac_secure_link_merge_srv_conf(ngx_conf_t *cf, void *parent,
        void *child) {

    ngx_http_hmac_secure_link_srv_conf_t *prev = parent;
    ngx_http_hmac_secure_link_srv_conf_t *conf = child;

    if (conf->secure_link == NULL) {
        conf->secure_link = prev->secure_link;
    }

    if (conf->secure_link_hmac_message == NULL) {
        conf->secure_link_hmac_message = prev->secure_link_hmac_message;
    }

    if (conf->secure_link_hmac_secret == NULL) {
        conf->secure_link_hmac_secret = prev->secure_link_hmac_secret;
    }
    return NGX_CONF_OK;
}

static char *
ngx_http_hmac_secure_link_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_hmac_secure_link_loc_conf_t *prev = parent;
    ngx_http_hmac_secure_link_loc_conf_t *conf = child;
    ngx_conf_merge_value(conf->secure_link_enabled, prev->secure_link_enabled, 0);

    if (conf->secure_link_enabled) {
        OpenSSL_add_all_digests();
    }

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_hmac_secure_link_postconfig(ngx_conf_t *cf) {
    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);

    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_hmac_secure_link_handler;

    return NGX_OK;
}

static ngx_http_module_t ngx_http_hmac_secure_link_ctx = {
    NULL, /* preconfiguration */
    ngx_http_hmac_secure_link_postconfig, /* postconfiguration */

    NULL, /* create main configuration */
    NULL, /* init main configuration */

    ngx_http_hmac_secure_link_create_srv_conf, /* create server configuration */
    ngx_http_hmac_secure_link_merge_srv_conf, /* merge server configuration */

    ngx_http_hmac_secure_link_create_loc_conf, /* create location configuration */
    ngx_http_hmac_secure_link_merge_loc_conf /* merge location configuration */
};


ngx_module_t ngx_http_hmac_secure_link_module = {
    NGX_MODULE_V1,
    &ngx_http_hmac_secure_link_ctx, /* module context */
    ngx_http_hmac_secure_link_commands, /* module directives */
    NGX_HTTP_MODULE, /* module type */
    NULL, /* init master */
    NULL, /* init module */
    NULL, /* init process */
    NULL, /* init thread */
    NULL, /* exit thread */
    NULL, /* exit process */
    NULL, /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_int_t ngx_http_hmac_secure_link_verify(ngx_http_request_t *r,
        ngx_str_t *key, ngx_str_t *hash_msg, ngx_str_t *message) {
    const EVP_MD *evp_md;
    ngx_str_t hash;
    u_char hash_buf[EVP_MAX_MD_SIZE],
            hmac_buf[EVP_MAX_MD_SIZE];
    u_int hmac_len;



    evp_md = EVP_get_digestbyname((const char*) NGX_DEFAULT_HASH_FUNCTION);

    if (evp_md == NULL) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "Unknown cryptographic hash function \"%s\"", NGX_DEFAULT_HASH_FUNCTION);
        return NGX_ERROR;
    }

    hash.len = (u_int) EVP_MD_size(evp_md);
    hash.data = hash_buf;

    if (ngx_decode_base64url(&hash, hash_msg) != NGX_OK) {
        return NGX_ERROR;
    }

    if (hash.len != (u_int) EVP_MD_size(evp_md)) {
        return NGX_ERROR;
    }
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "secure link message: \"%V\"", message);

    HMAC(evp_md, key->data, key->len, message->data,
            message->len, hmac_buf, &hmac_len);

    if (CRYPTO_memcmp(hash_buf, hmac_buf, EVP_MD_size(evp_md)) != 0) {
        return NGX_ERROR;
    }
    return NGX_OK;
}

static char *ngx_strcpy(const char *str) {
    int len = strlen(str) + 1;
    char *buf = malloc(len);
    if (NULL == buf)
        return NULL;
    memcpy(buf, str, len);
    return buf;
}

static ngx_int_t ngx_strsplit(const char *str, char *parts[], const char *delimiter) {
    char *pch;
    ngx_int_t i = 0;
    char *tmp = ngx_strcpy(str);
    pch = strtok(tmp, delimiter);

    parts[i++] = ngx_strcpy(pch);

    while (pch) {
        pch = strtok(NULL, delimiter);
        if (NULL == pch)
            break;
        parts[i++] = ngx_strcpy(pch);
    }

    free(tmp);
    free(pch);
    return i;
}

ngx_int_t
ngx_http_hmac_secure_link_handler(ngx_http_request_t *r) {

    ngx_http_hmac_secure_link_srv_conf_t *ssf;
    ngx_http_hmac_secure_link_loc_conf_t *slf;
    ngx_str_t hmac_message;
    ngx_str_t secure_link;
    ngx_str_t secure_key;
    u_char *last, *p;
    ngx_str_t favicon_url = ngx_string(FAVICON_URL);
    ngx_int_t timestamp = 0, expires = 0;
    char **args;
    ngx_int_t rc;


    slf = ngx_http_get_module_loc_conf(r, ngx_http_hmac_secure_link_module);

    if (r->main->internal || !slf->secure_link_enabled) {
        // if it's not our phase, just return NGX_DECLINED
        return NGX_DECLINED;
    }

    if (ngx_memn2cmp(r->uri.data, favicon_url.data,
            r->uri.len, favicon_url.len) == 0) {
        return NGX_OK;
    }

    ssf = ngx_http_get_module_srv_conf(r, ngx_http_hmac_secure_link_module);
    if (ssf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (slf == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }


    if (ngx_http_complex_value(r, ssf->secure_link_hmac_message,
            &hmac_message) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* secure link is the arg contains hmac hash*/
    if (ngx_http_complex_value(r, ssf->secure_link, &secure_link)
            != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    last = secure_link.data + secure_link.len;
    p = ngx_strlchr(secure_link.data, last, ',');

    /* get timestamp value */
    if (p) {
        secure_link.len = p++ - secure_link.data;
        args = ngx_pcalloc(r->connection->pool, last - p + 1);
        rc = ngx_strsplit((const char*) p, args, ",");
        timestamp = atoi(args[0]);
        if (rc > 0) {
            expires = atoi(args[1]);
        }

        /* secure key is the key use to hash*/
        if (ngx_http_complex_value(r, ssf->secure_link_hmac_secret, &secure_key)
                != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (expires != 0) {
            rc = ngx_http_hmac_secure_link_verify(r, &secure_key,
                &secure_link, &hmac_message) == NGX_OK && timestamp
                + expires > ngx_time() ? NGX_OK : NGX_HTTP_FORBIDDEN;
        } else {
            rc = ngx_http_hmac_secure_link_verify(r, &secure_key,
                &secure_link, &hmac_message) == NGX_OK 
                    ? NGX_OK : NGX_HTTP_FORBIDDEN;
        }
        ngx_pfree(r->connection->pool, args);
        return rc;
    }
    return NGX_HTTP_FORBIDDEN;
}
