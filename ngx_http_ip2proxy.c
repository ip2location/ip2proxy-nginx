#include <nginx.h>
#include <ngx_http.h>

#include "IP2Proxy.h"

typedef struct {
	IP2ProxyRecord	*record;
	u_char			not_found;
	u_char			error;
} ngx_http_ip2proxy_ctx_t;

typedef struct {
	ngx_flag_t	enabled;
} ngx_http_ip2proxy_loc_conf_t;

typedef struct {
	ngx_int_t		access_type;
	ngx_str_t		access_type_name;
	ngx_str_t		file_name;
	ngx_flag_t		enabled;
	u_char			*enable_file;
	ngx_uint_t		enable_line;
	u_char			*database_file;
	ngx_uint_t		database_line;
	IP2Proxy		*database;
	ngx_flag_t		reverse_proxy;
} ngx_http_ip2proxy_conf_t;

static void *
	ngx_http_ip2proxy_create_main_conf(ngx_conf_t *cf);

static char *
	ngx_http_ip2proxy_init_main_conf(ngx_conf_t *cf, void *conf);

static void *
	ngx_http_ip2proxy_create_loc_conf(ngx_conf_t *cf);

static char *
	ngx_http_ip2proxy_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_int_t
	ngx_http_ip2proxy_add_variables(ngx_conf_t *cf);

static ngx_int_t
	ngx_http_ip2proxy_get_str_value(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);

static char *
	ngx_http_ip2proxy_database(ngx_conf_t *cf, void *data, void *conf);

static char *
	ngx_http_ip2proxy_access_type(ngx_conf_t *cf, void *data, void *conf);

static char *
	ngx_http_ip2proxy_enable(ngx_conf_t *cf, void *data, void *conf);

static ngx_conf_post_t
	ngx_http_ip2proxy_post_database = {ngx_http_ip2proxy_database};

static ngx_conf_post_t
	ngx_http_ip2proxy_post_enable = {ngx_http_ip2proxy_enable};

static ngx_conf_post_t
	ngx_http_ip2proxy_post_access_type = {ngx_http_ip2proxy_access_type};

static ngx_command_t
	ngx_http_ip2proxy_commands[] = {
		{
			ngx_string("ip2proxy"),
			NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
			ngx_conf_set_flag_slot,
			NGX_HTTP_LOC_CONF_OFFSET,
			offsetof(ngx_http_ip2proxy_loc_conf_t, enabled),
			&ngx_http_ip2proxy_post_enable
		}, {
			ngx_string("ip2proxy_database"),
			NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
			ngx_conf_set_str_slot,
			NGX_HTTP_MAIN_CONF_OFFSET,
			offsetof(ngx_http_ip2proxy_conf_t, file_name),
			&ngx_http_ip2proxy_post_database
		},  {
			ngx_string("ip2proxy_access_type"),
			NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
			ngx_conf_set_str_slot,
			NGX_HTTP_MAIN_CONF_OFFSET,
			offsetof(ngx_http_ip2proxy_conf_t, access_type_name),
			&ngx_http_ip2proxy_post_access_type
		}, {
			ngx_string("ip2proxy_reverse_proxy"),
			NGX_HTTP_MAIN_CONF|NGX_CONF_FLAG,
			ngx_conf_set_flag_slot,
			NGX_HTTP_MAIN_CONF_OFFSET,
			offsetof(ngx_http_ip2proxy_conf_t, reverse_proxy),
			NULL
		},
		ngx_null_command
	};
	
static ngx_http_module_t
	ngx_http_ip2proxy_module_ctx = {
		ngx_http_ip2proxy_add_variables,
		NULL,
		ngx_http_ip2proxy_create_main_conf,
		ngx_http_ip2proxy_init_main_conf,
		NULL,
		NULL,
		ngx_http_ip2proxy_create_loc_conf,
		ngx_http_ip2proxy_merge_loc_conf
	};

ngx_module_t
	ngx_http_ip2proxy_module = {
		NGX_MODULE_V1,
		&ngx_http_ip2proxy_module_ctx,
		ngx_http_ip2proxy_commands,
		NGX_HTTP_MODULE,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NGX_MODULE_V1_PADDING
	};
	
static ngx_http_variable_t
	ngx_http_ip2proxy_vars[] = {
		{
			ngx_string("ip2proxy_country_short"),
			NULL,
			ngx_http_ip2proxy_get_str_value,
			offsetof(IP2ProxyRecord, country_short),
			0,
			0
		}, {
			ngx_string("ip2proxy_country_long"),
			NULL,
			ngx_http_ip2proxy_get_str_value,
			offsetof(IP2ProxyRecord, country_long),
			0,
			0
		}, {
			ngx_string("ip2proxy_region"),
			NULL,
			ngx_http_ip2proxy_get_str_value,
			offsetof(IP2ProxyRecord, region),
			0, 0
		}, {
			ngx_string("ip2proxy_city"),
			NULL,
			ngx_http_ip2proxy_get_str_value,
			offsetof(IP2ProxyRecord, city),
			0,
			0
		}, {
			ngx_string("ip2proxy_isp"),
			NULL,
			ngx_http_ip2proxy_get_str_value,
			offsetof(IP2ProxyRecord, isp),
			0,
			0
		}, {
			ngx_string("ip2proxy_is_proxy"),
			NULL,
			ngx_http_ip2proxy_get_str_value,
			offsetof(IP2ProxyRecord, is_proxy),
			0,
			0
		}, {
			ngx_string("ip2proxy_proxy_type"),
			NULL,
			ngx_http_ip2proxy_get_str_value,
			offsetof(IP2ProxyRecord, proxy_type),
			0,
			0
		}, {
			ngx_string("ip2proxy_domain),
			NULL,
			ngx_http_ip2proxy_get_str_value,
			offsetof(IP2ProxyRecord, domain),
			0,
			0
		}, {
			ngx_string("ip2proxy_usage_type"),
			NULL,
			ngx_http_ip2proxy_get_str_value,
			offsetof(IP2ProxyRecord, usage_type),
			0,
			0
		}, {
			ngx_string("ip2proxy_asn"),
			NULL,
			ngx_http_ip2proxy_get_str_value,
			offsetof(IP2ProxyRecord, asn),
			0,
			0
		}, {
			ngx_string("ip2proxy_as"),
			NULL,
			ngx_http_ip2proxy_get_str_value,
			offsetof(IP2ProxyRecord, as_),
			0,
			0
		}, {
			ngx_string("ip2proxy_last_seen"),
			NULL,
			ngx_http_ip2proxy_get_str_value,
			offsetof(IP2ProxyRecord, last_seen),
			0,
			0
		}, {
			ngx_null_string,
			NULL,
			NULL,
			0,
			0,
			0
		}
	};

static void *
	ngx_http_ip2proxy_create_main_conf(ngx_conf_t *cf) {
		ngx_http_ip2proxy_conf_t  *cfg;
		
		cfg = ngx_pcalloc(cf->pool, sizeof(ngx_http_ip2proxy_conf_t));
		
		if (cfg == NULL) {
			return NULL;
		}
		
		cfg->access_type = NGX_CONF_UNSET;
		cfg->reverse_proxy = NGX_CONF_UNSET;
		
		return cfg;
	}

void ngx_http_ip2proxy_cleanup(void *data) {
	IP2Proxy *loc = data;
	IP2Proxy_close(loc);
	IP2Proxy_DB_del_shm();
}

static char *
	ngx_http_ip2proxy_init_main_conf(ngx_conf_t *cf, void *data) {
		ngx_http_ip2proxy_conf_t *cfg = data;
		ngx_pool_cleanup_t *cln;

		if (cfg->access_type == NGX_CONF_UNSET) {
			cfg->access_type = IP2PROXY_SHARED_MEMORY;
		}

		if (cfg->enabled) {
			if (cfg->file_name.len == 0) {
				ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "No IP2Proxy database specified in %s:%ui", cfg->enable_file, cfg->enable_line);

				return NGX_CONF_ERROR;
			}

			cfg->database = IP2Proxy_open((char *)cfg->file_name.data);

			if (cfg->database == NULL) {
				ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "Unable to open database file \"%V\" in %s:%ui", &cfg->file_name, cfg->database_file, cfg->database_line);

				return NGX_CONF_ERROR;
			}

			if (IP2Proxy_open_mem(cfg->database, cfg->access_type) == -1) {
				IP2Proxy_close(cfg->database);
				ngx_log_error(NGX_LOG_EMERG, cf->log, 0, "Unable to load %V using \"%V\" access type in %s:%ui", &cfg->file_name, &cfg->access_type_name, cfg->database_file, cfg->database_line);

				return NGX_CONF_ERROR;
			}

			cln = ngx_pool_cleanup_add(cf->pool, 0);
			if (cln == NULL) {
				return NGX_CONF_ERROR;
			}
			
			cln->data = cfg->database;
			cln->handler = ngx_http_ip2proxy_cleanup;
		}
		return NGX_CONF_OK;
	}

static void *
	ngx_http_ip2proxy_create_loc_conf(ngx_conf_t *cf) {
		ngx_http_ip2proxy_loc_conf_t *conf;

		conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ip2proxy_loc_conf_t));

		if (conf == NULL) {
			return NULL;
		}
		
		conf->enabled = NGX_CONF_UNSET;
		return conf;
	}

static char *
	ngx_http_ip2proxy_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
		ngx_http_ip2proxy_loc_conf_t *prev = parent;
		ngx_http_ip2proxy_loc_conf_t *conf = child;
		
		ngx_conf_merge_value(conf->enabled, prev->enabled, 0);
		
		return NGX_CONF_OK;
	}

static char *
	ngx_http_ip2proxy_access_type(ngx_conf_t *cf, void *data, void *conf) {
		ngx_http_ip2proxy_conf_t *cfg;
		ngx_str_t value;

		cfg = ngx_http_conf_get_module_main_conf(cf, ngx_http_ip2proxy_module);

		value = *((ngx_str_t *)conf);

		if (ngx_strcasecmp((u_char *)"file_io", value.data) == 0) {
			cfg->access_type = IP2PROXY_FILE_IO;

		} else if (ngx_strcasecmp((u_char *)"cache_memory", value.data) == 0) {
			cfg->access_type = IP2PROXY_CACHE_MEMORY;

		} else if (ngx_strcasecmp((u_char *)"shared_memory", value.data) == 0) {
			cfg->access_type = IP2PROXY_SHARED_MEMORY;

		} else {
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "Unknown access type \"%V\"", &value);

			return NGX_CONF_ERROR;
		}

		return NGX_CONF_OK;
	}

static char * 
	ngx_http_ip2proxy_enable (ngx_conf_t *cf, void *data, void *conf) {
		ngx_flag_t enabled = *((ngx_flag_t *)conf);
		ngx_http_ip2proxy_conf_t *cfg;

		if (enabled) {
			cfg = ngx_http_conf_get_module_main_conf(cf, ngx_http_ip2proxy_module);
			cfg->enabled = 1;
			cfg->enable_file = cf->conf_file->file.name.data;
			cfg->enable_line = cf->conf_file->line;
		}

		return NGX_CONF_OK;
	}

static char *
	ngx_http_ip2proxy_database(ngx_conf_t *cf, void *data, void *conf) {
		ngx_http_ip2proxy_conf_t  *cfg;

		cfg = ngx_http_conf_get_module_main_conf(cf, ngx_http_ip2proxy_module);

		cfg->database_file = cf->conf_file->file.name.data;
		cfg->database_line = cf->conf_file->line;

		return NGX_CONF_OK;
	}

static ngx_http_ip2proxy_ctx_t *
	ngx_http_ip2proxy_create_ctx(ngx_http_request_t *r) {
		ngx_http_ip2proxy_ctx_t *ctx;
		ngx_pool_cleanup_t *cln;
		ngx_http_ip2proxy_conf_t *cfg;
		ngx_array_t *xfwd;
		u_char ip_addr[NGX_INET6_ADDRSTRLEN + 1];

		ctx = ngx_http_get_module_ctx(r, ngx_http_ip2proxy_module);

		if (ctx) {
			return ctx;
		}

		ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_ip2proxy_ctx_t));

		if (ctx == NULL) {
			return NULL;
		}

		ngx_http_set_ctx(r, ctx, ngx_http_ip2proxy_module);

		cfg = ngx_http_get_module_main_conf(r, ngx_http_ip2proxy_module);

		xfwd = &r->headers_in.x_forwarded_for;

		if (xfwd->nelts > 0 && cfg->reverse_proxy) {
			ngx_table_elt_t **p = xfwd->elts;
			ngx_str_t addr = p[0]->value;
			(void) ngx_copy((void *)ip_addr, addr.data, addr.len);
			ip_addr[addr.len] = '\0';
		} else {
			ngx_str_t addr = r->connection->addr_text;
			(void) ngx_copy((void *)ip_addr, addr.data, addr.len);
			ip_addr[addr.len] = '\0';
		}

		ctx->record = IP2Proxy_get_all(cfg->database, (char *)ip_addr);

		if (ctx->record == NULL) {
			ctx->not_found = 1;

			return ctx;
		}

		cln = ngx_pool_cleanup_add(r->pool, 0);
		if (cln == NULL) {
			ngx_http_set_ctx(r, NULL, ngx_http_ip2proxy_module);
			IP2Proxy_free_record(ctx->record);

			return NULL;
		}

		cln->data = ctx->record;
		cln->handler = (ngx_pool_cleanup_pt) IP2Proxy_free_record;

		return ctx;
	}


static ngx_int_t 
	ngx_http_ip2proxy_get_str_value(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
		ngx_http_ip2proxy_ctx_t *ctx;
		ngx_http_ip2proxy_loc_conf_t *ilcf;

		v->valid = 1;
		v->no_cacheable = 0;
		v->not_found = 0;

		ilcf = ngx_http_get_module_loc_conf(r, ngx_http_ip2proxy_module);
		if (!ilcf->enabled) {
			v->not_found = 1;
			return NGX_OK;
		}

		ctx = ngx_http_ip2proxy_create_ctx(r);

		if (ctx == NULL) {
			return NGX_ERROR;
		}

		if (ctx->not_found) {
			v->not_found = 1;
			return NGX_OK;
		}

		v->data = *(u_char **) ((char *) ctx->record + data);

		if (ngx_strcmp(v->data, NOT_SUPPORTED) == 0 || ngx_strcmp(v->data, INVALID_IPV4_ADDRESS) == 0) {
			v->not_found = 1;
			return NGX_OK;
		}

		v->len = ngx_strlen(v->data);

		return NGX_OK;
	}

static ngx_int_t
	ngx_http_ip2proxy_add_variables(ngx_conf_t *cf) {
		ngx_http_variable_t  *var, *v;

		for (v = ngx_http_ip2proxy_vars; v->name.len; v++) {
			var = ngx_http_add_variable(cf, &v->name, v->flags);
			if (var == NULL) {
				return NGX_ERROR;
			}

			var->get_handler = v->get_handler;
			var->data = v->data;
		}

		return NGX_OK;
	}