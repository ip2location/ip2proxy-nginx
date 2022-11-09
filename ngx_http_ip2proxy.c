/*
 * IP2Proxy Nginx module is distributed under MIT license
 * Copyright (c) 2013-2021 IP2Location.com. support at ip2location dot com
 *
 * This module is free software; you can redistribute it and/or
 * modify it under the terms of the MIT license
 */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <IP2Proxy.h>

typedef struct {
	IP2Proxy			*handler;
	ngx_array_t			*proxies;
	ngx_flag_t			proxy_recursive;
} ngx_http_ip2proxy_conf_t;

typedef struct {
	ngx_str_t	*name;
	uintptr_t	data;
} ngx_http_ip2proxy_var_t;

static ngx_int_t ngx_http_ip2proxy_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_ip2proxy_get_str_value(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static IP2ProxyRecord *ngx_http_ip2proxy_get_records(ngx_http_request_t *r);
static void *ngx_http_ip2proxy_create_conf(ngx_conf_t *cf);
static char *ngx_http_ip2proxy_init_conf(ngx_conf_t *cf, void *conf);
static char *ngx_http_ip2proxy_database(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_ip2proxy_proxy(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_ip2proxy_cidr_value(ngx_conf_t *cf, ngx_str_t *net, ngx_cidr_t *cidr);
static void ngx_http_ip2proxy_cleanup(void *data);
static IP2Proxy *ip2proxy_bin_handler;

static ngx_command_t ngx_http_ip2proxy_commands[] = {
	{
		ngx_string("ip2proxy_database"),
		NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE12,
		ngx_http_ip2proxy_database,
		NGX_HTTP_MAIN_CONF_OFFSET,
		0,
		NULL
	},
	{
		ngx_string("ip2proxy_proxy"),
		NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
		ngx_http_ip2proxy_proxy,
		NGX_HTTP_MAIN_CONF_OFFSET,
		0,
		NULL
	},
	{
		ngx_string("ip2proxy_proxy_recursive"),
		NGX_HTTP_MAIN_CONF|NGX_CONF_FLAG,
		ngx_conf_set_flag_slot,
		NGX_HTTP_MAIN_CONF_OFFSET,
		offsetof(ngx_http_ip2proxy_conf_t, proxy_recursive),
		NULL
	},
	ngx_null_command
};


static ngx_http_module_t ngx_http_ip2proxy_module_ctx = {
	ngx_http_ip2proxy_add_variables,	/* preconfiguration */
	NULL,								/* postconfiguration */
	ngx_http_ip2proxy_create_conf,		/* create main configuration */
	ngx_http_ip2proxy_init_conf,		/* init main configuration */
	NULL,								/* create server configuration */
	NULL,								/* merge server configuration */
	NULL,								/* create location configuration */
	NULL								/* merge location configuration */
};


ngx_module_t ngx_http_ip2proxy_module = {
	NGX_MODULE_V1,
	&ngx_http_ip2proxy_module_ctx,	/* module context */
	ngx_http_ip2proxy_commands,		/* module directives */
	NGX_HTTP_MODULE,				/* module type */
	NULL,							/* init master */
	NULL,							/* init module */
	NULL,							/* init process */
	NULL,							/* init thread */
	NULL,							/* exit thread */
	NULL,							/* exit process */
	NULL,							/* exit master */
	NGX_MODULE_V1_PADDING
};

static ngx_http_variable_t
ngx_http_ip2proxy_vars[] = {
	{
		ngx_string("ip2proxy_country_short"), NULL,
		ngx_http_ip2proxy_get_str_value,
		offsetof(IP2ProxyRecord, country_short),
		0, 0
	},
	{
		ngx_string("ip2proxy_country_long"), NULL,
		ngx_http_ip2proxy_get_str_value,
		offsetof(IP2ProxyRecord, country_long),
		0, 0
	},
	{
		ngx_string("ip2proxy_region"), NULL,
		ngx_http_ip2proxy_get_str_value,
		offsetof(IP2ProxyRecord, region),
		0, 0
	},
	{
		ngx_string("ip2proxy_city"), NULL,
		ngx_http_ip2proxy_get_str_value,
		offsetof(IP2ProxyRecord, city),
		0, 0
	},
	{
		ngx_string("ip2proxy_isp"), NULL,
		ngx_http_ip2proxy_get_str_value,
		offsetof(IP2ProxyRecord, isp),
		0, 0
	},
	{
		ngx_string("ip2proxy_is_proxy"), NULL,
		ngx_http_ip2proxy_get_str_value,
		offsetof(IP2ProxyRecord, is_proxy),
		0, 0
	},
	{
		ngx_string("ip2proxy_proxy_type"), NULL,
		ngx_http_ip2proxy_get_str_value,
		offsetof(IP2ProxyRecord, proxy_type),
		0, 0
	},
	{
		ngx_string("ip2proxy_domain"), NULL,
		ngx_http_ip2proxy_get_str_value,
		offsetof(IP2ProxyRecord, domain),
		0, 0
	},
	{
		ngx_string("ip2proxy_usage_type"), NULL,
		ngx_http_ip2proxy_get_str_value,
		offsetof(IP2ProxyRecord, usage_type),
		0, 0
	},
	{
		ngx_string("ip2proxy_asn"), NULL,
		ngx_http_ip2proxy_get_str_value,
		offsetof(IP2ProxyRecord, asn),
		0, 0
	},
	{
		ngx_string("ip2proxy_as"), NULL,
		ngx_http_ip2proxy_get_str_value,
		offsetof(IP2ProxyRecord, as_),
		0, 0
	},
	{
		ngx_string("ip2proxy_last_seen"), NULL,
		ngx_http_ip2proxy_get_str_value,
		offsetof(IP2ProxyRecord, last_seen),
		0, 0
	},
	{
		ngx_string("ip2proxy_threat"), NULL,
		ngx_http_ip2proxy_get_str_value,
		offsetof(IP2ProxyRecord, threat),
		0, 0
	},
	{
		ngx_string("ip2proxy_provider"), NULL,
		ngx_http_ip2proxy_get_str_value,
		offsetof(IP2ProxyRecord, provider),
		0, 0
	},

	ngx_http_null_variable
};

static ngx_int_t
ngx_http_ip2proxy_get_str_value(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
	char			*val;
	size_t			len;
	IP2ProxyRecord	*record;

	record = ngx_http_ip2proxy_get_records(r);

	if (record == NULL) {
		goto not_found;
	}

	val = *(char **) ((char *) record + data);
	
	if (val == NULL) {
		goto no_value;
	}

	len = ngx_strlen(val);
	v->data = ngx_pnalloc(r->pool, len);
	
	if (v->data == NULL) {
		IP2Proxy_free_record(record);
		return NGX_ERROR;
	}

	ngx_memcpy(v->data, val, len);

	v->len = len;
	v->valid = 1;
	v->no_cacheable = 0;
	v->not_found = 0;

	IP2Proxy_free_record(record);

	return NGX_OK;

no_value:

	IP2Proxy_free_record(record);

not_found:

	v->not_found = 1;

	return NGX_OK;
}

static IP2ProxyRecord *
ngx_http_ip2proxy_get_records(ngx_http_request_t *r)
{
	ngx_http_ip2proxy_conf_t	*gcf;

	gcf = ngx_http_get_module_main_conf(r, ngx_http_ip2proxy_module);

	if (gcf->handler) {
		ngx_addr_t	addr;
		
	#if defined(nginx_version) && nginx_version >= 1023000
		ngx_table_elt_t         *xfwd;
	#else
	        ngx_array_t             *xfwd;
	#endif
		u_char		p[NGX_INET6_ADDRSTRLEN + 1];
		size_t		size;

		addr.sockaddr = r->connection->sockaddr;
		addr.socklen = r->connection->socklen;

	#if defined(nginx_version) && nginx_version >= 1023000
    		xfwd = r->headers_in.x_forwarded_for;

    		if (xfwd != NULL && gcf->proxies != NULL) {
	#else
    		xfwd = &r->headers_in.x_forwarded_for;

    		if (xfwd->nelts > 0 && gcf->proxies != NULL) {
	#endif		
			(void) ngx_http_get_forwarded_addr(r, &addr, xfwd, NULL, gcf->proxies, gcf->proxy_recursive);
		}

#if defined(nginx_version) && (nginx_version) >= 1005003
	size = ngx_sock_ntop(addr.sockaddr, addr.socklen, p, NGX_INET6_ADDRSTRLEN, 0);
#else
	size = ngx_sock_ntop(addr.sockaddr, p, NGX_INET6_ADDRSTRLEN, 0);
#endif

		p[size] = '\0';

		ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "IP address detected by IP2Proxy: %s", p);

		return IP2Proxy_get_all(gcf->handler, (char *)p);
	}
	
	return NULL;
}


static ngx_int_t
ngx_http_ip2proxy_add_variables(ngx_conf_t *cf)
{
	ngx_http_variable_t	*var, *v;

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


static void *
ngx_http_ip2proxy_create_conf(ngx_conf_t *cf)
{
	ngx_pool_cleanup_t			*cln;
	ngx_http_ip2proxy_conf_t	*conf;

	conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ip2proxy_conf_t));
	
	if (conf == NULL) {
		return NULL;
	}

	conf->proxy_recursive = NGX_CONF_UNSET;

	cln = ngx_pool_cleanup_add(cf->pool, 0);
	
	if (cln == NULL) {
		return NULL;
	}

	cln->handler = ngx_http_ip2proxy_cleanup;
	cln->data = conf;

	return conf;
}


static char *
ngx_http_ip2proxy_init_conf(ngx_conf_t *cf, void *conf)
{
	ngx_http_ip2proxy_conf_t	*gcf = conf;

	ngx_conf_init_value(gcf->proxy_recursive, 0);

	return NGX_CONF_OK;
}


static char *
ngx_http_ip2proxy_database(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_ip2proxy_conf_t	*gcf = conf;
	ngx_str_t					*value;

	if (gcf->handler) {
		return "Duplicated";
	}

	if (ip2proxy_bin_handler){
		//close the bin if it's still opened
		IP2Proxy_close(ip2proxy_bin_handler);
		ip2proxy_bin_handler = NULL;
	}

	value = cf->args->elts;

	if (value[1].len == 0) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "No IP2Proxy database specified.");
		return NGX_CONF_ERROR;
	}

	// Open IP2Proxy BIN database
	gcf->handler = IP2Proxy_open((char *) value[1].data);
	ip2proxy_bin_handler = gcf->handler;

	if (gcf->handler == NULL) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "Unable to open database file \"%s\".", &value[1].data);
		return NGX_CONF_ERROR;
	}

	IP2Proxy_open_mem(gcf->handler, IP2PROXY_CACHE_MEMORY);

	return NGX_CONF_OK;
}

static char *
ngx_http_ip2proxy_proxy(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_http_ip2proxy_conf_t	*gcf = conf;
	ngx_str_t					*value;
	ngx_cidr_t					cidr, *c;

	value = cf->args->elts;

	if (ngx_http_ip2proxy_cidr_value(cf, &value[1], &cidr) != NGX_OK) {
		return NGX_CONF_ERROR;
	}

	if (gcf->proxies == NULL) {
		gcf->proxies = ngx_array_create(cf->pool, 4, sizeof(ngx_cidr_t));
		if (gcf->proxies == NULL) {
			return NGX_CONF_ERROR;
		}
	}

	c = ngx_array_push(gcf->proxies);
	if (c == NULL) {
		return NGX_CONF_ERROR;
	}

	*c = cidr;

	return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_ip2proxy_cidr_value(ngx_conf_t *cf, ngx_str_t *net, ngx_cidr_t *cidr)
{
	ngx_int_t	rc;

	if (ngx_strcmp(net->data, "255.255.255.255") == 0) {
		cidr->family = AF_INET;
		cidr->u.in.addr = 0xffffffff;
		cidr->u.in.mask = 0xffffffff;

		return NGX_OK;
	}

	rc = ngx_ptocidr(net, cidr);

	if (rc == NGX_ERROR) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "Invalid network \"%V\"", net);
		return NGX_ERROR;
	}

	if (rc == NGX_DONE) {
		ngx_conf_log_error(NGX_LOG_WARN, cf, 0, "Low address bits of %V are meaningless", net);
	}

	return NGX_OK;
}


static void
ngx_http_ip2proxy_cleanup(void *data)
{
	//ngx_http_ip2proxy_conf_t	*gcf = data;

	// if (gcf->handler) {
	// 	IP2Proxy_close(gcf->handler);
	// 	gcf->handler = NULL;
	// }
}
