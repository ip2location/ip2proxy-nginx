# Nginx IP2Proxy module



### Description

The Nginx IP2Proxy module enables user to detect visitor IP addresses which are used as VPN servers, open proxies, web proxies, Tor exit nodes, search engine robots, data center ranges, residential proxies, consumer privacy networks, and enterprise private networks.

The IP2Proxy database can be downloaded from [https://lite.ip2location.com](https://lite.ip2location.com/ip2proxy-lite) (Free) or [https://www.ip2location.com](https://www.ip2location.com/database/ip2proxy) (Commercial).



### Installation

1. Download IP2Proxy C library from https://github.com/ip2location/ip2proxy-c.

2. Compile and install IP2Proxy C library.

3. Download IP2Proxy module and decompress the package.

   ```bash
   wget https://github.com/ip2location/ip2proxy-nginx/archive/master.zip
   unzip master.zip
   rm master.zip
   ```

   

4. Download the latest Nginx source code from https://nginx.org/en/download.html

   ```bash
   wget https://nginx.org/download/nginx-x.y.z.tar.gz
   ```

   

5. Decompress and go into Nginx source directory.

   ```bash
   tar xvfz nginx-x.y.z.tar.gz
   cd nginx-x.y.z
   ```

   

6. Re-compile Nginx from source to include this module.

   **Static Module**

   ```bash
   ./configure --add-module=/absolute/path/to/nginx-ip2proxy-master
   make
   make install
   ```

   **Dynamic Module**

   ```bash
   ./configure --add-dynamic-module=/absolute/path/to/nginx-ip2proxy-master
   make
   make install
   ```



### Nginx Configuration

Insert the configuration below to your `nginx.conf`.

```
Syntax      : load_module modules/ngx_http_ip2proxy_module.so;
Default     : -
Context     : main
Description : Load IP2Proxy Nginx module if it was compiled as dynamic.
```

```
Syntax      : ip2proxy_database path
Default     : none
Context     : http
Description : The absolute path to IP2Proxy BIN database.
```

```
Syntax      : ip2proxy_proxy_recursive on|off
Default     : off
Context     : http
Description : Enable recursive search in the x-forwarded-for headers.
```

```
Syntax      : ip2proxy_proxy cidr|address
Default     : none
Context     : http
Description : Set a list of proxies to translate x-forwarded-for headers for.
```



**Example:**

```nginx
http {
	...
	
	ip2proxy_database			/usr/share/ip2location/PX3.BIN;
	ip2proxy_proxy_recursive	on;
	ip2proxy_proxy				192.168.1.0/24;
}
```



### Variables

The following variables will be made available in Nginx:

```nginx
$ip2proxy_country_short;
$ip2proxy_country_long;
$ip2proxy_region;
$ip2proxy_city;
$ip2proxy_isp;
$ip2proxy_is_proxy;
$ip2proxy_proxy_type;
$ip2proxy_domain;
$ip2proxy_usage_type;
$ip2proxy_proxy_asn;
$ip2proxy_proxy_as;
$ip2proxy_last_seen;
$ip2proxy_threat;
$ip2proxy_provider;
```



### Usage Example

##### Add Server Variables

```nginx
server {
	listen 80 default_server;
	root /var/www;
	index index.html index.php;

	access_log /var/log/nginx/access.log;
	error_log /var/log/nginx/error.log;

	server_name _;

	location / {
		try_files $uri $uri/ =404;
	}

	location ~ \.php$ {
		fastcgi_pass php-fpm-sock;
		fastcgi_index index.php;
		include fastcgi.conf;
        
		# Add custom header to view result in HTTP response
		add_header X-Country-Code $ip2proxy_country_short;
		add_header X-Country-Name $ip2proxy_country_long;

		fastcgi_param IP2PROXY_COUNTRY_SHORT	$ip2proxy_country_short;
		fastcgi_param IP2PROXY_COUNTRY_LONG	$ip2proxy_country_long;
		fastcgi_param IP2PROXY_REGION		$ip2proxy_region;
		fastcgi_param IP2PROXY_CITY		$ip2proxy_city;
		fastcgi_param IP2PROXY_ISP		$ip2proxy_isp;
		fastcgi_param IP2PROXY_IS_PROXY		$ip2proxy_is_proxy;
		fastcgi_param IP2PROXY_PROXY_TYPE	$ip2proxy_proxy_type;
		fastcgi_param IP2PROXY_DOMAIN		$ip2proxy_domain;
		fastcgi_param IP2PROXY_USAGE_TYPE	$ip2proxy_usage_type;
		fastcgi_param IP2PROXY_PROXY_ASN	$ip2proxy_proxy_asn;
		fastcgi_param IP2PROXY_PROXY_AS		$ip2proxy_proxy_as;
		fastcgi_param IP2PROXY_LAST_SEEN	$ip2proxy_last_seen;
		fastcgi_param IP2PROXY_THREAT		$ip2proxy_threat;
		fastcgi_param IP2PROXY_PROVIDER		$ip2proxy_provider;
	}
}
```

**Notes:** Restart Nginx and view your server response header to confirm the variables are added.



##### Block Proxy IP

```nginx
if ( $ip2proxy_is_proxy = '1' ) {
    return 444;
}
```



##### Block Spammers

```nginx
if ( $ip2proxy_threat = 'SPAM' ) {
    return 444;
}
```



### IPv4 BIN vs IPv6 BIN

Use the IPv4 BIN file if you just need to query IPv4 addresses.

If you query an IPv6 address using the IPv4 BIN, you'll see the INVALID_IP_ADDRESS error.

Use the IPv6 BIN file if you need to query BOTH IPv4 and IPv6 addresses.



### Support
Please visit us at https://www.ip2location.com for services and databases we offer.

For support, please email us at support@ip2location.com
