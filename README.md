# IP2Proxy HTTP Module for Nginx

The module detects visitor IP addresses which are used as VPN anonymizer, open proxies, web proxies and Tor exits.

A IP2Proxy database is required for the lookup. It can be downloaded from https://lite.ip2location.com (Free) or https://www.ip2location.com (Commercial).



### Installation

1. Install required packages for development.

   ```
   apt-get install -y wget git build-essential zlib1g-dev libpcre3 libpcre3-dev libtool autoconf automake
   ```

   

2. Create a working directory.

   ```
   mkdir ~/ip2proxy-dev
   cd ~/ip2proxy-dev
   ```

   

3. Download IP2Proxy C library source code.

   ```
   git clone https://github.com/ip2location/ip2proxy-c.git
   ```

   

4. Compile and install the IP2Proxy C library.

   ```
   cd ip2proxy-c
   autoreconf -i -v --force
   ./configure
   make
   make install
   ```

   

5. Refresh local library.

   ```
   ldconfig
   ```

   

6. Download IP2Proxy Nginx.

   ```
   cd ~/ip2proxy-dev
   git clone https://github.com/ip2location/ip2proxy-nginx
   ```

   

7. Download the latest Nginx source.

   ```
   wget http://nginx.org/download/nginx-VERSION.tar.gz
   ```

   **Notes:** Please check the `VERSION` number from http://nginx.org/en/download.html

   

8. Compile and install Nginx with IP2Proxy module.

   ```
   tar -xvzf nginx-VERSION.tar.gz 
   cd nginx-VERSION
   ./configure --sbin-path=/usr/sbin/nginx --conf-path=/etc/nginx/nginx.conf --pid-path=/run/nginx.pid --add-module=~/ip2proxy-dev/ip2proxy-nginx
   make
   make install
   ```



### Configuration

```
Syntax      : ip2proxy
Value       : on | off
Default     : off
Context     : http, server, location
Description : Enable of disable IP2Proxy module.
```

```
Syntax      : ip2proxy_database
Value       : [Absolute path to IP2Proxy database]
Default     : none
Context     : http, server, location
Description : The absolute path to IP2Proxy BIN database file.
```

```
Syntax      : ip2proxy_access_type
Value       : file_io | shared_memory | cache_memory
Default     : file_io
Context     : http, server, location
Description : Define the lookup mode for best performance practice.
```

```
Syntax      : ip2proxy_reverse_proxy
Value       : on | off
Default     : off
Context     : http, server, location
Description : Detect X-Forwareded-For header for actual visitor IP if Nginx is behind a reverse proxy.
```



### Example of nginx.conf

```
http {
        ...

        ip2proxy on;
        ip2proxy_database /ip2proxy/databases/DB4.BIN;
        ip2proxy_access_type shared_memory;
        ip2proxy_reverse_proxy on;
        
        # Add custom headers so the values are accessible from PHP
        add_header IP2Proxy-Country-Code $ip2proxy_country_short;
        add_header IP2Proxy-Country-Name $ip2proxy_country_long;
        add_header IP2Proxy-Region $ip2proxy_region;
        add_header IP2Proxy-City $ip2proxy_city;
        add_header IP2Proxy-ISP $ip2proxy_isp;
        add_header IP2Proxy-Is-Proxy $ip2proxy_is_proxy;
        add_header IP2Proxy-Proxy-Type $ip2proxy_proxy_type;
        add_header IP2Proxy-Domain $ip2proxy_domain;
        add_header IP2Proxy-Usage-Type $ip2proxy_usage_type;
        add_header IP2Proxy-ASN $ip2proxy_proxy_asn;
        add_header IP2Proxy-AS $ip2proxy_proxy_as;
        add_header IP2Proxy-Last-Seen $ip2proxy_last_seen;

        ...
}

```

