# CoPSeC TLS Decryption Mirroring & Reverse-Proxy Ingress Architecture

## 1. Architectural Overview

In high-throughput enterprise and banking topologies, external TLS encryption is terminated at an edge reverse-proxy or API gateway before being routed to microservice backends. Traditional hardware-accelerated eBPF/XDP hooks operate directly on the raw Network Interface Card (NIC) driver ring buffer at Layer 3/4. Inspecting packets prior to TLS termination would only yield encrypted TLS application records.

To provide zero-dependency Layer 7 Deep Packet Inspection (DPI) and Machine Learning intrusion detection without invasive man-in-the-middle (MitM) certificate rewriting, **CoPSeC** implements **Transparent Reverse-Proxy Decryption Mirroring**.

```
                           +---------------------------------------------+
                           |           Internet Attacker                 |
                           +---------------------------------------------+
                                                 |
                                     (HTTPS Traffic on :443)
                                                 v
                           +---------------------------------------------+
                           |       Host NIC Driver (eBPF / XDP)          |
                           |  [Fast-Path Drop: banned_ips BPF Map]       |
                           +---------------------------------------------+
                                                 | (XDP_PASS)
                                                 v
                           +---------------------------------------------+
                           |  Edge Reverse-Proxy (Nginx/HAProxy/Envoy)   |
                           |  1. Terminates TLS 1.3                      |
                           |  2. Forwards to Upstream App                |
                           |  3. Copies Decrypted Buffer via Tee Mirror  |
                           +---------------------------------------------+
                                     /                         \
                          (Decrypted HTTP)                 (Upstream App)
                                   /                             v
                                  v                    [Internal Services]
         +---------------------------------------------------+
         | UNIX Domain Socket: /run/copsec/mirror.sock       |
         |  - Extracts Real Client IP (PROXY v1/v2 or XFF)   |
         |  - Feeds into CoPSeC Aho-Corasick & SnortML Engine|
         +---------------------------------------------------+
                                  |
              +-------------------+-------------------+
              |                                       |
    [Verdict: VerdictClean]                 [Verdict: VerdictDrop]
              |                                       |
       (No Action Taken)                 1. Injects Client IP into eBPF banned_ips
                                         2. Future packets dropped at NIC line-rate (XDP_DROP)
                                         3. Background PCAP snapshot dumped
                                         4. Authenticated mTLS gRPC alert to Tier 2
```

---

## 2. Production Configuration Recipes

### A. Nginx Configuration (`/etc/nginx/conf.d/copsec_mirror.conf`)
Using the native Nginx `ngx_http_mirror_module`:

```nginx
upstream copsec_mirror_sock {
    server unix:/run/copsec/mirror.sock;
}

server {
    listen 443 ssl http2;
    server_name banking.corp.internal;

    ssl_certificate     /etc/ssl/certs/corporate_banking.crt;
    ssl_certificate_key /etc/ssl/private/corporate_banking.key;

    location / {
        # 1. Asynchronously duplicate request body and headers to CoPSeC
        mirror /_copsec_tee;
        mirror_request_body on;

        proxy_pass http://internal_banking_upstream;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location = /_copsec_tee {
        internal;
        proxy_pass http://copsec_mirror_sock;
        proxy_pass_request_body on;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $remote_addr;
        
        # Ultra-low timeout so mirror failures never impede production traffic
        proxy_connect_timeout 50ms;
        proxy_send_timeout 50ms;
        proxy_read_timeout 50ms;
    }
}
```

---

### B. HAProxy Configuration (`/etc/haproxy/haproxy.cfg`)
Using Stream Processing Offload Engine (SPOE) or log mirroring:

```haproxy
frontend https_in
    bind :443 ssl crt /etc/ssl/certs/bundle.pem
    mode http
    option forwardfor
    
    # Send copy of decrypted payload to CoPSeC engine over Unix Domain Socket
    filter spoe engine copsec config /etc/haproxy/copsec.spoe.cfg
    
    default_backend app_backend

backend app_backend
    mode http
    server srv1 10.0.0.10:8080 check
```

---

### C. Envoy Proxy Configuration (`envoy.yaml`)
Using Envoy's native HTTP Tap Filter:

```yaml
http_filters:
  - name: envoy.filters.http.tap
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.tap.v3.Tap
      common_config:
        static_config:
          match_config:
            any_match: true
          output_config:
            sinks:
              - format: JSON_BODY_AS_BYTES
                streaming_admin: {}
  - name: envoy.filters.http.router
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router
```

---

### D. Linux Kernel Network Tap (`AF_PACKET` / `tc mirred`)
For environments using unencrypted host bridges or tap interfaces:

```bash
# Mirror egress traffic of interface eth0 to ingress of a dummy monitoring interface
sudo ip link add name copsec_tap type dummy
sudo ip link set copsec_tap up
sudo tc qdisc add dev eth0 handle 1: root prio
sudo tc filter add dev eth0 parent 1: protocol ip u32 match u32 0 0 action mirred egress mirror dev copsec_tap
```

---

## 3. Real Client IP Attribution Engine

When requests are forwarded across reverse-proxies, the IP seen on the Unix socket is `127.0.0.1` or the local proxy worker. CoPSeC's `ExtractClientIPAndPayload()` transparently resolves the genuine attacker IP via:

1. **HAProxy / AWS ALB PROXY Protocol v2**: Binary 16-byte header containing connection metadata and true Layer 4 remote address.
2. **PROXY Protocol v1**: Text header `PROXY TCP4 <client_ip> <dst_ip> <src_port> <dst_port>\r\n`.
3. **HTTP Forwarding Headers**:
   - `X-Forwarded-For: <client_ip>, <proxy_1>, <proxy_2>` (Extracts outermost untrusted public IP)
   - `X-Real-IP: <client_ip>`
   - `CF-Connecting-IP: <client_ip>`
   - `True-Client-IP: <client_ip>`

## 4. Zero-Latency Fast-Path Execution

Once an exploit is identified in the decrypted mirror:
1. `CIDRWhitelist.IsWhitelisted(clientIP)` ensures internal gateways and vulnerability scanners are never banned.
2. If non-whitelisted, `ebpf.GetXDPEngine().AddBan(clientIP)` injects the client IP directly into the eBPF `banned_ips` map.
3. The next IP frame sent by that attacker over TCP/IP is dropped instantly at the NIC ring buffer by `copsec_xdp` ($XDP\_DROP$), terminating the attacker session with zero CPU consumption in userspace.
