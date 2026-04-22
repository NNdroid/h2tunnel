# h2tunnel

H2Tunnel is a high-performance HTTP/2 tunneling tool written in Go. It leverages the bidirectional streaming capabilities of HTTP/2 to provide secure, low-latency TCP traffic forwarding to remote servers.

By implementing advanced custom SNI (Server Name Indication) and HTTP Host header masquerading, H2Tunnel offers robust anti-censorship capabilities and the ability to penetrate restricted networks via CDNs.

## ✨ Key Features

* **Bidirectional Real-time Streaming**: Built on top of `http.Flusher`, it eliminates the "wait-for-full-request" mechanism of traditional HTTP proxies, delivering near-native TCP latency.
* **Dual-Engine Support**:
  * **H2 (TLS)**: Standard encrypted HTTP/2, suitable for direct public exposure.
  * **H2C (Cleartext)**: Cleartext HTTP/2, designed to work behind reverse proxies like Nginx or Caddy.
* **Advanced Traffic Masquerading**: Full client-side support for custom SNI and Host headers, enabling easy integration with CDNs (e.g., Cloudflare) or parasitizing existing website traffic.
* **Anti-Abuse Security**: Built-in target address whitelisting to prevent malicious scanners from using your server as an open proxy.

## 🚀 Quick Start (Server)

We provide a comprehensive one-click script that handles dependencies, binary updates, self-signed certificates, and systemd service configuration.

### Option 1: Fully Automatic Installation (Recommended)
Generates a random 16-character Token and a random 32-character Path for maximum security:
```bash
bash -c "$(curl -L https://raw.githubusercontent.com/NNdroid/h2tunnel/refs/heads/main/install.sh)" @ install
```

### Option 2: Custom Parameters
Manually specify your secret Token and proxy Path:
```bash
bash -c "$(curl -L https://raw.githubusercontent.com/NNdroid/h2tunnel/refs/heads/main/install.sh)" @ install --token your_secret_token --path /your/secure/path
```

## 🛡️ Reverse Proxy Configuration (Nginx & h2c)

For production environments, running `h2tunnel` in **h2c** (cleartext) mode behind a reverse proxy like Nginx is the most recommended "traffic parasitism" method. This allows your tunnel traffic to blend perfectly with standard HTTPS traffic.

### 1. Run H2Tunnel in h2c Mode
Ensure your `h2tunnel` service is listening on localhost (e.g., `127.0.0.1:12345`) without TLS certificates.

### 2. Nginx Configuration
Add the following `location` block to your existing Nginx `server` configuration:

```nginx
server {
    listen 443 ssl http2; # HTTP/2 is REQUIRED
    server_name yourdomain.com;

    # SSL certificates handled by Nginx
    ssl_certificate /path/to/your/fullchain.pem;
    ssl_certificate_key /path/to/your/privkey.pem;

    # H2Tunnel endpoint
    location /your_secret_path {
        # CRITICAL: Disable buffering for real-time streaming
        proxy_buffering off;
        
        # Forward to local h2c port
        proxy_pass [http://127.0.0.1:12345](http://127.0.0.1:12345);
        
		# 1.1 or 2
        proxy_http_version 1.1;
        
        # Standard headers
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        
        # Prevent connection timeouts for long-lived SSH/Tunnel sessions
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;

        # Support for WebSockets/Streaming upgrades
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }

    # Your existing website content
    location / {
        root /var/www/html;
        index index.html;
    }
}
```

### 3. Apply Changes
Verify your configuration and restart Nginx:
```bash
nginx -t && systemctl restart nginx
```

## 📱 Client Support

* [**Stun**](https://github.com/NNdroid/Stun) - Official Android client implementation, supporting VpnService-based and underlying Root-level global transparent proxying.

---
*© NNdroid 2026*
