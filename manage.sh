cat > /etc/systemd/system/dnscrypt-proxy.service << 'EOF'
[Unit]
Description=DNSCrypt-Proxy Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root/dnscrypt-proxy
Environment=PYTHONMALLOC=mimalloc
#记得替换为自己的启动路径
ExecStart=/root/Python-3.13.2/python /root/dnscrypt-proxy/main.py

Restart=on-failure
RestartSec=5s

# 安全加固（可选）
NoNewPrivileges=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF
