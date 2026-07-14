cat > /etc/systemd/system/dnscrypt-proxy.service << 'EOF'
[Unit]
Description=DNSCrypt-Proxy Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root/dnscrypt-proxy
Environment=PYTHONMALLOC=mimalloc
#记得替换为自己的启动路径,-B是防止生成__pycache__文件夹每次启动都得编译运行
ExecStart=/root/Python-3.13.2/python -B /root/dnscrypt-proxy/main.py

Restart=on-failure
RestartSec=5s
KillMode=process

# 安全加固（可选）
NoNewPrivileges=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF
