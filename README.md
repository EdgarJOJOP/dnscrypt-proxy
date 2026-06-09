# dnscrypt-proxy
双栈并行查询全链路加密dns机制，拥有53端口一样的速度，自动从多个上游 DNS 中选择最快响应结果。用户可自由自定义加密 DNS 与 Bootstrap DNS（禁用 53 端口以提升安全性）。内置可配置 TTL 与大小限制的 DNS 缓存，支持识别并应用 AdGuard Home 拦截规则实现域名过滤。采用异步方式记录 DNS 请求日志，到达阈值自动裁剪日志，内存达到设定阈值后自动转存至本地文件并清理内存。整体代码已对内存占用和 CPU 使用进行了深度优化。

# 加密dns与ECH同属于网络加密的最后一块拼图，类似只输入223.6.6.6的都输入明文dns，完全能对任何设备进行流量劫持(默认被流量劫持)，所以必须使用加密dns并且放弃类似223.6.6.6的明文传输。

# 新功能：

新增自动提权为管理员和root，如果不给，可能只影响arp防护功能。

## 1.支持ipv4的arp防护避免流量劫持的高危风险(ipv6是NDP防护)：

win安装npcap （https://npcap.com/#download ），linux不管有root就行。

win记得安装360杀毒(https://sd.360.cn/ )比360安全管家管用。

支持的arp防御：

    攻击类型	攻击包特征
    1	网关冒充	Sender IP=网关IP, Sender MAC=攻击者MAC
    2	IP 冲突	Sender IP=本机IP, Sender MAC=攻击者MAC
    3	GARP 宣告（最危险）	Opcode=2, Sender IP=Target IP=网关, MAC=攻击者
    4	双向 MITM	同时发包 Sender=网关(攻MAC) 和 Sender=本机(攻MAC)
    5	ARP 应答投毒	Opcode=2, Sender IP=网关, MAC=攻击者 → Target=本机
    6	目标端伪装	Target=网关IP, Target MAC≠正确MAC 回应者攻击
    7	基线污染（启动时）	程序刚启动时第一个收到的 ARP 包被设为基线
    8	Opcode=2 回复劫持	正常请求 谁有网关IP? 后被攻击者抢先用错误 MAC 回复
    9	ARP Flood/风暴	短时间内大量不同 MAC 声称是网关/本机

## 2.支持ipv6的NDP防护避免流量劫持的高危风险：

1.里提到的npcap和360杀毒，这个功能默认开启。

支持的NDP防御：

    攻击类型           说明
    4.1.1	NS/NA 欺骗	  常驻嗅探基线 + 主动 NS 探测
    4.1.2	NUD 失败	  _nud_tracker 80ms 窗口追踪
    4.1.3	DAD DoS	sniff   检测 ≥3 次 DAD NS
    4.2.1	恶意路由器 (Rogue RA)  	  检测未知 MAC 源发 RA
    4.2.2	默认路由器被"杀死"	  NUD 失败可感知，无主动切换
    4.2.3	合法路由器变坏	  硬件 MAC 不变时无法检测（需 SEND）
    4.2.4	伪造 Redirect	  sniff 非网关源 Redirect
    4.2.5	虚假 on-link 前缀	  RA 携带假前缀——检测到未知 RA 源可覆盖
    4.2.6	虚假地址配置前缀	  同上，本质是 RA 子类
    4.2.7	参数欺骗 (hop limit / M/O 标志)	  未检查——RA 中 CurHopLimit、M/O 标志未校验
    4.3.1	Replay 攻击	  静态 NDP 终局防御
    4.3.2	远程 NDP DoS	  T7 邻居表增长率监控


## 3.支持config.yaml自定义根目录证书集验证上游加密dns是否可靠：

      根目录证书集下载链接: https://curl.se/ca/cacert.pem
      
      (如果不放心本机的ca有没有被替换，就删除本机全部证书后下载上面的根目录证书集，导入进去就行(问ai命令)。
        就算删除完本机的全部ca证书，该程序也能正常运行。
      )

      这是 Mozilla 维护的 CA 证书包，由 curl 项目打包提供，不依赖 Windows和linux系统存储。
      
      config.yaml：
      
      `tls:
            ca_path: "D:/dns/certs/cacert.pem"  # 只信任此 CA，系统 CA 被完全禁用
      `
      自己只设置自己搭建的上游服务器就只导入你公共 CA签发的(阿里云/腾讯云/华为云)的证书(不要密钥).

      证书扎订(Certificate Pinning)也是一样，程序将只信任这张证书，连 CA 都不需要信任:
      
      示例：
      
      `openssl s_client -connect dns.alidns.com:443 -servername dns.alidns.com </dev/null | openssl x509 -outform PEM > alidns-cert.pem`
 
# 1. 安装库

使用python3.13+版本，无论是python官方版还是conda版。

`pip install -r requirements.txt`

# 2. 生成本地DOH服务所需证书(可选)

证书创建命令.txt中的命令在openssl中进行生成(https://slproweb.com/products/Win32OpenSSL.html )，然后：
1. 按下 Windows 键 + R，输入 `mmc` 打开 Microsoft 管理控制台。
2. 在菜单中选择“文件” > “添加/删除管理单元”。
3. 选择“证书”并点击“添加”。
4. 选择“计算机帐户”，然后点击“完成”。
5. 在控制台中展开“受信任的根证书颁发机构” > “证书”。
6. 完成

linux上就简单了。。。。。。。

# 3. 开启全链路加密最后一块拼图ECH(可选)
我目前查询连cloudflare的加密dns都不支持ech，如果要用需要自行搭建加密dns反代nginx或者caddy开启ech就能验证代码是否工作正常。
使用和写法全部在config.yaml文件里，默认是关闭的。

# 4. 运行

默认关闭本地53端口服务器。

`python main.py`

需要打包自行打包exe或者其它平台就行.

示例：

`pip install nuitka`

 目录内运行下面指令（win打包）
 
`python -m nuitka ^
    --standalone ^
    --mingw64 ^
    --lto=yes ^
    --include-package=crypto ^
    --include-package=resolvers ^
    --include-data-dir=openssl-4.0.0-Windows-x64=openssl-4.0.0-Windows-x64 ^
    --include-data-files=config.yaml=config.yaml ^
    --windows-console-mode=disable ^
    --output-dir=dist ^
    --product-name=dnscrypt-proxy ^
    --product-version=1.0.0 ^
    --file-version=1.0.0 ^
    main.py
`

# 5. 在win11上使用加密dns本地服务


<img width="833" height="457" alt="图片" src="https://github.com/user-attachments/assets/9aa0cbee-0e6c-4913-bb14-b7dac47b18ab" />

为什么不用单个加密dns？
答：单个加密dns不支持全链路tls加密非常容易被中间人攻击，网卡加载网页缓慢或直接加载不了都是因为被中间人攻击。

## 1. IPV4设置参考：

首选DNS：127.0.0.1

DNS over HTTPS：开（手动模板）

DNS over HTTPS 模板：https://127.0.0.1:8443/dns-query
备用：
首选DNS：1.12.12.12 （腾讯DNSPod）

DNS over HTTPS：开（手动模板）

DNS over HTTPS 模板：https://doh.pub/dns-query （这个模板的意思对应上面的DNS地址，要是同一家的才行，这个就是DNSPod的DoH服务器）

## 2. IPV6设置参考

首选DNS：::1 （英文的冒号）

DNS over HTTPS：开（手动模板）

DNS over HTTPS 模板：https://[::1]:8443/dns-query

备用：
首选DNS：2400:3200::1 （腾讯DNSPod）

DNS over HTTPS：开（手动模板）

DNS over HTTPS 模板：https://dns.alidns.com/dns-query


# 待添加功能

无
