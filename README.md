# dnscrypt-proxy
双栈并行查询全链路加密dns机制，拥有53端口一样的速度，自动从多个上游 DNS 中选择最快响应结果。用户可自由自定义加密 DNS 与 Bootstrap DNS（禁用 53 端口以提升安全性）。内置可配置 TTL 与大小限制的 DNS 缓存，支持识别并应用 AdGuard Home 拦截规则实现域名过滤。采用异步方式记录 DNS 请求日志，到达阈值自动裁剪日志，内存达到设定阈值后自动转存至本地文件并清理内存。整体代码已对内存占用和 CPU 使用进行了深度优化。

# 1. 安装库

我使用的是python3.11版本

`pip install -r requirements.txt`

# 2. 生成本地DOH服务所需证书(可选)

证书创建命令.txt中的命令在openssl中进行生成，然后：
1. 按下 Windows 键 + R，输入 `mmc` 打开 Microsoft 管理控制台。
2. 在菜单中选择“文件” > “添加/删除管理单元”。
3. 选择“证书”并点击“添加”。
4. 选择“计算机帐户”，然后点击“完成”。
5. 在控制台中展开“受信任的根证书颁发机构” > “证书”。
6. 完成

linux上就简单了。。。。。。。

# 3. 运行

默认关闭本地53端口服务器。

`python main.py`

需要打包自行打包exe或者其它平台就行.

# 4. 在win11上使用加密dns本地服务


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

`没有后台运行功能，后面会开发。
没有自动开机自启功能，后面会开发。
`
