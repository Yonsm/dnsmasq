# [dnsmasq](：http://www.thekelleys.org.uk/dnsmasq/doc.html)

当前分支基于 [2.8.9](https://thekelleys.org.uk/dnsmasq/dnsmasq-2.89.tar.xz)

```
git checkout git@github.com:Yonsm/dnsmasq.git
git remote add upstream git://thekelleys.org.uk/dnsmasq.git

make

src/dnsmasq -p 5354 -d -q &
sleep 1
dig @127.0.0.1 -p 5354 google.com
```

## 1. 支持 gfwlist 配置

配置文件格式：

```
gfwlist=<path|domain>[@server][^ipset]
```

- `path`：以 `/` 或 `.` 开头的文件路径，内容为每行逐条的 gfwlist.txt
- `domain`：域名，支持逗号分割多个域名（每行需小于 1000 字符）
- `server`：可以省略默认为 `127.0.0.1#5354`
- `ipset`：默认为 `gfwlist`，如果不想启用 ipset 功能，可以直接用 `^`` 而不跟随任何字符即可

举例（如果在命令行中使用为 `--gfwlist`）：

```
gfwlist=mit.edu
gfwlist=github.com,github.io@8.8.4.4~53^gfwlist
gfwlist=/etc/gfwlist.txt
```

仅在 parse 参数和配置的过程中改动，兑现成 dnsmasq 原有的功能。方案靠谱，改动不大，但受益很大。

## 2. 支持 dhcp-host 主机名的持久解析

**问题背景**：Router + AP 情况下，Router 重启后 ，因设备连接 AP 而没有来重新 DHCP，导致 dnsmasq 无法解析 `dhcp-host` 中配置的 hostname。

**解决方案**：支持 `dhcp-to-host` 配置，当此配置开启后，遇到 `dhcp-host` 中包含 hostname 时，会自动添加一条 `host-record` 记录，解决上述问题。

举例（如果在命令行中使用为 `--dhcp-to-host`）

```
dhcp-to-host
```

**改动内容**：在适当的时机调用 dnsmasq 原有代码实现相关功能。

## 3. 支持 TCP DNS

可替代 `dns2tcp`/`dns-forwarder` 功能，要启用此功能可设置如下 `server=/google.com/8.8.8.8~53`，即原 UDP DNS 的 `#` 改成 `~`。

尽量小的改动方案来实现 TCP DNS 功能，对 dnsmasq 的原主链路的入侵影响控制到最小：

- 主流程：只切入到 forward UDP 的一个函数中，向上游 UDP Server 发送请求的时候，不发了，改为我们自己的 TCP DNS 的实现。
- TCP DNS 请求成功后，直接向本机发送 UDP 结果；原主链路收到 UDP 结果后的检查 server 的部分需接受本机发送的结果，也有一点小更改。
- 配置解析：解析到 TCP DNS 后记录下来。
- 日志打印时的相关 `#`/`~` 字符呈现。

_本想实现 TCP connection 复用，但竟然 [RFC 没有支持](https://serverfault.com/questions/761172/long-lived-tcp-connection-to-dns-servers)。不复用 TCP 连接的情况下，初次查询耗时为 160 毫秒左右，比 dns2tcp 略好 5 ～ 10 毫秒，胜在少了一个进程，少了很多代码，简单。_
