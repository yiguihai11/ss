![alt text](pictures/banner.webp "Shadowsocks")  
[![pipeline status](https://gitlab.com/yiguihai/ss/badges/dev/pipeline.svg)](https://gitlab.com/yiguihai/ss/-/commits/dev)  
**不支持Centos**  
### 使用方法
安装脚本
```Shell
wget --no-check-certificate -O /usr/local/bin/ss-main 'https://gitlab.com/yiguihai/ss/-/raw/dev/usr/bin/ss-main'
chmod +x /usr/local/bin/ss-main
```
安装脚本(CDN)
```Shell
wget --no-check-certificate -O /usr/local/bin/ss-main 'https://glcdn.githack.com/yiguihai/ss/-/raw/dev/usr/bin/ss-main'
chmod +x /usr/local/bin/ss-main
```
运行脚本
```Shell
ss-main
```
<details open>
  <summary>更新记录</summary>
  <table>
    <caption><i><b>2022-05-16 00:27:23</b></i></caption>
    <thead>
      <tr>
        <th>项目</th>
        <th>更新详情</th>
      </tr>
    </thead>
    <tbody>
      <tr><td>shadowsocks-rust</td><td><a href=https://github.com/shadowsocks/shadowsocks-rust/commit/76f8b021c8fb6f4cd53530b4088f57e5bd8617a0>fixed PingBalancer checker panic when servers is empty</a></td></tr>
    </tbody>
  </table>
</details>
