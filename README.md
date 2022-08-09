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
    <caption><i><b>2022-08-10 00:13:34</b></i></caption>
    <thead>
      <tr>
        <th>项目</th>
        <th>更新详情</th>
      </tr>
    </thead>
    <tbody>
      <tr><td><a href="https://quic.nginx.org">nginx-quic</a></td><td><a href="https://hg.nginx.org/nginx-quic/rev/f9d7930d0eed">HTTP/3: skip empty request body buffers (ticket #2374).</a></td></tr>
    </tbody>
  </table>
</details>
