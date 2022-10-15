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
    <caption><i><b>2022-10-15 16:09:16</b></i></caption>
    <thead>
      <tr>
        <th>项目</th>
        <th>更新详情</th>
      </tr>
    </thead>
    <tbody>
      <tr><td>kcptun</td><td><a href=https://github.com/xtaci/kcptun/commit/208deccd09b3e9f90fc5c39c16271a53c1128ef2>use rand port instead of sequential pattern</a></td></tr>
<tr><td>tun2socks</td><td><a href=https://github.com/xjasonlyu/tun2socks/commit/24a53467f6cc5ad68210787b55672512b39863e3>Chore: deprecate set-output command</a></td></tr>
    </tbody>
  </table>
</details>
