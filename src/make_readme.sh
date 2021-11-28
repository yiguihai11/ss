#!/usr/bin/env bash

cat >"${CI_PROJECT_DIR:?}/README.md" <<'EOF'
[![pipeline status](https://gitlab.com/yiguihai/ss/badges/dev/pipeline.svg)](https://gitlab.com/yiguihai/ss/-/commits/dev)
[![coverage report](https://gitlab.com/yiguihai/ss/badges/dev/coverage.svg)](https://gitlab.com/yiguihai/ss/-/commits/dev)  
**Debian 10+**  
**独立公网IP**
### 使用方法
安装脚本
```Shell
wget --no-check-certificate -O /usr/local/bin/ss-main https://gitlab.com/yiguihai/ss/-/raw/dev/usr/bin/ss-main
chmod +x /usr/local/bin/ss-main
```
运行脚本
```Shell
ss-main
```
EOF
: <<'EOF'
查看状态
```Shell
systemctl status ss-main
```
取消开机自启
```Shell
systemctl disable ss-main
```
EOF

if [ -s "${CI_PROJECT_DIR:?}/temp/upgrade.log" ]; then
	cat >>"${CI_PROJECT_DIR:?}/README.md" <<EOF
<details open>
  <summary>更新记录</summary>
  <table>
    <caption><i><b>$(TZ='Asia/Shanghai' date +%Y年%m月%d日\ %X)</b></i></caption>
    <thead>
      <tr>
        <th>项目</th>
        <th>更新详情</th>
      </tr>
    </thead>
    <tbody>
      $(cat ${CI_PROJECT_DIR:?}/temp/upgrade.log)
    </tbody>
  </table>
</details>
EOF
fi
rm -f ${CI_PROJECT_DIR:?}/temp/upgrade.log
