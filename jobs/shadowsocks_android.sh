#!/bin/bash
set -e
#mount -o remount,size=8G,noatime /sys/devices/virtual/dmi/id
#mount -o remount,size=8G,noatime /sys/fs/cgroup
df -h
#授予权限与引入环境变量
chmod +x jobs/ndk.sh jobs/rust.sh
source jobs/ndk.sh
source jobs/rust.sh
apt-get -qq update
apt-get --quiet install --yes git curl ca-certificates python2.7-minimal python3
apt-get -qq autoremove --purge
apt-get -qq clean
df -h
if [ -z "$CI_PROJECT_DIR" ]; then
	CI_PROJECT_DIR=$(pwd)
fi
#或者python2.7
git clone --depth 1 https://github.com/shadowsocks/shadowsocks-android /tmp/shadowsocks-android
cd /tmp/shadowsocks-android
git submodule update --init
git submodule update --remote
cargo update --manifest-path core/src/main/rust/shadowsocks-rust/Cargo.toml
#https://www.vogella.com/tutorials/GitSubmodules/article.html
#https://en.m.wikipedia.org/wiki/Reserved_IP_addresses
cp -f ${CI_PROJECT_DIR:?}/acl/bypass-lan.acl core/src/main/assets/acl/bypass-lan.acl
cat >core/src/main/assets/acl/bypass-china.acl <<EOF
[proxy_all]

[bypass_list]
$(curl -s https://bgp.space/china.html | grep -oP '([0-9]+\.){3}[0-9]+?\/[0-9]{1,2}')
$(curl -s https://bgp.space/china6.html | grep -oP '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}\/[0-9]{1,3}')
EOF
cat >core/src/main/assets/acl/bypass-lan-china.acl <<EOF
$(cat ${CI_PROJECT_DIR:?}/acl/bypass-lan.acl)
$(curl -s https://bgp.space/china.html | grep -oP '([0-9]+\.){3}[0-9]+?\/[0-9]{1,2}')
$(curl -s https://bgp.space/china6.html | grep -oP '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}\/[0-9]{1,3}')
EOF
cat >core/src/main/assets/acl/china-list.acl <<EOF
[bypass_all]

[proxy_list]
$(curl -s https://bgp.space/china.html | grep -oP '([0-9]+\.){3}[0-9]+?\/[0-9]{1,2}')
$(curl -s https://bgp.space/china6.html | grep -oP '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}\/[0-9]{1,3}')
EOF
curl -s -o core/gfwlist/gfwlist.txt https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt
python2.7 core/gfwlist/parse.py -i core/gfwlist/gfwlist.txt -f core/src/main/assets/acl/gfwlist.acl
cd core/src/main/rust/shadowsocks-rust
rustup target add armv7-linux-androideabi aarch64-linux-android i686-linux-android x86_64-linux-android
rustup update
cd /tmp/shadowsocks-android
patch -p0 core/build.gradle.kts <${CI_PROJECT_DIR:?}/patch/build.gradle.kts.patch
./gradlew assembleRelease
./gradlew assembleDebug
find ./ -name "*.apk"
bash ${CI_PROJECT_DIR}/jobs/push.sh
echo "<tr><td><a href="usr/app">shadowsocks-android</a></td><td><a href="https://github.com/shadowsocks/shadowsocks-android/commit/$(git log --pretty=format:"%H")">$(git log --pretty=format:"%s%n")</a></td></tr>" >>${CI_PROJECT_DIR:?}/temp/upgrade.log
mv -vf mobile/build/outputs/apk ${CI_PROJECT_DIR:?}
cd ${CI_PROJECT_DIR:?}
cp -vf apk/debug/mobile-armeabi-v7a-debug.apk usr/app/shadowsoccks-armeabi-v7a.apk
cp -vf apk/debug/mobile-arm64-v8a-debug.apk usr/app/shadowsoccks-arm64-v8a.apk
sed -i "s/${shadowsocks_android_old:?}/${shadowsocks_android:?}/g" version/version
git add usr/app/*.apk version/version temp/upgrade.log
git commit -m "更新shadowsoccks-android"
git push -o ci.skip origin HEAD:${CI_COMMIT_REF_NAME:?}
