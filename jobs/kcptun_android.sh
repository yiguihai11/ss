#!/bin/bash
set -e
#授予权限与引入环境变量
chmod +x jobs/ndk.sh jobs/golang.sh
source jobs/ndk.sh
source jobs/golang.sh
#不改为auto 或者 on 编译时可能会报错
export GO111MODULE=auto
git clone --depth 1 https://github.com/shadowsocks/kcptun-android /tmp/kcptun-android
cd /tmp/kcptun-android
git submodule update --init
./gradlew assembleRelease
./gradlew assembleDebug
bash ${CI_PROJECT_DIR}/jobs/push.sh
echo "<tr><td><a href="usr/app">kcptun-android</a></td><td><a href="https://github.com/shadowsocks/kcptun-android/commit/$(git log --pretty=format:"%H")">$(git log --pretty=format:"%s%n")</a></td></tr>" >>${CI_PROJECT_DIR:?}/temp/upgrade.log
mv -vf app/build/outputs ${CI_PROJECT_DIR:?}
cd ${CI_PROJECT_DIR:?}
cp -vf outputs/apk/debug/app-armeabi-v7a-debug.apk usr/app/kcptun-armeabi-v7a.apk
cp -vf outputs/apk/debug/app-arm64-v8a-debug.apk usr/app/kcptun-arm64-v8a.apk
sed -i "s/${kcptun_android_old:?}/${kcptun_android:?}/g" version/version
git add usr/app/*.apk version/version temp/upgrade.log
git commit -m "更新kcptun-android"
git push origin HEAD:${CI_COMMIT_REF_NAME:?}
