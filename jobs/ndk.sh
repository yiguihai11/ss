#!/bin/bash
set -e
apt-get -qq update
apt-get --quiet install --yes wget curl tar unzip lib32stdc++6 lib32z1 git ca-certificates autoconf libtool libev-dev cmake autoconf automake build-essential gcc m4 binutils pkg-config

#脚本参考来源于 https://gitlab.com/gitlab-org/gitlab-foss/-/blob/master/lib/gitlab/ci/templates/Android.latest.gitlab-ci.yml
export ANDROID_SDK_ROOT="/tmp/android-home"
export ANDROID_HOME="/tmp/android-home" #已经弃用https://developer.android.com/studio/command-line/variables
install -d $ANDROID_SDK_ROOT
wget --quiet --output-document=$ANDROID_SDK_ROOT/cmdline-tools.zip $(wget -qO- 'https://developer.android.com/studio#command-tools' | grep -oP 'https://dl.google.com/android/repository/commandlinetools-linux-[0-9]+_latest.zip')
pushd $ANDROID_SDK_ROOT
echo "解压cmdline-tools与测试"
unzip cmdline-tools.zip
[ -d cmdline-tools/bin ] || exit 127
export PATH=$PATH:${ANDROID_SDK_ROOT}/cmdline-tools/bin
popd
sdkmanager --sdk_root=${ANDROID_SDK_ROOT} --version

# use yes to accept all licenses
yes | sdkmanager --sdk_root=${ANDROID_SDK_ROOT} --licenses || true
#列出已安装和可用的软件包 https://developer.android.com/studio/command-line/sdkmanager
#sdkmanager --sdk_root=${ANDROID_SDK_ROOT} --list
data=$(sdkmanager --sdk_root=${ANDROID_SDK_ROOT} --list)
sdkmanager --sdk_root=${ANDROID_SDK_ROOT} --install "$(echo $data | grep -oP "platforms\;android\-[0-9]{2,}" | tail -n1)"
sdkmanager --sdk_root=${ANDROID_SDK_ROOT} --install "platform-tools"
sdkmanager --sdk_root=${ANDROID_SDK_ROOT} --install "ndk-bundle"
sdkmanager --sdk_root=${ANDROID_SDK_ROOT} --install "cmake;3.18.1"
build_tools=$(echo $data | grep -oP "build\-tools\;(\d+){2,}\.\d\.\d(\-[0-9a-z]+)?" | tail -n1)
sdkmanager --sdk_root=${ANDROID_SDK_ROOT} --install "${build_tools:?}"
export PATH=$PATH:${ANDROID_SDK_ROOT}/build-tools/${build_tools#*;}
apksigner version
#https://developer.android.com/studio/projects/install-ndk
sdkmanager --sdk_root=${ANDROID_SDK_ROOT} --install "$(echo $data | grep -oP "ndk\;\d+\.\d+\.\d+" | tail -n1)" --channel=3
sdkmanager --update --sdk_root=${ANDROID_SDK_ROOT}
#查找编译器所在路径可能需要加入PATH环境变量
#find ${ANDROID_SDK_ROOT} -name "apksigner"
#find ${ANDROID_SDK_ROOT} -name "arm-linux-androideabi-strip"
#find ${ANDROID_SDK_ROOT} -name "aarch64-linux-android-strip"
export ANDROID_NDK_HOME="${ANDROID_SDK_ROOT}/ndk-bundle"
