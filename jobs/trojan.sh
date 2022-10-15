#!/bin/bash
set -e

git clone --depth 1 https://github.com/trojan-gfw/trojan.git /tmp/trojan
cd /tmp/trojan
#https://github.com/trojan-gfw/trojan/issues/567#issue-794744406
echo 'target_link_libraries(trojan dl)' >>CMakeLists.txt
mkdir -p build
cd build/
cmake \
	-DENABLE_MYSQL=OFF \
	-DENABLE_NAT=OFF \
	-DENABLE_SSL_KEYLOG=OFF \
	-DFORCE_TCP_FASTOPEN=OFF \
	-DSYSTEMD_SERVICE=OFF \
	-DBoost_USE_STATIC_LIBS=ON \
	-DOPENSSL_USE_STATIC_LIBS=ON \
	..
make -j2
#ctest
strip /tmp/trojan/build/trojan
cd /tmp/trojan
bash ${CI_PROJECT_DIR}/jobs/push.sh
echo "<tr><td>trojan</td><td><a href="https://github.com/trojan-gfw/trojan/commit/$(git log --pretty=format:"%H")">$(git log --pretty=format:"%s%n")</a></td></tr>" >>${CI_PROJECT_DIR:?}/temp/upgrade.log
cp -vf build/trojan ${CI_PROJECT_DIR:?}/usr/bin
cd ${CI_PROJECT_DIR:?}
sed -i "s/${trojan_old:?}/${trojan:?}/g" version/version
git add usr/bin/trojan version/version temp/upgrade.log
git commit -m "更新trojan流量转发工具"
git push origin HEAD:${CI_COMMIT_REF_NAME:?}
