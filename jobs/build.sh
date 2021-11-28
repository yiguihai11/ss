#!/bin/bash
set -e

echo "安装依赖"
apt-get -qq update
apt-get --yes install --no-install-recommends \
	wget \
	curl \
	ca-certificates \
	openssh-client \
	openssh-server \
	gettext \
	build-essential \
	autoconf \
	libtool \
	automake \
	unzip \
	git \
	cmake \
	libev-dev \
	jq \
	shellcheck \
	libdigest-sha-perl
echo "配置ssh"
#https://forum.gitlab.com/t/git-push-from-inside-a-gitlab-runner/30554/5
eval $(ssh-agent -s)
echo "${SSH_PRIVATE_KEY}" | tr -d '\r' | ssh-add - >/dev/null
mkdir -p ~/.ssh
chmod 700 ~/.ssh
echo "$SSH_PUBLIC_KEY" >>~/.ssh/id_rsa.pub
if [ -f /.dockerenv ]; then
	echo -e "Host *\n\tStrictHostKeyChecking no\n\n" >~/.ssh/config
fi
ssh -T git@gitlab.com
git config --global user.email "$GITLAB_USER_EMAIL"
git config --global user.name "$GITLAB_USER_LOGIN"
git remote set-url origin git@${CI_SERVER_HOST}:${CI_PROJECT_PATH}.git

echo "检查更新"
source version/version
old=($(shasum -a1 version/version))

now=($(shasum -a1 src/manager.sh))
if [ "$ss_main" != "${now:=0}" ]; then
	echo "ss-main 发现有更新"
	sed -i "s/$ss_main/$now/g" version/version
	ss_main="$now"
fi
now=($(shasum -a1 src/main.c))
if [ "$ss_tool" != "${now:=0}" ]; then
	echo "ss-tool 发现有更新"
	sed -i "s/$ss_tool/$now/g" version/version
	ss_tool="$now"
fi
now=$(wget -qO- https://api.github.com/repos/zfl9/ipt2socks/commits/master | jq -r '.sha')
if [ "$ipt2socks" != "${now:=0}" ]; then
	echo "ipt2socks 发现有更新"
	sed -i "s/$ipt2socks/$now/g" version/version
	ipt2socks="$now"
fi
now=$(wget -qO- https://api.github.com/repos/xtaci/kcptun/commits/master | jq -r '.sha')
if [ "$kcptun" != "${now:=0}" ]; then
	echo "kcptun 发现有更新"
	sed -i "s/$kcptun/$now/g" version/version
	kcptun="$now"
fi
now=$(wget -qO- https://api.github.com/repos/teddysun/v2ray-plugin/commits/master | jq -r '.sha')
if [ "$v2ray_plugin" != "${now:=0}" ]; then
	echo "v2ray-plugin 发现有更新"
	sed -i "s/$v2ray_plugin/$now/g" version/version
	v2ray_plugin="$now"
fi
now=$(wget -qO- https://api.github.com/repos/fukuchi/libqrencode/commits/master | jq -r '.sha')
if [ "$qrencode" != "${now:=0}" ]; then
	echo "libqrencode 发现有更新"
	sed -i "s/$qrencode/$now/g" version/version
	qrencode="$now"
fi
now=$(wget -qO- https://api.github.com/repos/shadowsocks/simple-obfs/commits/master | jq -r '.sha')
if [ "$simple_obfs" != "${now:=0}" ]; then
	echo "simple-obfs 发现有更新"
	sed -i "s/$simple_obfs/$now/g" version/version
	simple_obfs="$now"
fi
now=$(wget -qO- https://api.github.com/repos/shadowsocksrr/shadowsocksr-libev/commits/master | jq -r '.sha')
if [ "$shadowsocksr_libev" != "${now:=0}" ]; then
	echo "shadowsocksr-libev 发现有更新"
	sed -i "s/$shadowsocksr_libev/$now/g" version/version
	shadowsocksr_libev="$now"
fi
now=$(wget -qO- https://www.php.net/downloads.php | grep -oP 'php\-\d+\.\d+\.\d+\.tar.gz' | head -n 1)
if [ "$php" != ${now/.tar.gz/} ]; then
	echo "php 发现有更新"
	sed -i "s/$php/${now/.tar.gz/}/g" version/version
	php="${now/.tar.gz/}"
	echo "<tr><td>php</td><td><a href="https://www.php.net/downloads.php">${now/.tar.gz/}</a></td></tr>" >>/tmp/upgrade.log
fi
data=$(curl --silent --location --cookie "$(curl --silent https://hg.nginx.org/nginx-quic | grep cookie | cut -d'"' -f2 | xargs echo -n)" https://hg.nginx.org/nginx-quic | grep "/nginx-quic/rev/" | grep -e "[0-9a-f]\{12\}" | head -n1)
now=$(echo $data | cut -d'"' -f2 | grep -oP '[0-9a-f]{12}')
if [ "$nginx_quic" != "${now:=0}" ]; then
	echo "nginx-quic 发现有更新"
	sed -i "s/$nginx_quic/$now/g" version/version
	nginx_quic="$now"
	echo "<tr><td><a href="https://quic.nginx.org">nginx-quic</a></td><td><a href="https://hg.nginx.org/nginx-quic/rev/$now">$(echo $data | cut -d'>' -f2 | cut -d'<' -f1)</a></td></tr>" >>/tmp/upgrade.log
fi
now=$(wget -qO- https://api.github.com/repos/shadowsocks/shadowsocks-rust/commits/master | jq -r '.sha')
if [ "$shadowsocks_rust" != "${now:=0}" ]; then
	echo "shadowsocks-rust 发现有更新"
	sed -i "s/$shadowsocks_rust/$now/g" version/version
	shadowsocks_rust="$now"
fi
new=($(shasum -a1 version/version))
if [ "$old" != "$new" ]; then
	: <<EOF
	echo "修正时区"
	#https://cloud.tencent.com/developer/article/1626811
	ln -fs /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
	echo "Asia/Shanghai" >/etc/timezone
	dpkg-reconfigure --frontend noninteractive tzdata
	rm -rf /var/lib/apt/lists/*
EOF
	echo "开始编译更新..."
	update="$new"
	mkdir -p /etc/ssmanager/usr /etc/ssmanager/usr/bin /etc/ssmanager/usr/sbin
	touch /tmp/outputs.sh
fi

if [ "$update" ] && [ "$shadowsocks_rust" ]; then
	echo "安装Rust编译环境"
	rustup update
	rustup install nightly
	rustc --version
	rustup target add x86_64-unknown-linux-gnu
fi
if [ "$update" ]; then
	if [ "$ipt2socks" ] || [ "$kcptun" ] || [ "$v2ray_plugin" ] || [ "$qrencode" ] || [ "$simple_obfs" ] || [ "$shadowsocksr_libev" ] || [ "$php" ] || [ "$nginx_quic" ] || [ "$shadowsocks_rust" ]; then
		echo "编译UPX压缩工具"
		cd /tmp
		wget --quiet --continue http://www.oberhumer.com/opensource/ucl/download/ucl-1.03.tar.gz
		tar xzf ucl-1.03.tar.gz
		cd ucl-1.03
		#https://blog.csdn.net/qq_34905587/article/details/106663453
		./configure CPPFLAGS="$CPPFLAGS -std=c90 -fPIC"
		make
		make install
		make clean
		git clone --depth 1 https://github.com/upx/upx /tmp/upx
		cd /tmp/upx
		git submodule update --init --recursive
		make all
		strip src/upx.out
		mv -f src/upx.out /usr/local/bin/upx
		make clean
		upx -V
	fi
fi
if [ "$update" ]; then
	if [ "$ss_main" ] || [ "$kcptun" ] || [ "$v2ray_plugin" ]; then
		cd /tmp
		latest_version="$(wget -qO- https://golang.org/dl/ | grep 'download downloadBox' | grep -oP '\d+\.\d+(\.\d+)?' | head -n 1)"
		echo "Downloading latest Go for AMD64: ${latest_version}"
		wget --quiet --continue https://dl.google.com/go/go${latest_version}.linux-amd64.tar.gz
		tar -C /usr/local -xzf go${latest_version}.linux-amd64.tar.gz
		rm -f go${latest_version}.linux-amd64.tar.gz
		#必须更改变量，不然调用go编译器报错
		export GOROOT="/usr/local/go"
		export GOTOOLDIR="/usr/local/go/pkg/tool/linux_amd64"
		ln -sf /usr/local/go/bin/go /usr/bin/go
		go version
		go env
	fi
fi

if [ "$update" ] && [ "$ss_main" ]; then
	/usr/local/go/bin/go install mvdan.cc/sh/v3/cmd/shfmt@latest
	cp -f $(go env GOPATH)/bin/shfmt /usr/local/bin
	shfmt -version
fi

if [ "$update" ] && [ "$php" ]; then
	cd /tmp
	latest_version="$(wget -qO- https://www.openssl.org/source/ | grep -oP 'openssl\-\d+\.\d+\.\d+\w+\.tar\.gz' | head -n1)"
	wget --quiet --continue https://www.openssl.org/source/${latest_version}
	tar xzf ${latest_version}
	rm -f ${latest_version}
	mv ${latest_version/.tar.gz/} openssl
	cd openssl
	./Configure \
		no-shared \
		linux-x86_64
	make
	make install_sw
	make distclean
fi
if [ "$update" ] && [ "$kcptun" ]; then
	cd /tmp
	git clone --depth 1 https://github.com/xtaci/kcptun.git
	cd kcptun/server
	echo "<tr><td>kcptun</td><td><a href="https://github.com/xtaci/kcptun/commit/$(git log --pretty=format:"%H")">$(git log --pretty=format:"%s%n")</a></td></tr>" >>/tmp/upgrade.log
	env GO111MODULE=on CGO_ENABLED=1 GOOS=linux GOARCH=amd64 /usr/local/go/bin/go build -mod=vendor -ldflags "-X main.VERSION=$(date -u +%Y%m%d) -s -w" -o /etc/ssmanager/usr/bin/kcptun-server
	upx --best --ultra-brute /etc/ssmanager/usr/bin/kcptun-server
	/etc/ssmanager/usr/bin/kcptun-server -version
	echo "cp -vf /etc/ssmanager/usr/bin/kcptun-server ${CI_PROJECT_DIR}/usr/bin" >>/tmp/outputs.sh
fi
if [ "$update" ] && [ "$v2ray_plugin" ]; then
	cd /tmp
	git clone --depth 1 https://github.com/teddysun/v2ray-plugin.git
	cd v2ray-plugin
	echo "<tr><td>v2ray-plugin</td><td><a href="https://github.com/teddysun/v2ray-plugin/commit/$(git log --pretty=format:"%H")">$(git log --pretty=format:"%s%n")</a></td></tr>" >>/tmp/upgrade.log
	/usr/local/go/bin/go get -d ./...
	env CGO_ENABLED=1 GOOS=linux GOARCH=amd64 /usr/local/go/bin/go build -ldflags "-X main.VERSION=$(date -u +%Y%m%d) -s -w" -o /etc/ssmanager/usr/bin/v2ray-plugin
	upx --best --ultra-brute /etc/ssmanager/usr/bin/v2ray-plugin
	/etc/ssmanager/usr/bin/v2ray-plugin -version
	echo "cp -vf /etc/ssmanager/usr/bin/v2ray-plugin ${CI_PROJECT_DIR}/usr/bin" >>/tmp/outputs.sh
fi
if [ "$update" ] && [ "$ipt2socks" ]; then
	cd /tmp
	git clone --depth 1 https://github.com/zfl9/ipt2socks
	cd ipt2socks
	make
	upx --best --ultra-brute ipt2socks
	/tmp/ipt2socks/ipt2socks -V
	echo "cp -vf /tmp/ipt2socks/ipt2socks ${CI_PROJECT_DIR}/usr/bin" >>/tmp/outputs.sh
fi
if [ "$update" ] && [ "$qrencode" ]; then
	cd /tmp
	git clone --depth 1 https://github.com/fukuchi/libqrencode
	cd libqrencode
	echo "<tr><td>libqrencode</td><td><a href="https://github.com/fukuchi/libqrencode/commit/$(git log --pretty=format:"%H")">$(git log --pretty=format:"%s%n")</a></td></tr>" >>/tmp/upgrade.log
	./autogen.sh
	./configure --without-png --enable-shared=no --prefix=/etc/ssmanager/usr
	make
	make install
	make clean
	strip /etc/ssmanager/usr/bin/qrencode
	upx --best --ultra-brute /etc/ssmanager/usr/bin/qrencode
	/etc/ssmanager/usr/bin/qrencode -V
	echo "cp -vf /etc/ssmanager/usr/bin/qrencode ${CI_PROJECT_DIR}/usr/bin" >>/tmp/outputs.sh
fi
if [ "$update" ] && [ "$simple_obfs" ]; then
	cd /tmp
	git clone --depth 1 https://github.com/shadowsocks/simple-obfs
	cd simple-obfs
	echo "<tr><td>simple-obfs</td><td><a href="https://github.com/shadowsocks/simple-obfs/commit/$(git log --pretty=format:"%H")">$(git log --pretty=format:"%s%n")</a></td></tr>" >>/tmp/upgrade.log
	git submodule update --init
	./autogen.sh
	#https://www.cnblogs.com/z16166/p/13192665.html
	env LDFLAGS=-no-pie ./configure \
		--disable-documentation \
		--prefix=/etc/ssmanager/usr
	find ./ -name "Makefile" -type f -exec sed -i 's/-lev/-l:libev.a/g' {} +
	make
	make install
	strip /etc/ssmanager/usr/bin/obfs-server
	upx --best --ultra-brute /etc/ssmanager/usr/bin/obfs-server
	echo "cp -vf /etc/ssmanager/usr/bin/obfs-server ${CI_PROJECT_DIR}/usr/bin" >>/tmp/outputs.sh
	make clean
fi
if [ "$update" ] && [ "$shadowsocksr_libev" ]; then
	cd /tmp
	#git clone --depth 1 https://github.com/ARMmbed/mbedtls
	#cd mbedtls
	#ssr源码只兼容到这一版本mbedtls
	wget --quiet --continue https://github.com/ARMmbed/mbedtls/archive/refs/tags/v2.26.0.tar.gz
	tar xzf v2.26.0.tar.gz
	cd mbedtls-2.26.0
	make no_test
	make install DESTDIR=/usr/local
	git clone --depth 1 https://github.com/shadowsocksrr/shadowsocksr-libev
	cd shadowsocksr-libev
	echo "<tr><td>shadowsocksr-libev</td><td><a href="https://github.com/shadowsocksrr/shadowsocksr-libev/commit/$(git log --pretty=format:"%H")">$(git log --pretty=format:"%s%n")</a></td></tr>" >>/tmp/upgrade.log
	./autogen.sh
	./configure --disable-documentation --with-crypto-library=mbedtls --prefix=/etc/ssmanager/usr
	find ./ -name "Makefile" -type f -exec sed -i 's/-lmbedcrypto -lm -lpcre/-l:libmbedcrypto.a -lm -l:libpcre.a/g' {} +
	make
	make install
	strip /etc/ssmanager/usr/bin/ss-redir
	upx --best --ultra-brute /etc/ssmanager/usr/bin/ss-redir
	echo "cp -vf /etc/ssmanager/usr/bin/ss-redir ${CI_PROJECT_DIR}/usr/bin" >>/tmp/outputs.sh
	make clean
fi

if [ "$update" ] && [ "$php" ]; then
	cd /tmp
	wget --quiet --continue https://www.php.net/distributions/${php}.tar.gz
	tar xzf ${php}.tar.gz
	rm -f ${php}.tar.gz
	#编译依赖库
	git clone --depth 1 https://gitlab.gnome.org/GNOME/libxml2.git
	cd libxml2
	autoreconf -vfi
	./configure --enable-shared=no
	make
	make install
	git clone --depth 1 https://github.com/kkos/oniguruma
	cd oniguruma
	./autogen.sh
	./configure --enable-shared=no
	make
	make install
	git clone --depth 1 https://github.com/curl/curl.git
	cd curl
	autoreconf -vfi
	./configure --with-openssl --enable-shared=no
	make
	make install
	cd /tmp/$php
	./buildconf
	./configure \
		--with-curl \
		--with-openssl \
		--enable-mbstring \
		--enable-fpm \
		--enable-sockets \
		--without-sqlite3 \
		--without-pdo-sqlite \
		--enable-shared=no \
		--prefix=/etc/ssmanager/usr
	#patch -p0 Makefile < ${CI_PROJECT_DIR}/patch/Makefile_php.patch
	make
	make install
	make clean
	strip /etc/ssmanager/usr/sbin/php-fpm /etc/ssmanager/usr/bin/php
	upx --best --ultra-brute /etc/ssmanager/usr/sbin/php-fpm /etc/ssmanager/usr/bin/php
	/etc/ssmanager/usr/sbin/php-fpm -v
	/etc/ssmanager/usr/bin/php -v
	echo "cp -vf /etc/ssmanager/usr/sbin/php-fpm /etc/ssmanager/usr/bin/php ${CI_PROJECT_DIR}/usr/sbin" >>/tmp/outputs.sh
fi
if [ "$update" ] && [ "$nginx_quic" ]; then
	git clone --recursive https://github.com/google/ngx_brotli /tmp/ngx_brotli
	cd /tmp/ngx_brotli && git submodule update --init
	cd /tmp
	git clone --depth 1 https://boringssl.googlesource.com/boringssl
	mkdir boringssl/build
	cd boringssl/build
	cmake ..
	make
	hg clone -b quic https://hg.nginx.org/nginx-quic /tmp/nginx-quic
	cd /tmp/nginx-quic
	./auto/configure \
		--prefix=/etc/ssmanager/usr \
		--user=nobody \
		--group=root \
		--with-pcre \
		--with-stream \
		--with-pcre-jit \
		--with-threads \
		--with-http_stub_status_module \
		--with-http_dav_module \
		--with-http_ssl_module \
		--with-stream_ssl_module \
		--with-stream_ssl_preread_module \
		--with-http_v2_module \
		--with-http_v3_module \
		--add-module=/tmp/ngx_brotli \
		--with-cc-opt="-Wno-error=type-limits -I../boringssl/include" \
		--with-ld-opt="-L../boringssl/build/ssl -L../boringssl/build/crypto"
	find ./ -name "Makefile" -type f -exec sed -i 's/-lpcre/-l:libpcre.a/g' {} +
	make
	make install
	make clean
	strip /etc/ssmanager/usr/sbin/nginx
	upx --best --ultra-brute /etc/ssmanager/usr/sbin/nginx
	/etc/ssmanager/usr/sbin/nginx -V
	echo "cp -vf /etc/ssmanager/usr/sbin/nginx ${CI_PROJECT_DIR}/usr/sbin" >>/tmp/outputs.sh
fi
if [ "$update" ] && [ "$shadowsocks_rust" ]; then
	cd /tmp
	git clone --depth 1 https://github.com/shadowsocks/shadowsocks-rust.git
	cd shadowsocks-rust
	echo "<tr><td>shadowsocks-rust</td><td><a href="https://github.com/shadowsocks/shadowsocks-rust/commit/$(git log --pretty=format:"%H")">$(git log --pretty=format:"%s%n")</a></td></tr>" >>/tmp/upgrade.log
	env CARGO_HTTP_MULTIPLEXING=false cargo +nightly build --release --target x86_64-unknown-linux-gnu --features "local-redir aead-cipher-extra"
	for i in ssurl ssmanager ssserver; do
		cp -vf target/x86_64-unknown-linux-gnu/release/$i /etc/ssmanager/usr/bin
		strip /etc/ssmanager/usr/bin/$i
		upx --best --ultra-brute -v /etc/ssmanager/usr/bin/$i
		/etc/ssmanager/usr/bin/$i -V
		echo "cp -vf /etc/ssmanager/usr/bin/$i ${CI_PROJECT_DIR}/usr/bin" >>/tmp/outputs.sh
	done
fi
if [ "$update" ] && [ "$ss_tool" ]; then
	gcc -s -fPIE -O3 -o /etc/ssmanager/usr/bin/ss-tool src/main.c
	#mv -f ss-tool usr/bin
	echo "cp -vf /etc/ssmanager/usr/bin/ss-tool ${CI_PROJECT_DIR}/usr/bin" >>/tmp/outputs.sh
fi
if [ "$update" ] && [ "$ss_main" ]; then
	shfmt -l -s -w src/manager.sh
	shellcheck --shell=bash src/manager.sh
	cp -vf src/manager.sh /tmp
	gzexe /tmp/manager.sh
	echo "cp -vf /tmp/manager.sh ${CI_PROJECT_DIR}/usr/bin/ss-main" >>/tmp/outputs.sh
fi
if [ "$update" ]; then
	echo "上传更新"
	[ -s /tmp/upgrade.log ] && bash src/make_readme.sh
	bash /tmp/outputs.sh
	shasum -a512 \
		usr/bin/v2ray-plugin \
		usr/bin/kcptun-server \
		usr/bin/obfs-server \
		usr/bin/qrencode \
		usr/bin/ss-main \
		usr/bin/ssmanager \
		usr/bin/ssserver \
		usr/bin/ss-tool \
		usr/bin/ssurl \
		>version/update
	sed -i "s/usr/\/etc\/ssmanager\/usr/g" version/update
	git add README.md src/manager.sh backups/* version/* usr/*
	git commit -m "$GITLAB_USER_NAME $CI_RUNNER_EXECUTABLE_ARCH"
	git push -o ci.skip origin HEAD:${CI_COMMIT_REF_NAME}
else
	echo "No changes, nothing to commit!"
fi
