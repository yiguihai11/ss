<?php
//https://codebeautify.org/php-beautifier
error_reporting(1); //https://www.php.net/manual/zh/errorfunc.constants.php

function trim_value(&$value)
{
    $value = trim($value);
}
function plugin_opts_val($data, $key)
{
    foreach (explode(";", $data) as $data1) {
        if (isset(explode("=", $data1)[0]) && isset(explode("=", $data1)[1])) {
            if ($key == explode("=", $data1)[0]) {
                return explode("=", $data1)[1] ?? null;
            }
        }
    }
}
function external_ip_address($ipv)
{
    //https://stackoverflow.com/a/36604437
    if ($ipv == 4) {
        $ip = "8.8.8.8";
        $sock = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
    }
    if ($ipv == 6) {
        $ip = "2001:4860:4860::8888";
        $sock = socket_create(AF_INET6, SOCK_DGRAM, SOL_UDP);
    }
    if (in_array($ipv, [4, 6])) {
        if (@socket_connect($sock, $ip, 53)) {
            socket_getsockname($sock, $localAddr);
            socket_shutdown($sock, 2);
            socket_close($sock);
            return $localAddr;
        }
    }
}
function GetOs()
{
    $OS = @$_SERVER["HTTP_USER_AGENT"];
    if (isset($OS)) {
        if (stripos($OS, "Android") || stripos($OS, "Dalvik")) {
            return "Android";
        } elseif (
            stripos($OS, "iPhone") ||
            stripos($OS, "Apple") ||
            stripos($OS, "Darwin")
        ) {
            return "iPhone";
        } elseif (stripos($OS, "Windows")) {
            return "Windows";
        } else {
            return "Other";
        }
    } else {
        exit("获取访客操作系统信息失败！");
    }
}
//https://www.uuidgenerator.net/dev-corner/php
function guidv4($data = null)
{
    // Generate 16 bytes (128 bits) of random data or use the data passed into the function.
    $data = $data ?? random_bytes(16);
    assert(strlen($data) == 16);
    // Set version to 0100
    $data[6] = chr((ord($data[6]) & 0x0f) | 0x40);
    // Set bits 6-7 to 10
    $data[8] = chr((ord($data[8]) & 0x3f) | 0x80);
    // Output the 36 character UUID.
    return vsprintf("%s%s-%s-%s-%s-%s%s%s", str_split(bin2hex($data), 4));
}
function controller_ipc($input)
{
    $client_side_sock = "/tmp/ss-client2.socket";
    if (file_exists($client_side_sock)) {
        unlink($client_side_sock);
    }
    if (!($socket = socket_create(AF_UNIX, SOCK_DGRAM, 0))) {
        $errorcode = socket_last_error();
        $errormsg = socket_strerror($errorcode);
        die("Couldn't create socket: [$errorcode] $errormsg \n");
    }
    socket_set_option($socket, SOL_SOCKET, SO_SNDTIMEO, [
        "sec" => 1,
        "usec" => 0,
    ]);
    socket_set_option($socket, SOL_SOCKET, SO_RCVTIMEO, [
        "sec" => 1,
        "usec" => 0,
    ]);
    if (!socket_bind($socket, $client_side_sock)) {
        $errorcode = socket_last_error();
        $errormsg = socket_strerror($errorcode);
        die("Could not bind socket : [$errorcode] $errormsg \n");
    }
    socket_sendto(
        $socket,
        $input,
        strlen($input),
        0,
        "/tmp/ss-manager.socket",
        0
    );
    if (!socket_recvfrom($socket, $buf, 64 * 1024, 0, $source)) {
        $errorcode = socket_last_error();
        $errormsg = socket_strerror($errorcode);
        die("Could not receive data: [$errorcode] $errormsg \n");
    }
    // close socket and delete own .sock file
    socket_close($socket);
    unlink($client_side_sock);
    if (isset($buf) && $buf != $input) {
        return $buf;
    }
}
//https://shadowsocks.org/en/wiki/SIP008-Online-Configuration-Delivery.html
header("Content-Type: application/json; charset=utf-8");
$array = [
    "version" => (int) 1,
    "remarks" => (string) "Shadowsocks-Rust",
    "servers" => (array) [],
];
$arrContextOptions = [
    "http" => [
        "timeout" => 3,
    ],
    "ssl" => [
        "verify_peer" => false,
        "verify_peer_name" => false,
    ],
];
$ini_array = parse_ini_file("/etc/ssmanager/conf/config.ini");
$user_data = json_decode(
    str_replace("stat: ", "", controller_ipc("ping")),
    true
);
$port_list = "/etc/ssmanager/port.list";
$tls_cert = "/etc/ssmanager/ssl/server.cer";
$ipCheck = empty($_SERVER["HTTP_CDN_LOOP"]) ? false : true;
//https://www.geeksforgeeks.org/how-to-get-parameters-from-a-url-string-in-php/
@parse_str(base64_decode($_GET["args"]), $args);
array_walk($_GET, "trim_value");
array_walk($args, "trim_value");
$route = @$_GET["route"] ?? $args["route"];
$client_type = @$_GET["client_type"] ?? $args["client_type"];
$remote_dns = @$_GET["remote_dns"] ?? $args["remote_dns"];
$bypass_app = @$_GET["bypass_app"] ?? $args["bypass_app"];
$add_best_ip = @$_GET["add_best_ip"] ?? $args["add_best_ip"];
if (file_exists($port_list) and is_array($user_data)) {
    $array["status"] = (string) "Succeed";
} else {
    $array["status"] = (string) "Failed";
}
if (file_exists($port_list)) {
    $my_ipv4 = filter_var(
        external_ip_address(4),
        FILTER_VALIDATE_IP,
        FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
    );
    $my_ipv6 = filter_var(
        external_ip_address(6),
        FILTER_VALIDATE_IP,
        FILTER_FLAG_IPV6 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
    );
    if ($my_ipv6) {
        $server_addr = $my_ipv6;
    }
    if ($my_ipv4) {
        $server_addr = $my_ipv4;
    }
    if (!is_string($client_type)) {
        $client_type = GetOs();
    }
    if (empty($server_addr)) {
        $server_addr = file_get_contents(
            "https://api64.ipify.org",
            false,
            stream_context_create($arrContextOptions)
        );
    }
    if (empty($server_addr)) {
        exit("获取IP地址失败！");
    }
    if ($bypass_app == "true" and $client_type == "Android") {
        $android_list =
            file(
                $ini_array["URL"] . "/conf/android_list",
                FILE_SKIP_EMPTY_LINES,
                stream_context_create($arrContextOptions)
            ) ?? null;
    }
    $names = file($port_list, FILE_SKIP_EMPTY_LINES);
    $i = 0;
    foreach ($names as $name) {
        foreach (explode("|", $name) as $name) {
            $name = explode("^", $name);
            //$server = $_SERVER["SERVER_ADDR"];
            $server = $server_addr;
            switch ($name[0]) {
                case "server_port":
                    $server_port = $name[1];
                    break;
                case "password":
                    $password = $name[1];
                    break;
                case "method":
                    $method = $name[1];
                    break;
                case "plugin":
                    $plugin = $name[1];
                    break;
                case "plugin_opts":
                    $plugin_opts = $name[1];
                    break;
                case "used_traffic":
                    $used_traffic = $name[1];
                    break;
                case "total":
                    $total = $name[1];
                    break;
                case "reset_day":
                    $reset_day = $name[1];
                    break;
                case "reset_type":
                    $reset_type = $name[1];
                    break;
                case "expire_timestamp":
                    $expire_timestamp = $name[1];
                    break;
                case "upload_limit":
                    $upload_limit = $name[1];
                    break;
                case "download_limit":
                    $download_limit = $name[1];
                    break;
                case "user_id":
                    $user_id = $name[1];
                    break;
            }
        }
        $used = $user_data[$server_port];
        $percent = null;
        if (!is_numeric($used)) {
            $percent = " Offline";
        }
        if (is_numeric($used) && is_numeric($total)) {
            if ($total > 0) {
                $percent =
                    " " .
                    round(($used + $used_traffic) / $total, 2) * 100 .
                    "%";
            }
        }
        switch ($plugin) {
            case "obfs-server":
                $plugin = "obfs-local";
                $plugin_opts =
                    $plugin_opts . ";obfs-host=pull.free.video.10010.com";
                break;
            case "kcptun.sh":
                $plugin = "kcptun";
                if ($client_type != "Android") {
                    $plugin_opts = str_replace(
                        "acknodelay",
                        "acknodelay=true",
                        str_replace("nocomp", "nocomp=true", $plugin_opts)
                    );
                }
                break;
            case "v2ray-plugin":
                if (file_exists($tls_cert)) {
                    $v2ray_certraw = trim(
                        str_replace(
                            "-----END CERTIFICATE-----",
                            "",
                            str_replace(
                                "-----BEGIN CERTIFICATE-----",
                                "",
                                file_get_contents($tls_cert)
                            )
                        )
                    );
                }
                //if ($ipCheck && !preg_match("[quic|grpc]", $plugin_opts)) {
                if ($ipCheck and !strpos($plugin_opts, "quic")) {
                    if (
                        strpos($plugin_opts, "grpc") and
                            strpos($plugin_opts, "tls") or
                        !strpos($plugin_opts, "grpc")
                    ) {
                        $server =
                            @$_GET["cloudflare_ip"] ?? $args["cloudflare_ip"];
                        if (empty($server)) {
                            $server = $_SERVER["SERVER_NAME"];
                        }
                        if (str_contains($plugin_opts, "tls")) {
                            $server_port = 443;
                        } else {
                            $server_port = 80;
                        }
                    }
                }
                if (
                    str_contains($plugin_opts, "grpc") &&
                    str_contains($plugin_opts, "tls")
                ):
                    if ($server_port == 443) {
                        $plugin_opts =
                            "tls;mode=grpc;host=" .
                            plugin_opts_val($plugin_opts, "host") .
                            ";serviceName=" .
                            plugin_opts_val($plugin_opts, "serviceName");
                        if (is_numeric($used)) {
                            $forward_list[] = (int) $i;
                        }
                    } else {
                        $plugin_opts =
                            "tls;mode=grpc;host=" .
                            plugin_opts_val($plugin_opts, "host") .
                            ";serviceName=" .
                            plugin_opts_val($plugin_opts, "serviceName") .
                            ";certRaw=" .
                            $v2ray_certraw;
                    }
                elseif (str_contains($plugin_opts, "grpc")):
                    $plugin_opts =
                        "mode=grpc;host=" .
                        plugin_opts_val($plugin_opts, "host") .
                        ";serviceName=" .
                        plugin_opts_val($plugin_opts, "serviceName") .
                        ";certRaw=" .
                        $v2ray_certraw;
                elseif (str_contains($plugin_opts, "quic")):
                    $plugin_opts =
                        "mode=quic;host=" .
                        plugin_opts_val($plugin_opts, "host") .
                        ";certRaw=" .
                        $v2ray_certraw;
                elseif (str_contains($plugin_opts, "tls")):
                    if ($server_port == 443) {
                        $plugin_opts =
                            "tls;host=" .
                            plugin_opts_val($plugin_opts, "host") .
                            ";path=" .
                            plugin_opts_val($plugin_opts, "path");
                        if (is_numeric($used)) {
                            $forward_list[] = (int) $i;
                        }
                    } else {
                        $plugin_opts =
                            "tls;host=" .
                            plugin_opts_val($plugin_opts, "host") .
                            ";path=" .
                            plugin_opts_val($plugin_opts, "path") .
                            ";certRaw=" .
                            $v2ray_certraw;
                    }
                else:
                    $plugin_opts =
                        "host=" .
                        plugin_opts_val($plugin_opts, "host") .
                        ";path=" .
                        plugin_opts_val($plugin_opts, "path");
                endif;
                break;
        }
        $array["servers"][$i]["id"] = (string) $user_id ?? guidv4();
        $array["servers"][$i]["remarks"] =
            (string) "Server #" . $i + 1 . $percent;
        $array["servers"][$i]["server"] = (string) $server;
        $array["servers"][$i]["server_port"] = (int) $server_port;
        $array["servers"][$i]["password"] = (string) $password;
        $array["servers"][$i]["method"] = (string) $method;
        if ($client_type == "Android") {
            if (
                filter_var(
                    $server_addr,
                    FILTER_VALIDATE_IP,
                    FILTER_FLAG_IPV6
                ) or $my_ipv6
            ) {
                $array["servers"][$i]["ipv6"] = (bool) true;
            } else {
                $array["servers"][$i]["ipv6"] = (bool) false;
            }
        }
        if ($client_type == "Android") {
            if (is_string($route)) {
                $array["servers"][$i]["route"] = (string) $route;
            }
            if (is_string($remote_dns)) {
                $array["servers"][$i]["remote_dns"] = (string) $remote_dns;
            }
        }
        if ($plugin && $plugin_opts) {
            $array["servers"][$i]["plugin"] = (string) $plugin;
            $array["servers"][$i]["plugin_opts"] = (string) $plugin_opts;
        } else {
            $udp_list[] = (int) $i;
        }
        if (is_array($android_list) and $client_type == "Android") {
            $array["servers"][$i]["proxy_apps"]["enabled"] = (bool) true;
            $array["servers"][$i]["proxy_apps"]["bypass"] = (bool) true;
            $array["servers"][$i]["proxy_apps"][
                "android_list"
            ] = (array) $android_list;
        }
        $array["servers"][$i]["bytes_used"] = (int) $used ?? 0;
        $array["servers"][$i]["bytes_remaining"] = (int) $total ?? 0;
        $bytes_upload += (int) $used + $used_traffic;
        $bytes_download += (int) $used + $used_traffic;
        #$bytes_total += (int) $total;
        $bytes_total += (int) $used + $used_traffic;
        $i++;
    }
}

if (isset($forward_list) and $add_best_ip == "true") {
    $ip_scanner_csv =
        file(
            $ini_array["URL"] . "/conf/best_ip.csv",
            FILE_SKIP_EMPTY_LINES,
            stream_context_create($arrContextOptions)
        ) ?? null;
    $i = count($array["servers"]);
    $rand_id = $forward_list[array_rand($forward_list, 1)];
    if (is_array($ip_scanner_csv) and $i > 0 and $rand_id > 0) {
        foreach ($ip_scanner_csv as $ip_scanner) {
            $csv_line = explode(",", $ip_scanner);
            array_walk($csv_line, "trim_value");
            if (is_numeric($csv_line[2])) {
                $array["servers"][$i] = (array) $array["servers"][$rand_id];
                $array["servers"][$i]["id"] = (string) guidv4();
                $array["servers"][$i]["remarks"] = (string) str_replace(
                    "中国 ",
                    "",
                    $csv_line[0]
                );
                $array["servers"][$i]["server"] = (string) $csv_line[1];
                $i++;
            }
        }
    }
}

//https://stackoverflow.com/a/4414669
if (isset($udp_list) and $client_type == "Android") {
    $i = 0;
    foreach ($array["servers"] as $item1) {
        $a = $array["servers"][$i]["server_port"];
        foreach ($udp_list as $item2) {
            $b = $array["servers"][$item2]["server_port"];
            if (is_numeric($a) && is_numeric($b) && $a != $b) {
                $array["servers"][$i]["udpdns"] = (bool) true;
                $array["servers"][$i]["udp_fallback"] = (array) [
                    "server" => (string) $array["servers"][$item2]["server"],
                    "server_port" =>
                        (int) $array["servers"][$item2]["server_port"],
                    "password" =>
                        (string) $array["servers"][$item2]["password"],
                    "method" => (string) $array["servers"][$item2]["method"],
                ];
            }
        }
        $i++;
    }
}

header(
    "Subscription-Userinfo: upload=" .
        0 .
        "; download=" .
        0 .
        "; total=" .
        $bytes_total .
        "; expire=" .
        time()
); //
die(str_replace('\n', "", json_encode($array, JSON_NUMERIC_CHECK))); //需要去除证书换行\n否则出错
?>
