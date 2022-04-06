#!/usr/bin/env bash

#   Инфа скачивания и запуска скрипта в Ubuntu 20.04
#   wget https://raw.githubusercontent.com/roman82101/s/1/s.sh
#   chmod +x s.sh
#   ./s.sh install 2>&1

#   Мои данные серевера изменённые в скрипте Shadowsocks
#	shadowsocks_method="chacha20-ietf-poly1305"
#	shadowsocks_port="8080"
#	shadowsocks_fastopen="true"
#	"nameserver":"127.0.0.1",

#   Мои данные серевера изменённые в скрипте OpenVPN
#	IPV6_SUPPORT ="n"
#	PORT="1194"
#	PROTOCOL="udp"
#	DNS="1"
#	COMPRESSION_ENABLED="n"
#	CUSTOMIZE_ENC="n"


echo "... Удаление пользователя temp ..."
deluser --remove-home temp


echo "... Изменить пароль ..."
passwd


echo "... Установка программ ..."
apt install -y ufw htop nethogs iftop fail2ban python3-requests git curl dnsutils


echo "... Настройка ufw ..."
ufw default deny incoming
ufw default allow outgoing
ufw allow 22
ufw allow 8080
ufw allow 1194
ufw allow 53
ufw allow 80
ufw allow 3000
#echo "... Блокировка подозрителных IP ..."
ufw deny from 59.83.229.31 to any
ufw deny from 131.159.25.7 to any
ufw deny from 162.142.125.221 to any
ufw deny from 162.142.125.132 to any
ufw deny from 192.87.173.56 to any
ufw deny from 141.22.28.227 to any
ufw enable


echo "... Oтключить IPv6 ..."
echo 'net.ipv6.conf.all.disable_ipv6 = 1' >> /etc/sysctl.conf
echo 'net.ipv6.conf.default.disable_ipv6 = 1' >> /etc/sysctl.conf
echo 'net.ipv6.conf.lo.disable_ipv6 = 1' >> /etc/sysctl.conf
sysctl -p


echo "... Oтключить PasswordAuthentication ..."
sed -i 's/.*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config


echo "... Установка ufw-bots ..."
wget https://raw.githubusercontent.com/brahma-dev/ufw-bots/master/files/ufw.sh
echo "... Удалить IP Белтелекома ..."
sed '/ 37.212.*.0/d;/ 37.45.*.0/d' ufw.sh > ufw-m.sh
chmod +x ufw-m.sh
./ufw-m.sh
rm -f ufw.sh ufw-m.sh


echo "... Установка Shadowsocks ..."
# shadowsocks.sh - a CLI Bash script to install shadowsocks server automatic for Debian / Ubuntu

# Copyright (c) 2016-2018 Wave WorkShop <waveworkshop@outlook.com>

#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.

scriptVersion="3.0.3"
scriptDate="20201130"

clear
echo
echo "............................................................#"
echo "# shadowsocks python server install for Debian / Ubuntu     #"
echo "# Thanks: @clowwindy <https://twitter.com/clowwindy>        #"
echo "# Author: Wave WorkShop <waveworkshop@outlook.com>          #"
echo "# Github: https://github.com/shadowsocks/shadowsocks        #"
echo "............................................................#"
echo

# Set color
RED="\033[31;1m"
GREEN="\033[32;1m"
YELLOW="\033[33;1m"
BLUE="\033[34;1m"
PURPLE="\033[35;1m"
CYAN="\033[36;1m"
PLAIN="\033[0m"

# Info messages
FAIL="${RED}[FAIL]${PLAIN}"
DONE="${GREEN}[DONE]${PLAIN}"
ERROR="${RED}[ERROR]${PLAIN}"
WARNING="${YELLOW}[WARNING]${PLAIN}"
CANCEL="${CYAN}[CANCEL]${PLAIN}"

# Font Format
BOLD="\033[1m"
UNDERLINE="\033[4m"

# Current folder
cur_dir=`pwd`

# Make sure root user
rootNess(){
    if [[ $EUID -ne 0 ]]; then
        echo -e "${WARNING} MUST RUN AS ${RED}ROOT${PLAIN} USER!"
        exit 1
    fi
}

# Get public IP address
get_ip(){
    local IP=$( ip addr | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | egrep -v "^192\.168|^172\.1[6-9]\.|^172\.2[0-9]\.|^172\.3[0-2]\.|^10\.|^127\.|^255\.|^0\." | head -n 1 )
    [ -z ${IP} ] && IP=$( wget -qO- -t1 -T2 ipv4.icanhazip.com )
    [ -z ${IP} ] && IP=$( wget -qO- -t1 -T2 ipinfo.io/ip )
    [ ! -z ${IP} ] && echo ${IP} || echo
}

get_char(){
    SAVEDSTTY=`stty -g`
    stty -echo
    stty cbreak
    dd if=/dev/tty bs=1 count=1 2> /dev/null
    stty -raw
    stty echo
    stty $SAVEDSTTY
}

# Configure shadowsocks setting
setupProfile(){
    # Set shadowsocks config password
    echo "Please input password for shadowsocks:"
    echo "default: material"
    read shadowsocks_passwd
    [ -z "${shadowsocks_passwd}" ] && shadowsocks_passwd="material"
    echo
    echo "---------------------------"
    echo "password = ${shadowsocks_passwd}"
    echo "---------------------------"
    echo
    # Set shadowsocks encryption method
    shadowsocks_method="chacha20-ietf-poly1305"
    # Set shadowsocks config port
    shadowsocks_port="8080"
    # Set TCP Fast Open for shadowsocks
    shadowsocks_fastopen="true"
    # Install necessary dependencies
    apt -y update
    apt -y install curl wget unzip gcc swig automake make perl cpio build-essential
    if [ $DEPMARK -ne 0 ]; then
        apt -y install python2 python2-dev libssl-dev
        curl https://bootstrap.pypa.io/pip/2.7/get-pip.py --output get-pip.py
        python2 get-pip.py
        pip2 install setuptools m2crypto
    else
        apt -y install python python-dev python-pip python-setuptools python-m2crypto
    fi
    # Return Home
    cd ${cur_dir}
}

# Download files
downloadFiles(){
    # Download file
    if [ ! -f LATEST.tar.gz ]; then
        if ! wget --no-check-certificate https://download.libsodium.org/libsodium/releases/LATEST.tar.gz; then
            echo "Failed to download libsodium file!"
        fi
    fi
    if [ ! -f master.zip ]; then
        if ! wget --no-check-certificate https://github.com/shadowsocks/shadowsocks/archive/master.zip; then
            echo "Failed to download shadowsocks python file!"
        fi
    fi
    if [ ! -f /etc/init.d/shadowsocks ]; then
        if ! wget --no-check-certificate https://raw.githubusercontent.com/wavengine/shadowsocks-install/master/shadowsocks -O /etc/init.d/shadowsocks; then
            echo "Failed to download shadowsocks daemon file!"
        fi
    fi
}

# Write shadowsocks config
writeProfile(){
    cat > /etc/shadowsocks.json<<-EOF
{
    "server":"0.0.0.0",
    "server_port":${shadowsocks_port},
    "password":"${shadowsocks_passwd}",
    "timeout":300,
    "method":"${shadowsocks_method}",
    "nameserver":"127.0.0.1",
    "fast_open":${shadowsocks_fastopen}
}
EOF
}

# Install shadowsocks
programInstall(){
    # Install libsodium
    tar xf LATEST.tar.gz
    pushd libsodium-stable
    ./configure && make -j2 && make install
    if [ $? -ne 0 ]; then
        echo -e "${FAIL}libsodium install failed!"
        cleanUp
        exit 1
    fi
    ldconfig
    popd
    # Install shadowsocks
    cd ${cur_dir}
    unzip -q master.zip
    if [ $? -ne 0 ]; then
        echo -e "${FAIL} unzip master.zip failed!"
        cleanUp
        exit 1
    fi

    cd ${cur_dir}/shadowsocks-master
    python2 setup.py install --record /usr/local/shadowsocks_install.log

    if [ -f /usr/bin/ssserver ] || [ -f /usr/local/bin/ssserver ]; then
        chmod +x /etc/init.d/shadowsocks
        update-rc.d -f shadowsocks defaults
        /etc/init.d/shadowsocks start
    else
        echo -e "${FAIL} shadowsocks install failed! please email error log to ${RED}waveworkshop@outlook.com${PLAIN}."
        cleanUp
        exit 1
    fi
    printf "shadowsocks server installing..."
    sleep 1
    clear
    echo
    echo -e "#-----------------------------------------------------#"
    echo -e "#         ${CYAN}Server${PLAIN}: ${RED} $(get_ip) ${PLAIN}"
    echo -e "#           ${CYAN}Port${PLAIN}: ${RED} $shadowsocks_port ${PLAIN}"
    echo -e "#       ${CYAN}Password${PLAIN}: ${RED} $shadowsocks_passwd ${PLAIN}"
    echo -e "# ${CYAN}Encrypt Method${PLAIN}: ${RED} $shadowsocks_method ${PLAIN}"
    echo -e "#   ${CYAN}TCP FastOpen${PLAIN}: ${RED} $shadowsocks_fastopen ${PLAIN}"
    echo -e "#-----------------------------------------------------#"
    echo
}

# Cleanup install files
cleanUp(){
    cd ${cur_dir}
    rm -rf master.zip LATEST.tar.gz shadowsocks-master libsodium-stable
}

# Optimize the shadowsocks server on Linux
optimizeShadowsocks(){
    # Step 1, First of all, make sure your Linux kernel is 3.5 or later please.
    local LIMVER1=3
    local LIMVER2=5
    # Step 2, Extract kernel value
    local COREVER1=$(echo $COREVER | awk -F '.' '{print $1}')
    local COREVER2=$(echo $COREVER | awk -F '.' '{print $2}')
    # Step 3, increase the maximum number of open file descriptors
    if [ `echo "$COREVER1 >= $LIMVER1" | bc` -eq 1 ]; then
        if [ `echo "$COREVER2 >= $LIMVER2" | bc` -eq 1 ]; then
            # Backup default file
            cp -a /etc/security/limits.conf /etc/security/limits.conf.bak
            # To handle thousands of current TCP connections, we should increase the limit of file descriptors opened.
            echo -e "* soft nofile 51200 \n* hard nofile 51200" >> /etc/security/limits.conf
            # Set the ulimit
            ulimit -n 51200
        else
            echo "Linux kernel not support"
        fi
    else
        exit 1
    fi
    # Step 4, To use BBR, make sure your Linux kernel is 4.9 or later please.
    local TCP_BBR1=4
    local TCP_BBR2=9
    # Step 5, Tune the kernel parameters
    if [ `echo "$COREVER1 >= $TCP_BBR1" | bc` -eq 1 ]; then
        if [ `echo "$COREVER2 >= $TCP_BBR2" | bc` -eq 1 ]; then
            # Backup default file
            cp -a /etc/sysctl.conf /etc/sysctl.conf.bak
            # Use Google BBR
            cat >> /etc/sysctl.conf <<'EOF'
fs.file-max = 51200
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.netdev_max_backlog = 250000
net.core.somaxconn = 4096
net.core.default_qdisc = fq
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_tw_recycle = 0
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.ip_local_port_range = 10000 65000
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_max_tw_buckets = 5000
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mem = 25600 51200 102400
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_congestion_control = bbr
EOF
        else
            # The priciples of tuning parameters for shadowsocks are
            # 1.Reuse ports and conections as soon as possible.
            # 2.Enlarge the queues and buffers as large as possible.
            # 3.Choose the TCP congestion algorithm for large latency and high throughput.
            cat >> /etc/sysctl.conf <<'EOF'
fs.file-max = 51200
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.netdev_max_backlog = 250000
net.core.somaxconn = 4096
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_tw_recycle = 0
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.ip_local_port_range = 10000 65000
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_max_tw_buckets = 5000
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mem = 25600 51200 102400
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_congestion_control = hybla
EOF
        fi
        # reload the config at runtime.
        sysctl -p 1> /dev/null
    else
        echo "The kernel ($COREVER1.$COREVER2)is too old, can not use BBR. Use hybla "
    fi
}

# Display Help info
displayHelp(){
    echo -e "${UNDERLINE}Usage${PLAIN}:"
    echo -e "  $0 [OPTIONAL FLAGS]"
    echo
    echo -e "shadowsocks.sh - a CLI Bash script to install shadowsocks server automatic for Debian / Ubuntu."
    echo
    echo -e "${UNDERLINE}Options${PLAIN}:"
    echo -e "   ${BOLD}-i, --install${PLAIN}      Install shadowsocks."
    echo -e "   ${BOLD}-u, --uninstall${PLAIN}    Uninstall shadowsocks."
    echo -e "   ${BOLD}-v, --version${PLAIN}      Display current script version."
    echo -e "   ${BOLD}-h, --help${PLAIN}         Display this help."
    echo
    echo -e "${UNDERLINE}shadowsocks.sh${PLAIN} - Version ${scriptVersion} "
    echo -e "Modify Date ${scriptDate}"
    echo -e "Created by and licensed to WaveWorkShop <waveworkshop@outlook.com>"
}

# Uninstall Shadowsocks
uninstallShadowsocks(){
    echo -e "${WARNING} Are you sure uninstall shadowsocks and libsodium? (y/n) "
    read -p "(Default: n):" answer
    [ -z ${answer} ] && answer="n"
    if [ "${answer}" == "y" ] || [ "${answer}" == "Y" ]; then
        ps -ef | grep -v grep | grep -i "ssserver" > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            /etc/init.d/shadowsocks stop
        fi
        # Remove daemon
        update-rc.d -f shadowsocks remove
        # Restore system config
        if [ -f /etc/security/limits.conf.bak ]; then
            rm -f /etc/security/limits.conf
            mv /etc/security/limits.conf.bak /etc/security/limits.conf
        fi
        if [ -f /etc/sysctl.conf.bak ]; then
            rm -f /etc/sysctl.conf
            mv /etc/sysctl.conf.bak /etc/sysctl.conf
        fi
        # Delete config file and log file
        rm -f /etc/shadowsocks.json
        rm -f /var/run/shadowsocks.pid
        rm -f /etc/init.d/shadowsocks
        rm -f /var/log/shadowsocks.log
        if [ -f /usr/local/shadowsocks_install.log ]; then
            cat /usr/local/shadowsocks_install.log | xargs rm -rf
        fi
        # Uninstall libsodium(can case other issues)
        if [ -d libsodium-stable ]; then
            cd libsodium-stable
            make && make uninstall
        else
            echo "no directory. can not uninstall libsodium."
        fi
        echo "shadowsocks uninstall success! "
    else
        echo -e "${CANCEL}Cancelled, nothing to do. "
    fi
}

# Install main function
installShadowsocks(){
    setupProfile
    downloadFiles
    writeProfile
    programInstall
    cleanUp
}

# Distro Detection
type apt >/dev/null 2>&1
if [ $? -eq 0 ];then
    # necessary depend μ
    apt -y install bc lsb-release
else
    if [ -s /etc/redhat-release ]; then
        if [ -s /etc/centos-release ]; then
            CENTOSVER=$(rpm -q centos-release | cut -d- -f3)
            clear
            echo -e "${ERROR} ${GREEN}CentOS${PLAIN} ${GREEN}${CENTOSVER}${PLAIN} is not supported. Please reinstall to Debian / Ubuntu and try again."
            exit 1
        else
            RADHATVER=$(cat /etc/redhat-release | sed -r 's/.* ([0-9]+)\..*/\1/')
            clear
            echo -e "${ERROR} ${GREEN}RedHat${PLAIN} ${GREEN}${RADHATVER}${PLAIN} is not supported. Please reinstall to Debian / Ubuntu and try again."
            exit 1
        fi
    fi
fi

# OS
OSID=$(grep ^ID= /etc/os-release | cut -d= -f2)
OSVER=$(lsb_release -cs)
OSNUM=$(grep -oE  "[0-9.]+" /etc/issue)
COREVER=$(uname -r | grep -Eo '[0-9].[0-9]+' | sed -n '1,1p')
MEMKB=$(cat /proc/meminfo | grep MemTotal | awk -F':' '{print $2}' | grep -o '[0-9]\+')
MEMMB=$(expr $MEMKB / 1024)
MEMGB=$(expr $MEMMB / 1024)
INSMARK=0
DEPMARK=0

# Debian & Ubuntu
case "$OSVER" in
    wheezy)
        # Debian 7.0 wheezy
        INSMARK=1
        ;;
    jessie)
        # Debian 8.0 jessie
        INSMARK=1
        ;;
    stretch)
        # Debian 9.0 stretch
        INSMARK=1
        ;;
    buster)
        # Debian 10.0 buster
        INSMARK=1
        ;;
    trusty)
        # Ubuntu 14.04 trusty LTS
        INSMARK=1
        ;;
    xenial)
        # Ubuntu 16.04 xenial LTS
        INSMARK=1
        ;;
    bionic)
        # Ubuntu 18.04 bionic LTS
        INSMARK=1
        ;;
    focal)
        # Ubuntu 20.04 focal LTS
        INSMARK=1
        DEPMARK=2
        ;;
    *)
        echo -e "${ERROR} Sorry,$OSID $OSVER is too old or unsupport, please update to retry."
        exit 1
        ;;
esac

echo -e "............................................................#"
echo -e "#       ${RED}OS${PLAIN}: $OSID $OSNUM $OSVER "
echo -e "#   ${RED}Kernel${PLAIN}: $(uname -m) Linux $(uname -r)"
echo -e "#      ${RED}CPU${PLAIN}: $(grep 'model name' /proc/cpuinfo | uniq | awk -F : '{print $2}' | sed 's/^[ \t]*//g' | sed 's/ \+/ /g') "
echo -e "#      ${RED}RAM${PLAIN}: $(cat /proc/meminfo | grep 'MemTotal' | awk -F : '{print $2}' | sed 's/^[ \t]*//g') "
echo -e "............................................................#"
echo

# Initialization step
case "$1" in
    install|-i|--install)
        rootNess
        if [ $INSMARK -eq 1 ]; then
            installShadowsocks
        fi
        optimizeShadowsocks
        ;;
    uninstall|-u|--uninstall)
        rootNess
        uninstallShadowsocks
        ;;
    *)
        clear
        displayHelp
        exit 0
        ;;
esac


echo "... Загрузка OpenVPN ..."
wget https://raw.githubusercontent.com/angristan/openvpn-install/master/openvpn-install.sh
chmod +x openvpn-install.sh


echo "... Установка AdGuardHome ..."
curl -s -S -L https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/scripts/install.sh | sh -s -- -v
#echo "... Добавление локального DNS в Shadowsocks ..."
#sed -i 's/.*nameserver.*/"nameserver": "127.0.0.1",/' /etc/shadowsocks.json
echo "... Добавление локального DNS в Ubuntu ..."
sed -i 's/^DNS=.*/DNS=127.0.0.1/;s/.*SStubListener=.*/DNSStubListener=no/' /etc/systemd/resolved.conf


echo "... Установка noisy ..."
git clone https://github.com/1tayH/noisy.git
cd noisy
rm -f config.json
echo "... Получить свежий список user_agents ..."
wget 'https://olegon.ru/user_agents.txt'
echo "... Редактирование списка user_agents ..."
sed -rn '/^.{110,200}$/p' user_agents.txt > tmp1
sed '/compatible/d;/NetSystemsResearch/d;/com.google.android/d;/Valve/d;/Chrome*\/1/d;/Chrome*\/2/d;/Chrome*\/3/d;/Chrome*\/4/d;/Chrome*\/5/d;/Chrome*\/6/d;/Chrome*\/7/d;/Chrome*\/8/d;s/^/"/;s/$/",/' tmp1 > tmp2
sort -R tmp2 > user_agents
echo "... Создание config для noisy ..."
echo '{' > /root/noisy/config
echo '    "max_depth": 25,' >> /root/noisy/config
echo '    "min_sleep": 3,' >> /root/noisy/config
echo '    "max_sleep": 6,' >> /root/noisy/config
echo '    "timeout": false,' >> /root/noisy/config
echo '    "root_urls": [' >> /root/noisy/config
echo '        "http://4chan.org",' >> /root/noisy/config
echo '        "https://www.reddit.com",' >> /root/noisy/config
echo '        "http://www.cnn.com",' >> /root/noisy/config
echo '        "https://pornhub.com",' >> /root/noisy/config
echo '        "https://yandex.ru",' >> /root/noisy/config
echo '        "https://baidu.com",' >> /root/noisy/config
echo '        "https://instagram.com",' >> /root/noisy/config
echo '        "https://xvideos.com",' >> /root/noisy/config
echo '        "https://ok.ru",' >> /root/noisy/config
echo '        "https://turbopages.org",' >> /root/noisy/config
echo '        "https://avito.ru",' >> /root/noisy/config
echo '        "https://wildberries.ru",' >> /root/noisy/config
echo '        "https://facebook.com",' >> /root/noisy/config
echo '        "https://gismeteo.ru",' >> /root/noisy/config
echo '        "https://kinopoisk.ru",' >> /root/noisy/config
echo '        "https://google.ru",' >> /root/noisy/config
echo '        "https://glavnoe.net",' >> /root/noisy/config
echo '        "https://ozon.ru",' >> /root/noisy/config
echo '        "https://market.yandex.ru",' >> /root/noisy/config
echo '        "https://gosuslugi.ru",' >> /root/noisy/config
echo '        "https://ria.ru",' >> /root/noisy/config
echo '        "https://lenta.ru",' >> /root/noisy/config
echo '        "https://rambler.ru",' >> /root/noisy/config
echo '        "https://rbc.ru",' >> /root/noisy/config
echo '        "https://news.mail.ru",' >> /root/noisy/config
echo '        "https://novostinedeli24.com",' >> /root/noisy/config
echo '        "https://rus-tv.su",' >> /root/noisy/config
echo '        "https://whatsapp.com",' >> /root/noisy/config
echo '        "https://twitter.com",' >> /root/noisy/config
echo '        "https://gdz.ru",' >> /root/noisy/config
echo '        "https://mk.ru",' >> /root/noisy/config
echo '        "https://ficbook.net",' >> /root/noisy/config
echo '        "https://drom.ru",' >> /root/noisy/config
echo '        "https://sberbank.ru",' >> /root/noisy/config
echo '        "https://kp.ru",' >> /root/noisy/config
echo '        "https://pikabu.ru",' >> /root/noisy/config
echo '        "https://greenfilm.vip",' >> /root/noisy/config
echo '        "https://music.yandex.ru",' >> /root/noisy/config
echo '        "https://livejournal.com",' >> /root/noisy/config
echo '        "https://mos.ru faviconmos.ru",' >> /root/noisy/config
echo '        "https://litnet.com",' >> /root/noisy/config
echo '        "https://hh.ru",' >> /root/noisy/config
echo '        "https://lentainform.com",' >> /root/noisy/config
echo '        "https://championat.com",' >> /root/noisy/config
echo '        "https://ssyoutube.com",' >> /root/noisy/config
echo '        "https://drive2.ru",' >> /root/noisy/config
echo '        "https://apple.com",' >> /root/noisy/config
echo '        "https://rutube.ru",' >> /root/noisy/config
echo '        "https://mail.rambler.ru",' >> /root/noisy/config
echo '        "https://bamper.by",' >> /root/noisy/config
echo '        "https://mail.ru",' >> /root/noisy/config
echo '        "https://onliner.by",' >> /root/noisy/config
echo '        "https://catalog.onliner.by",' >> /root/noisy/config
echo '        "https://kufar.by",' >> /root/noisy/config
echo '        "https://aliexpress.ru",' >> /root/noisy/config
echo '        "https://gdeposylka.ru",' >> /root/noisy/config
echo '        "https://skype.com",' >> /root/noisy/config
echo '        "https://gitlab.com",' >> /root/noisy/config
echo '        "https://4pda.ru",' >> /root/noisy/config
echo '        "https://2ip.ru",' >> /root/noisy/config
echo '        "https://playground.ru",' >> /root/noisy/config
echo '        "https://devices.sensor.community",' >> /root/noisy/config
echo '        "https://airly.org",' >> /root/noisy/config
echo '        "https://airmq.by",' >> /root/noisy/config
echo '        "https://charter97.org",' >> /root/noisy/config
echo '        "https://amazon.com",' >> /root/noisy/config
echo '        "https://vk.com",' >> /root/noisy/config
echo '        "https://tiktok.com",' >> /root/noisy/config
echo '        "https://twitch.tv",' >> /root/noisy/config
echo '        "https://microsoft.com",' >> /root/noisy/config
echo '        "https://bing.com",' >> /root/noisy/config
echo '        "https://fandom.com",' >> /root/noisy/config
echo '        "https://pinterest.com",' >> /root/noisy/config
echo '        "http://www.ebay.com",' >> /root/noisy/config
echo '        "https://wikipedia.org",' >> /root/noisy/config
echo '        "https://youtube.com",' >> /root/noisy/config
echo '        "https://github.com",' >> /root/noisy/config
echo '        "https://medium.com",' >> /root/noisy/config
echo '        "https://thepiratebay.org"' >> /root/noisy/config
echo '    ],' >> /root/noisy/config
echo '    "blacklisted_urls": [' >> /root/noisy/config
echo '        "https://t.co",' >> /root/noisy/config
echo '        "t.umblr.com",' >> /root/noisy/config
echo '        "messenger.com",' >> /root/noisy/config
echo '        "itunes.apple.com",' >> /root/noisy/config
echo '        "l.facebook.com",' >> /root/noisy/config
echo '        "bit.ly",' >> /root/noisy/config
echo '        "mediawiki",' >> /root/noisy/config
echo '        ".css",' >> /root/noisy/config
echo '        ".ico",' >> /root/noisy/config
echo '        ".xml",' >> /root/noisy/config
echo '        "intent/tweet",' >> /root/noisy/config
echo '        "twitter.com/share",' >> /root/noisy/config
echo '        "dialog/feed?",' >> /root/noisy/config
echo '        ".json",' >> /root/noisy/config
echo '        "zendesk",' >> /root/noisy/config
echo '        "clickserve",' >> /root/noisy/config
echo '        ".png",' >> /root/noisy/config
echo '        ".iso"' >> /root/noisy/config
echo '    ],' >> /root/noisy/config
echo '    "user_agents": [' >> /root/noisy/config
echo '"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/601.7.7 (KHTML, like Gecko) Version/9.1.2 Safari/601.7.7",' >> /root/noisy/config
echo '"Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.174 YaBrowser/22.1.3.850 Yowser/2.5 Safari/537.36"' >> /root/noisy/config
echo '    ]' >> /root/noisy/config
echo '}' >> /root/noisy/config
echo "... Слияние user_agents и config ..."
sed -e '/Intel Mac OS X 10_11_6/r./user_agents' config > config.json
rm -f user_agents.txt tmp1 tmp2 config user_agents

#echo ... Создание скрипта start-n0isy.sh ...
#echo -n "#!" > /root/noisy/start-n0isy.sh
#echo "/bin/sh" >> /root/noisy/start-n0isy.sh
#echo -n 'if [ -z "' >> /root/noisy/start-n0isy.sh
#echo -n '$' >> /root/noisy/start-n0isy.sh
#echo '(pgrep -f [n]oisy)" ]' >> /root/noisy/start-n0isy.sh
#echo "then {" >> /root/noisy/start-n0isy.sh
#echo -n '        echo ' >> /root/noisy/start-n0isy.sh
#echo -n '$' >> /root/noisy/start-n0isy.sh
#echo '(date +%Y-%m-%d:%k:%M:%S) "Running Noisy" >> /var/log/noisy.log' >> /root/noisy/start-n0isy.sh
#echo "        sleep 1  #delay" >> /root/noisy/start-n0isy.sh
#echo "        /usr/bin/python3 /root/noisy/noisy.py --config /root/noisy/config.json" >> /root/noisy/start-n0isy.sh
#echo "        exit 1" >> /root/noisy/start-n0isy.sh
#echo -n "}" >> /root/noisy/start-n0isy.sh
#echo -n " else " >> /root/noisy/start-n0isy.sh
#echo "{" >> /root/noisy/start-n0isy.sh
#echo -n '        echo ' >> /root/noisy/start-n0isy.sh
#echo -n '$' >> /root/noisy/start-n0isy.sh
#echo '"EXIT. Noisy already running!"' >> /root/noisy/start-n0isy.sh
#echo "        exit 1" >> /root/noisy/start-n0isy.sh
#echo "}" >> /root/noisy/start-n0isy.sh
#echo "fi" >> /root/noisy/start-n0isy.sh
#chmod +x /root/noisy/start-n0isy.sh

echo "... Добавление noisy в cron ..."
sed -i '$ d' /etc/crontab
echo "0 * * * *   root    if [ -z "$(pgrep -f [n]oisy)" ]; then { echo $(date +%Y-%m-%d:%k:%M:%S) "Running Noisy" >> /var/log/noisy.log; sleep 1; /usr/bin/python3 /root/noisy/noisy.py --config /root/noisy/config.json; exit 1; } else { echo $(date +%Y-%m-%d:%k:%M:%S) "EXIT. Noisy already running!" >> /var/log/noisy.log; exit 1; } fi" >> /etc/crontab
echo "@reboot   root    /usr/bin/python3 /root/noisy/noisy.py --config /root/noisy/config.json" >> /etc/crontab
echo "#" >> /etc/crontab
cd ..


echo -n "...Добавить команды в bash_history? ... (y/n) "
read item
case "$item" in
    y|Y) echo "... Добавление команд в bash_history ..."
        sed -i 'd' /root/.bash_history
        echo "apt update && apt upgrade -y" > /root/.bash_history
        echo "apt clean && apt autoclean" >> /root/.bash_history
        echo "./openvpn-install.sh" >> /root/.bash_history
        echo "nethogs" >> /root/.bash_history
        echo "iftop -P" >> /root/.bash_history
        echo "htop" >> /root/.bash_history
        echo "exit" >> /root/.bash_history
        ;;
    n|N) echo "... Ввели «n», пропускаем добавление команд ..."
        ;;
    *) echo "... Ничего не ввели. Пропускаем добавление команд ..."
        ;;
esac


echo "... Перезагрузка ..."
read -n 1 -s -r -p "Press any key to reboot"
rm -f s.sh
reboot
