#!/usr/bin/env bash

#   Инфа скачивания и запуска скрипта в Ubuntu 20.04
#   wget https://raw.githubusercontent.com/roman82101/s/1/s.sh
#   chmod +x s.sh
#   ./s.sh 2>&1

#   Мои данные серевера изменённые в скрипте Shadowsocks
    # Set shadowsocks encryption method
#    shadowsocks_method="chacha20-ietf-poly1305"
    # Set shadowsocks config port
#    shadowsocks_port="8080"
    # Set TCP Fast Open for shadowsocks
#    shadowsocks_fastopen="true"

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
echo "... Блокировка подозрителных IP ..."
ufw deny from 59.83.229.31 to any
ufw enable


echo "... Oтключить IPv6 ..."
echo 'net.ipv6.conf.all.disable_ipv6 = 1' >> /etc/sysctl.conf
echo 'net.ipv6.conf.default.disable_ipv6 = 1' >> /etc/sysctl.conf
echo 'net.ipv6.conf.lo.disable_ipv6 = 1' >> /etc/sysctl.conf
sysctl -p


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
echo "#############################################################"
echo "# shadowsocks python server install for Debian / Ubuntu     #"
echo "# Thanks: @clowwindy <https://twitter.com/clowwindy>        #"
echo "# Author: Wave WorkShop <waveworkshop@outlook.com>          #"
echo "# Github: https://github.com/shadowsocks/shadowsocks        #"
echo "#############################################################"
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

echo -e "#############################################################"
echo -e "#       ${RED}OS${PLAIN}: $OSID $OSNUM $OSVER "
echo -e "#   ${RED}Kernel${PLAIN}: $(uname -m) Linux $(uname -r)"
echo -e "#      ${RED}CPU${PLAIN}: $(grep 'model name' /proc/cpuinfo | uniq | awk -F : '{print $2}' | sed 's/^[ \t]*//g' | sed 's/ \+/ /g') "
echo -e "#      ${RED}RAM${PLAIN}: $(cat /proc/meminfo | grep 'MemTotal' | awk -F : '{print $2}' | sed 's/^[ \t]*//g') "
echo -e "#############################################################"
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


echo "... Установка OpenVPN ..."
# shellcheck disable=SC1091,SC2164,SC2034,SC1072,SC1073,SC1009
# Secure OpenVPN server installer for Debian, Ubuntu, CentOS, Amazon Linux 2, Fedora, Oracle Linux 8, Arch Linux, Rocky Linux and AlmaLinux.
# https://github.com/angristan/openvpn-install

function isRoot() {
	if [ "$EUID" -ne 0 ]; then
		return 1
	fi
}

function tunAvailable() {
	if [ ! -e /dev/net/tun ]; then
		return 1
	fi
}

function checkOS() {
	if [[ -e /etc/debian_version ]]; then
		OS="debian"
		source /etc/os-release

		if [[ $ID == "debian" || $ID == "raspbian" ]]; then
			if [[ $VERSION_ID -lt 9 ]]; then
				echo "⚠️ Your version of Debian is not supported."
				echo ""
				echo "However, if you're using Debian >= 9 or unstable/testing then you can continue, at your own risk."
				echo ""
				until [[ $CONTINUE =~ (y|n) ]]; do
					read -rp "Continue? [y/n]: " -e CONTINUE
				done
				if [[ $CONTINUE == "n" ]]; then
					exit 1
				fi
			fi
		elif [[ $ID == "ubuntu" ]]; then
			OS="ubuntu"
			MAJOR_UBUNTU_VERSION=$(echo "$VERSION_ID" | cut -d '.' -f1)
			if [[ $MAJOR_UBUNTU_VERSION -lt 16 ]]; then
				echo "⚠️ Your version of Ubuntu is not supported."
				echo ""
				echo "However, if you're using Ubuntu >= 16.04 or beta, then you can continue, at your own risk."
				echo ""
				until [[ $CONTINUE =~ (y|n) ]]; do
					read -rp "Continue? [y/n]: " -e CONTINUE
				done
				if [[ $CONTINUE == "n" ]]; then
					exit 1
				fi
			fi
		fi
	elif [[ -e /etc/system-release ]]; then
		source /etc/os-release
		if [[ $ID == "fedora" || $ID_LIKE == "fedora" ]]; then
			OS="fedora"
		fi
		if [[ $ID == "centos" || $ID == "rocky" || $ID == "almalinux" ]]; then
			OS="centos"
			if [[ ! $VERSION_ID =~ (7|8) ]]; then
				echo "⚠️ Your version of CentOS is not supported."
				echo ""
				echo "The script only support CentOS 7 and CentOS 8."
				echo ""
				exit 1
			fi
		fi
		if [[ $ID == "ol" ]]; then
			OS="oracle"
			if [[ ! $VERSION_ID =~ (8) ]]; then
				echo "Your version of Oracle Linux is not supported."
				echo ""
				echo "The script only support Oracle Linux 8."
				exit 1
			fi
		fi
		if [[ $ID == "amzn" ]]; then
			OS="amzn"
			if [[ $VERSION_ID != "2" ]]; then
				echo "⚠️ Your version of Amazon Linux is not supported."
				echo ""
				echo "The script only support Amazon Linux 2."
				echo ""
				exit 1
			fi
		fi
	elif [[ -e /etc/arch-release ]]; then
		OS=arch
	else
		echo "Looks like you aren't running this installer on a Debian, Ubuntu, Fedora, CentOS, Amazon Linux 2, Oracle Linux 8 or Arch Linux system"
		exit 1
	fi
}

function initialCheck() {
	if ! isRoot; then
		echo "Sorry, you need to run this as root"
		exit 1
	fi
	if ! tunAvailable; then
		echo "TUN is not available"
		exit 1
	fi
	checkOS
}

function installUnbound() {
	# If Unbound isn't installed, install it
	if [[ ! -e /etc/unbound/unbound.conf ]]; then

		if [[ $OS =~ (debian|ubuntu) ]]; then
			apt-get install -y unbound

			# Configuration
			echo 'interface: 10.8.0.1
access-control: 10.8.0.1/24 allow
hide-identity: yes
hide-version: yes
use-caps-for-id: yes
prefetch: yes' >>/etc/unbound/unbound.conf

		elif [[ $OS =~ (centos|amzn|oracle) ]]; then
			yum install -y unbound

			# Configuration
			sed -i 's|# interface: 0.0.0.0$|interface: 10.8.0.1|' /etc/unbound/unbound.conf
			sed -i 's|# access-control: 127.0.0.0/8 allow|access-control: 10.8.0.1/24 allow|' /etc/unbound/unbound.conf
			sed -i 's|# hide-identity: no|hide-identity: yes|' /etc/unbound/unbound.conf
			sed -i 's|# hide-version: no|hide-version: yes|' /etc/unbound/unbound.conf
			sed -i 's|use-caps-for-id: no|use-caps-for-id: yes|' /etc/unbound/unbound.conf

		elif [[ $OS == "fedora" ]]; then
			dnf install -y unbound

			# Configuration
			sed -i 's|# interface: 0.0.0.0$|interface: 10.8.0.1|' /etc/unbound/unbound.conf
			sed -i 's|# access-control: 127.0.0.0/8 allow|access-control: 10.8.0.1/24 allow|' /etc/unbound/unbound.conf
			sed -i 's|# hide-identity: no|hide-identity: yes|' /etc/unbound/unbound.conf
			sed -i 's|# hide-version: no|hide-version: yes|' /etc/unbound/unbound.conf
			sed -i 's|# use-caps-for-id: no|use-caps-for-id: yes|' /etc/unbound/unbound.conf

		elif [[ $OS == "arch" ]]; then
			pacman -Syu --noconfirm unbound

			# Get root servers list
			curl -o /etc/unbound/root.hints https://www.internic.net/domain/named.cache

			if [[ ! -f /etc/unbound/unbound.conf.old ]]; then
				mv /etc/unbound/unbound.conf /etc/unbound/unbound.conf.old
			fi

			echo 'server:
	use-syslog: yes
	do-daemonize: no
	username: "unbound"
	directory: "/etc/unbound"
	trust-anchor-file: trusted-key.key
	root-hints: root.hints
	interface: 10.8.0.1
	access-control: 10.8.0.1/24 allow
	port: 53
	num-threads: 2
	use-caps-for-id: yes
	harden-glue: yes
	hide-identity: yes
	hide-version: yes
	qname-minimisation: yes
	prefetch: yes' >/etc/unbound/unbound.conf
		fi

		# IPv6 DNS for all OS
		if [[ $IPV6_SUPPORT == 'y' ]]; then
			echo 'interface: fd42:42:42:42::1
access-control: fd42:42:42:42::/112 allow' >>/etc/unbound/unbound.conf
		fi

		if [[ ! $OS =~ (fedora|centos|amzn|oracle) ]]; then
			# DNS Rebinding fix
			echo "private-address: 10.0.0.0/8
private-address: fd42:42:42:42::/112
private-address: 172.16.0.0/12
private-address: 192.168.0.0/16
private-address: 169.254.0.0/16
private-address: fd00::/8
private-address: fe80::/10
private-address: 127.0.0.0/8
private-address: ::ffff:0:0/96" >>/etc/unbound/unbound.conf
		fi
	else # Unbound is already installed
		echo 'include: /etc/unbound/openvpn.conf' >>/etc/unbound/unbound.conf

		# Add Unbound 'server' for the OpenVPN subnet
		echo 'server:
interface: 10.8.0.1
access-control: 10.8.0.1/24 allow
hide-identity: yes
hide-version: yes
use-caps-for-id: yes
prefetch: yes
private-address: 10.0.0.0/8
private-address: fd42:42:42:42::/112
private-address: 172.16.0.0/12
private-address: 192.168.0.0/16
private-address: 169.254.0.0/16
private-address: fd00::/8
private-address: fe80::/10
private-address: 127.0.0.0/8
private-address: ::ffff:0:0/96' >/etc/unbound/openvpn.conf
		if [[ $IPV6_SUPPORT == 'y' ]]; then
			echo 'interface: fd42:42:42:42::1
access-control: fd42:42:42:42::/112 allow' >>/etc/unbound/openvpn.conf
		fi
	fi

	systemctl enable unbound
	systemctl restart unbound
}

function installQuestions() {
	echo "Welcome to the OpenVPN installer!"
	echo "The git repository is available at: https://github.com/angristan/openvpn-install"
	echo ""

	echo "I need to ask you a few questions before starting the setup."
	echo "You can leave the default options and just press enter if you are ok with them."
	echo ""
	echo "I need to know the IPv4 address of the network interface you want OpenVPN listening to."
	echo "Unless your server is behind NAT, it should be your public IPv4 address."

	# Detect public IPv4 address and pre-fill for the user
	IP=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | head -1)

	if [[ -z $IP ]]; then
		# Detect public IPv6 address
		IP=$(ip -6 addr | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | head -1)
	fi
	APPROVE_IP=${APPROVE_IP:-n}
	# If $IP is a private IP address, the server must be behind NAT
	if echo "$IP" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
		echo ""
		echo "It seems this server is behind NAT. What is its public IPv4 address or hostname?"
		echo "We need it for the clients to connect to the server."

		PUBLICIP=$(curl -s https://api.ipify.org)
	fi

	echo ""
	echo "Checking for IPv6 connectivity..."
	echo ""
	# "ping6" and "ping -6" availability varies depending on the distribution
	if type ping6 >/dev/null 2>&1; then
		PING6="ping6 -c3 ipv6.google.com > /dev/null 2>&1"
	else
		PING6="ping -6 -c3 ipv6.google.com > /dev/null 2>&1"
	fi
	if eval "$PING6"; then
		echo "Your host appears to have IPv6 connectivity."
		SUGGESTION="y"
	else
		echo "Your host does not appear to have IPv6 connectivity."
		SUGGESTION="n"
	fi

	IPV6_SUPPORT ="n"
	PORT="1194"
	PROTOCOL="udp"
	DNS="1"
	COMPRESSION_ENABLED="n"
	CUSTOMIZE_ENC="n"
    
	if [[ $CUSTOMIZE_ENC == "n" ]]; then
		# Use default, sane and fast parameters
		CIPHER="AES-128-GCM"
		CERT_TYPE="1" # ECDSA
		CERT_CURVE="prime256v1"
		CC_CIPHER="TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"
		DH_TYPE="1" # ECDH
		DH_CURVE="prime256v1"
		HMAC_ALG="SHA256"
		TLS_SIG="1" # tls-crypt
	fi
}
function installOpenVPN() {
	if [[ $AUTO_INSTALL == "y" ]]; then
		# Set default choices so that no questions will be asked.
		APPROVE_INSTALL=${APPROVE_INSTALL:-y}
		APPROVE_IP=${APPROVE_IP:-y}
		IPV6_SUPPORT=${IPV6_SUPPORT:-n}
		PORT_CHOICE=${PORT_CHOICE:-1}
		PROTOCOL_CHOICE=${PROTOCOL_CHOICE:-1}
		DNS=${DNS:-1}
		COMPRESSION_ENABLED=${COMPRESSION_ENABLED:-n}
		CUSTOMIZE_ENC=${CUSTOMIZE_ENC:-n}
		CLIENT=${CLIENT:-client}
		PASS=${PASS:-1}
		CONTINUE=${CONTINUE:-y}
		# Behind NAT, we'll default to the publicly reachable IPv4/IPv6.
		if [[ $IPV6_SUPPORT == "y" ]]; then
			PUBLIC_IP=$(curl --retry 5 --retry-connrefused https://ifconfig.co)
		else
			PUBLIC_IP=$(curl --retry 5 --retry-connrefused -4 https://ifconfig.co)
		fi
		ENDPOINT=${ENDPOINT:-$PUBLIC_IP}
	fi
	# Run setup questions first, and set other variables if auto-install
	installQuestions
	# Get the "public" interface from the default route
	NIC=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
	if [[ -z $NIC ]] && [[ $IPV6_SUPPORT == 'y' ]]; then
		NIC=$(ip -6 route show default | sed -ne 's/^default .* dev \([^ ]*\) .*$/\1/p')
	fi
	# $NIC can not be empty for script rm-openvpn-rules.sh
	if [[ -z $NIC ]]; then
		echo
		echo "Can not detect public interface."
		echo "This needs for setup MASQUERADE."
		until [[ $CONTINUE =~ (y|n) ]]; do
			read -rp "Continue? [y/n]: " -e CONTINUE
		done
		if [[ $CONTINUE == "n" ]]; then
			exit 1
		fi
	fi
	# If OpenVPN isn't installed yet, install it. This script is more-or-less
	# idempotent on multiple runs, but will only install OpenVPN from upstream
	# the first time.
	if [[ ! -e /etc/openvpn/server.conf ]]; then
		if [[ $OS =~ (debian|ubuntu) ]]; then
			apt-get update
			apt-get -y install ca-certificates gnupg
			# We add the OpenVPN repo to get the latest version.
			if [[ $VERSION_ID == "16.04" ]]; then
				echo "deb http://build.openvpn.net/debian/openvpn/stable xenial main" >/etc/apt/sources.list.d/openvpn.list
				wget -O - https://swupdate.openvpn.net/repos/repo-public.gpg | apt-key add -
				apt-get update
			fi
			# Ubuntu > 16.04 and Debian > 8 have OpenVPN >= 2.4 without the need of a third party repository.
			apt-get install -y openvpn iptables openssl wget ca-certificates curl
		elif [[ $OS == 'centos' ]]; then
			yum install -y epel-release
			yum install -y openvpn iptables openssl wget ca-certificates curl tar 'policycoreutils-python*'
		elif [[ $OS == 'oracle' ]]; then
			yum install -y oracle-epel-release-el8
			yum-config-manager --enable ol8_developer_EPEL
			yum install -y openvpn iptables openssl wget ca-certificates curl tar policycoreutils-python-utils
		elif [[ $OS == 'amzn' ]]; then
			amazon-linux-extras install -y epel
			yum install -y openvpn iptables openssl wget ca-certificates curl
		elif [[ $OS == 'fedora' ]]; then
			dnf install -y openvpn iptables openssl wget ca-certificates curl policycoreutils-python-utils
		elif [[ $OS == 'arch' ]]; then
			# Install required dependencies and upgrade the system
			pacman --needed --noconfirm -Syu openvpn iptables openssl wget ca-certificates curl
		fi
		# An old version of easy-rsa was available by default in some openvpn packages
		if [[ -d /etc/openvpn/easy-rsa/ ]]; then
			rm -rf /etc/openvpn/easy-rsa/
		fi
	fi
	# Find out if the machine uses nogroup or nobody for the permissionless group
	if grep -qs "^nogroup:" /etc/group; then
		NOGROUP=nogroup
	else
		NOGROUP=nobody
	fi
	# Install the latest version of easy-rsa from source, if not already installed.
	if [[ ! -d /etc/openvpn/easy-rsa/ ]]; then
		local version="3.0.7"
		wget -O ~/easy-rsa.tgz https://github.com/OpenVPN/easy-rsa/releases/download/v${version}/EasyRSA-${version}.tgz
		mkdir -p /etc/openvpn/easy-rsa
		tar xzf ~/easy-rsa.tgz --strip-components=1 --directory /etc/openvpn/easy-rsa
		rm -f ~/easy-rsa.tgz
		cd /etc/openvpn/easy-rsa/ || return
		case $CERT_TYPE in
		1)
			echo "set_var EASYRSA_ALGO ec" >vars
			echo "set_var EASYRSA_CURVE $CERT_CURVE" >>vars
			;;
		2)
			echo "set_var EASYRSA_KEY_SIZE $RSA_KEY_SIZE" >vars
			;;
		esac
		# Generate a random, alphanumeric identifier of 16 characters for CN and one for server name
		SERVER_CN="cn_$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)"
		echo "$SERVER_CN" >SERVER_CN_GENERATED
		SERVER_NAME="server_$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)"
		echo "$SERVER_NAME" >SERVER_NAME_GENERATED
		echo "set_var EASYRSA_REQ_CN $SERVER_CN" >>vars
		# Create the PKI, set up the CA, the DH params and the server certificate
		./easyrsa init-pki
		./easyrsa --batch build-ca nopass
		if [[ $DH_TYPE == "2" ]]; then
			# ECDH keys are generated on-the-fly so we don't need to generate them beforehand
			openssl dhparam -out dh.pem $DH_KEY_SIZE
		fi
		./easyrsa build-server-full "$SERVER_NAME" nopass
		EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
		case $TLS_SIG in
		1)
			# Generate tls-crypt key
			openvpn --genkey --secret /etc/openvpn/tls-crypt.key
			;;
		2)
			# Generate tls-auth key
			openvpn --genkey --secret /etc/openvpn/tls-auth.key
			;;
		esac
	else
		# If easy-rsa is already installed, grab the generated SERVER_NAME
		# for client configs
		cd /etc/openvpn/easy-rsa/ || return
		SERVER_NAME=$(cat SERVER_NAME_GENERATED)
	fi
	# Move all the generated files
	cp pki/ca.crt pki/private/ca.key "pki/issued/$SERVER_NAME.crt" "pki/private/$SERVER_NAME.key" /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn
	if [[ $DH_TYPE == "2" ]]; then
		cp dh.pem /etc/openvpn
	fi
	# Make cert revocation list readable for non-root
	chmod 644 /etc/openvpn/crl.pem
	# Generate server.conf
	echo "port $PORT" >/etc/openvpn/server.conf
	if [[ $IPV6_SUPPORT == 'n' ]]; then
		echo "proto $PROTOCOL" >>/etc/openvpn/server.conf
	elif [[ $IPV6_SUPPORT == 'y' ]]; then
		echo "proto ${PROTOCOL}6" >>/etc/openvpn/server.conf
	fi
	echo "dev tun
user nobody
group $NOGROUP
persist-key
persist-tun
keepalive 10 120
topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt" >>/etc/openvpn/server.conf
	# DNS resolvers
	case $DNS in
	1) # Current system resolvers
		# Locate the proper resolv.conf
		# Needed for systems running systemd-resolved
		if grep -q "127.0.0.53" "/etc/resolv.conf"; then
			RESOLVCONF='/run/systemd/resolve/resolv.conf'
		else
			RESOLVCONF='/etc/resolv.conf'
		fi
		# Obtain the resolvers from resolv.conf and use them for OpenVPN
		sed -ne 's/^nameserver[[:space:]]\+\([^[:space:]]\+\).*$/\1/p' $RESOLVCONF | while read -r line; do
			# Copy, if it's a IPv4 |or| if IPv6 is enabled, IPv4/IPv6 does not matter
			if [[ $line =~ ^[0-9.]*$ ]] || [[ $IPV6_SUPPORT == 'y' ]]; then
				echo "push \"dhcp-option DNS $line\"" >>/etc/openvpn/server.conf
			fi
		done
		;;
	esac
	echo 'push "redirect-gateway def1 bypass-dhcp"' >>/etc/openvpn/server.conf
	# IPv6 network settings if needed
	if [[ $IPV6_SUPPORT == 'y' ]]; then
		echo 'server-ipv6 fd42:42:42:42::/112
tun-ipv6
push tun-ipv6
push "route-ipv6 2000::/3"
push "redirect-gateway ipv6"' >>/etc/openvpn/server.conf
	fi
	if [[ $COMPRESSION_ENABLED == "y" ]]; then
		echo "compress $COMPRESSION_ALG" >>/etc/openvpn/server.conf
	fi
	if [[ $DH_TYPE == "1" ]]; then
		echo "dh none" >>/etc/openvpn/server.conf
		echo "ecdh-curve $DH_CURVE" >>/etc/openvpn/server.conf
	elif [[ $DH_TYPE == "2" ]]; then
		echo "dh dh.pem" >>/etc/openvpn/server.conf
	fi
	case $TLS_SIG in
	1)
		echo "tls-crypt tls-crypt.key" >>/etc/openvpn/server.conf
		;;
	2)
		echo "tls-auth tls-auth.key 0" >>/etc/openvpn/server.conf
		;;
	esac
	echo "crl-verify crl.pem
ca ca.crt
cert $SERVER_NAME.crt
key $SERVER_NAME.key
auth $HMAC_ALG
cipher $CIPHER
ncp-ciphers $CIPHER
tls-server
tls-version-min 1.2
tls-cipher $CC_CIPHER
client-config-dir /etc/openvpn/ccd
status /var/log/openvpn/status.log
verb 3" >>/etc/openvpn/server.conf
	# Create client-config-dir dir
	mkdir -p /etc/openvpn/ccd
	# Create log dir
	mkdir -p /var/log/openvpn
	# Enable routing
	echo 'net.ipv4.ip_forward=1' >/etc/sysctl.d/99-openvpn.conf
	if [[ $IPV6_SUPPORT == 'y' ]]; then
		echo 'net.ipv6.conf.all.forwarding=1' >>/etc/sysctl.d/99-openvpn.conf
	fi
	# Apply sysctl rules
	sysctl --system
	# If SELinux is enabled and a custom port was selected, we need this
	if hash sestatus 2>/dev/null; then
		if sestatus | grep "Current mode" | grep -qs "enforcing"; then
			if [[ $PORT != '1194' ]]; then
				semanage port -a -t openvpn_port_t -p "$PROTOCOL" "$PORT"
			fi
		fi
	fi
	# Finally, restart and enable OpenVPN
	if [[ $OS == 'arch' || $OS == 'fedora' || $OS == 'centos' || $OS == 'oracle' ]]; then
		# Don't modify package-provided service
		cp /usr/lib/systemd/system/openvpn-server@.service /etc/systemd/system/openvpn-server@.service
		# Workaround to fix OpenVPN service on OpenVZ
		sed -i 's|LimitNPROC|#LimitNPROC|' /etc/systemd/system/openvpn-server@.service
		# Another workaround to keep using /etc/openvpn/
		sed -i 's|/etc/openvpn/server|/etc/openvpn|' /etc/systemd/system/openvpn-server@.service
		systemctl daemon-reload
		systemctl enable openvpn-server@server
		systemctl restart openvpn-server@server
	elif [[ $OS == "ubuntu" ]] && [[ $VERSION_ID == "16.04" ]]; then
		# On Ubuntu 16.04, we use the package from the OpenVPN repo
		# This package uses a sysvinit service
		systemctl enable openvpn
		systemctl start openvpn
	else
		# Don't modify package-provided service
		cp /lib/systemd/system/openvpn\@.service /etc/systemd/system/openvpn\@.service
		# Workaround to fix OpenVPN service on OpenVZ
		sed -i 's|LimitNPROC|#LimitNPROC|' /etc/systemd/system/openvpn\@.service
		# Another workaround to keep using /etc/openvpn/
		sed -i 's|/etc/openvpn/server|/etc/openvpn|' /etc/systemd/system/openvpn\@.service
		systemctl daemon-reload
		systemctl enable openvpn@server
		systemctl restart openvpn@server
	fi
	if [[ $DNS == 2 ]]; then
		installUnbound
	fi
	# Add iptables rules in two scripts
	mkdir -p /etc/iptables
	# Script to add rules
	echo "#!/bin/sh
iptables -t nat -I POSTROUTING 1 -s 10.8.0.0/24 -o $NIC -j MASQUERADE
iptables -I INPUT 1 -i tun0 -j ACCEPT
iptables -I FORWARD 1 -i $NIC -o tun0 -j ACCEPT
iptables -I FORWARD 1 -i tun0 -o $NIC -j ACCEPT
iptables -I INPUT 1 -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >/etc/iptables/add-openvpn-rules.sh
	if [[ $IPV6_SUPPORT == 'y' ]]; then
		echo "ip6tables -t nat -I POSTROUTING 1 -s fd42:42:42:42::/112 -o $NIC -j MASQUERADE
ip6tables -I INPUT 1 -i tun0 -j ACCEPT
ip6tables -I FORWARD 1 -i $NIC -o tun0 -j ACCEPT
ip6tables -I FORWARD 1 -i tun0 -o $NIC -j ACCEPT
ip6tables -I INPUT 1 -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >>/etc/iptables/add-openvpn-rules.sh
	fi
	# Script to remove rules
	echo "#!/bin/sh
iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -o $NIC -j MASQUERADE
iptables -D INPUT -i tun0 -j ACCEPT
iptables -D FORWARD -i $NIC -o tun0 -j ACCEPT
iptables -D FORWARD -i tun0 -o $NIC -j ACCEPT
iptables -D INPUT -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >/etc/iptables/rm-openvpn-rules.sh
	if [[ $IPV6_SUPPORT == 'y' ]]; then
		echo "ip6tables -t nat -D POSTROUTING -s fd42:42:42:42::/112 -o $NIC -j MASQUERADE
ip6tables -D INPUT -i tun0 -j ACCEPT
ip6tables -D FORWARD -i $NIC -o tun0 -j ACCEPT
ip6tables -D FORWARD -i tun0 -o $NIC -j ACCEPT
ip6tables -D INPUT -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >>/etc/iptables/rm-openvpn-rules.sh
	fi
	chmod +x /etc/iptables/add-openvpn-rules.sh
	chmod +x /etc/iptables/rm-openvpn-rules.sh
	# Handle the rules via a systemd script
	echo "[Unit]
Description=iptables rules for OpenVPN
Before=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/etc/iptables/add-openvpn-rules.sh
ExecStop=/etc/iptables/rm-openvpn-rules.sh
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target" >/etc/systemd/system/iptables-openvpn.service
	# Enable service and apply rules
	systemctl daemon-reload
	systemctl enable iptables-openvpn
	systemctl start iptables-openvpn
	# If the server is behind a NAT, use the correct IP address for the clients to connect to
	if [[ $ENDPOINT != "" ]]; then
		IP=$ENDPOINT
	fi
	# client-template.txt is created so we have a template to add further users later
	echo "client" >/etc/openvpn/client-template.txt
	if [[ $PROTOCOL == 'udp' ]]; then
		echo "proto udp" >>/etc/openvpn/client-template.txt
		echo "explicit-exit-notify" >>/etc/openvpn/client-template.txt
	elif [[ $PROTOCOL == 'tcp' ]]; then
		echo "proto tcp-client" >>/etc/openvpn/client-template.txt
	fi
	echo "remote $IP $PORT
dev tun
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
verify-x509-name $SERVER_NAME name
auth $HMAC_ALG
auth-nocache
cipher $CIPHER
tls-client
tls-version-min 1.2
tls-cipher $CC_CIPHER
ignore-unknown-option block-outside-dns
setenv opt block-outside-dns # Prevent Windows 10 DNS leak
verb 3" >>/etc/openvpn/client-template.txt
	if [[ $COMPRESSION_ENABLED == "y" ]]; then
		echo "compress $COMPRESSION_ALG" >>/etc/openvpn/client-template.txt
	fi
	# Generate the custom client.ovpn
	newClient
	echo "If you want to add more clients, you simply need to run this script another time!"

function manageMenu() {
	echo "Welcome to OpenVPN-install!"
	echo "The git repository is available at: https://github.com/angristan/openvpn-install"
	echo ""
	echo "It looks like OpenVPN is already installed."
	echo ""
	echo "What do you want to do?"
	echo "   1) Add a new user"
	echo "   2) Revoke existing user"
	echo "   3) Remove OpenVPN"
	echo "   4) Exit"
	until [[ $MENU_OPTION =~ ^[1-4]$ ]]; do
		read -rp "Select an option [1-4]: " MENU_OPTION
	done
	case $MENU_OPTION in
	1)
		newClient
		;;
	2)
		revokeClient
		;;
	3)
		removeOpenVPN
		;;
	4)
		exit 0
		;;
	esac
}
# Check for root, TUN, OS...
initialCheck
# Check if OpenVPN is already installed
if [[ -e /etc/openvpn/server.conf && $AUTO_INSTALL != "y" ]]; then
	manageMenu
else
	installOpenVPN
fi


echo "... Установка AdGuardHome ..."
curl -s -S -L https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/scripts/install.sh | sh -s -- -v
echo "... Добавление локального DNS в Shadowsocks ..."
sed -i 's/.*nameserver.*/"nameserver": "127.0.0.1",/' /etc/shadowsocks-libev/config.json
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
echo ... Создание скрипта start-n0isy.sh ...
echo -n "#!" > /root/noisy/start-n0isy.sh
echo "/bin/sh" >> /root/noisy/start-n0isy.sh
echo -n 'if [ -z "' >> /root/noisy/start-n0isy.sh
echo -n '$' >> /root/noisy/start-n0isy.sh
echo '(pgrep -f [n]oisy)" ]' >> /root/noisy/start-n0isy.sh
echo "then {" >> /root/noisy/start-n0isy.sh
echo -n '        echo ' >> /root/noisy/start-n0isy.sh
echo -n '$' >> /root/noisy/start-n0isy.sh
echo '(date +%Y-%m-%d:%k:%M:%S) "Running Noisy" >> /var/log/noisy_log' >> /root/noisy/start-n0isy.sh
echo "        sleep 1  #delay" >> /root/noisy/start-n0isy.sh
echo "        /usr/bin/python3 /root/noisy/noisy.py --config /root/noisy/config.json" >> /root/noisy/start-n0isy.sh
echo "        exit 1" >> /root/noisy/start-n0isy.sh
echo -n "}" >> /root/noisy/start-n0isy.sh
echo -n " else " >> /root/noisy/start-n0isy.sh
echo "{" >> /root/noisy/start-n0isy.sh
echo -n '        echo ' >> /root/noisy/start-n0isy.sh
echo -n '$' >> /root/noisy/start-n0isy.sh
echo '"EXIT. Noisy already running!"' >> /root/noisy/start-n0isy.sh
echo "        exit 1" >> /root/noisy/start-n0isy.sh
echo "}" >> /root/noisy/start-n0isy.sh
echo "fi" >> /root/noisy/start-n0isy.sh
chmod +x /root/noisy/start-n0isy.sh
echo "... Добавление start-n0isy в cron ..."
sed -i '$ d' /etc/crontab
echo "0 * * * *   root    /root/noisy/start-n0isy.sh" >> /etc/crontab
echo "@reboot   root    /root/noisy/start-n0isy.sh" >> /etc/crontab
echo "#" >> /etc/crontab
cd ..


echo -n "...Добавить команды в bash_history? ... (y/n) "
read item
case "$item" in
    y|Y) echo "... Добавление команд в bash_history ..."
        sed -i 'd' /root/.bash_history
        echo "apt update && apt upgrade -y" >> /root/.bash_history
        echo "apt clean && apt autoclean" > /root/.bash_history
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
