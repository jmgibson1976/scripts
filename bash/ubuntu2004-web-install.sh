#!/usr/bin/env bash

# clear screen
clear

echo "Configuring Ubuntu 20.04 LTS Focal Fossa"
echo ""

# validate BASH info
if ((BASH_VERSINFO[0] < 4))
	then
		echo "Requires BASH version 4.0 or greater"
		exit 0
fi

# variables
export DIR=`pwd`
export BASH=`which bash`

# get scripts path
echo "Enter full path to scripts folder or hit enter to use the current directory (ex: ${DIR}):"
	read path

SCRIPT_PATH=${path}
if [[ ${SCRIPT_PATH} == "" ]]
    then
		SCRIPT_PATH=${DIR}
fi

export SCRIPT_PATH

apt-get -y upgrade && apt-get -y update

##############################################################
# update network config
##############################################################

# fix bootup delay issue
# https://askubuntu.com/questions/1090631/start-job-is-running-for-wait-for-network-to-be-configured-ubuntu-server-18-04

echo "Install vhost host-only network config? (y|n)"
    read install

INSTALL=${install%%/}
if [[ ${INSTALL} == "y" ]]; then

# EOF heredoc must be left justified
# make IP address dynamic at some point
read -d '' Netcfg <<EOF
network:
    ethernets:
        enp0s8:
            dhcp4: no
            addresses: [192.168.56.101/24]
            gateway4: 192.168.1.1
            nameservers:
                addresses: [192.168.1.1]
    version: 2
EOF

    # write string to network config script
    echo "${Netcfg}" | tee /etc/netplan/01-netcfg.yaml

    # execute network config
    netplan --debug apply

fi

##############################################################
# install ssh
##############################################################

echo "Would you like to install SSH Server service (y|n)"
    read ssh_build

SSH_BUILD=${ssh_build%%/}
if [[ $SSH_BUILD == "y" ]]; then

    # variables
    PORT=31000
    PROTOCOL=2
    ROOT_LOGIN=no
    X11_FORWARDING=no
    PAM=no
    DNS=no
    PASSWORD_AUTHENTICATION=no

    echo "Enter a string of user(s), separated by a space, to be added to AllowedUsers directive (ex: ssh-user ssh-tunnel jeremy): "
        read users

    # install ssh server and edit config script
    apt-get -y install openssh-server molly-guard monkeysphere sshpass

    # edit config with sed
    cd /etc/ssh
    if [ -f sshd_config ]; then

        # make backup
        cp sshd_config sshd_config.bak

        # begin editing
        sed -i "s/#Port 22/Port ${PORT}/" sshd_config
#       sed -i "s/Protocol.*/Protocol ${PROTOCOL}/" sshd_config
        sed -i "s/#PermitRootLogin.*/PermitRootLogin ${ROOT_LOGIN}/" sshd_config
        sed -i "s/#X11Forwarding.*/X11Forwarding ${X11_FORWARDING}/" sshd_config
        sed -i "s/#UsePAM.*/UsePAM ${PAM}/" sshd_config
        sed -i "s/#TCPKeepAlive.*/TCPKeepAlive no/" sshd_config

        # append data to file owned by root, standard echo will not work
        # http://unix.stackexchange.com/a/4337
        echo ""                                                     | tee -a sshd_config
        echo "#Custom"                                              | tee -a sshd_config
        echo "ClientAliveInterval 60"                               | tee -a sshd_config
        echo "ClientAliveCountMax 60"                               | tee -a sshd_config
        echo "UseDNS ${DNS}"                                        | tee -a sshd_config
        echo "PasswordAuthentication ${PASSWORD_AUTHENTICATION}"    | tee -a sshd_config
        echo "AllowUsers ${users}"                                  | tee -a sshd_config
    fi

    cd $SCRIPT_PATH
fi

##############################################################
# create ssh user
##############################################################

echo "Create default SSH user? (y|n)"
    read ssh_user_create

SSH_CREATE=${ssh_user_create%%/}
if [[ $SSH_CREATE == "y" ]]; then

#    echo "A user with a key or password? (key|password)"
#        read authenticate

#AUTH_TYPE=${authenticate%%/}

#    if [[ $AUTH_TYPE == 'password' ]]; then
#        $BASH ${SCRIPT_PATH}/ssh-server-user-create-with-password.sh
        # variables
        SSH_USER='ssh-user'

        # make sure use doesn't already exist
        USER_EXISTS=false
        getent passwd ${SSH_USER} > /dev/null 2>&1 && USER_EXISTS=true

        if $USER_EXISTS; then

            echo "User ${SSH_USER} already exists."
        else

            # create ssh user
            echo 'Creating SSH user ... '
            adduser $SSH_USER
            usermod -a -G sudo $SSH_USER
        fi

        # update ssd_config to allow password authentication
        sed -i "s/PasswordAuthentication no/PasswordAuthentication yes/" /etc/ssh/sshd_config
#    else
#        $BASH ${SCRIPT_PATH}/ssh-server-user-create-with-key.sh
#    fi
fi

##############################################################
# install libreSSL
##############################################################

echo "Would you like to replace OpenSSL w/ LibreSSL? (y|n)"
    read update

UPDATE=${update%%/}
if [[ ${UPDATE} == "y" ]]; then

    VERSION='3.1.2'

    # install gcc
    apt-get -y install build-essential

    # install LibreSSL (drop in replacement for OpenSSL)
    # instructions adapted from https://jetmirshatri.com/compile-nginx-and-libressl-from-source-with-support-for-chacha20-on-ubuntu/
    cd /tmp
    wget http://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-${VERSION}.tar.gz
    tar zxvf libressl-${VERSION}.tar.gz
    cd libressl-${VERSION}/
    ./configure --prefix=/usr && make check && make install

    # display version (should show LibreSSL, not OpenSSL version)
    openssl version

    sleep 5

    cd $SCRIPT_PATH
fi

##############################################################
# install apache server
##############################################################

echo "Install Apache? (y|n)"
    read install

INSTALL=${install%%/}
if [[ ${INSTALL} == "y" ]]; then

    # install apache server
    # http://www.2daygeek.com/apache-web-server-security-hardening-tips/#
    apt-get -y install apache2 ssl-cert libexpat1 apache2-suexec-pristine libapache2-mod-security2 libapache2-mod-evasive

    # update apache config to allow .htaccess in /var/www dir
    # @FIXME assumes /var/www config in 3rd spot, try using regex to find the right config
    sed -i ':a;N;$!ba;s/AllowOverride None/AllowOverride All/3' /etc/apache2/apache2.conf

    # alter apache signature from headers;
    # only shows apache, no version
    echo ''                         | tee -a /etc/apache2/apache2.conf
    echo 'ServerTokens ProductOnly' | tee -a /etc/apache2/apache2.conf
    echo 'ServerSignature Off'      | tee -a /etc/apache2/apache2.conf

    # restart apache
    /usr/sbin/service apache2 restart

    sleep 2
fi

##############################################################
# install php7
##############################################################

PHP_VERSION='7.4'

echo "Install PHP ${PHP_VERSION}? (y|n)"
    read install

INSTALL=${install%%/}
if [[ ${INSTALL} == "y" ]]; then

    # variables
    DISPLAY_ERRORS=On
    MEMORY_LIMIT=512M
    SESSION_TIMEOUT=900

    # decide whether or not display errors should be turned on
    echo "Toggle display errors, hit enter for default [${DISPLAY_ERRORS}] (On|Off): "
        read errors

    if [[ $errors != "" ]]; then

        DISPLAY_ERRORS=$errors
    fi

    # set memory limit
    echo "Set the memory limit, hit enter for default [${MEMORY_LIMIT}]: "
        read memory

    if [[ $memory != "" ]]; then

        MEMORY_LIMIT=$memory
    fi

    # set session timeout
    echo "Set the session timeout, hit enter for default [${SESSION_TIMEOUT}]: "
        read session

    if [[ $session != "" ]]; then

        SESSION_TIMEOUT=$session
    fi

    # update repos
    apt install software-properties-common
    add-apt-repository ppa:ondrej/php
    apt update

    # install php
    apt-get -y install php${PHP_VERSION} php${PHP_VERSION}-cli php${PHP_VERSION}-common php${PHP_VERSION}-dev \
    php${PHP_VERSION}-curl php${PHP_VERSION}-gmp php${PHP_VERSION}-mysql php${PHP_VERSION}-readline \
    php${PHP_VERSION}-opcache php${PHP_VERSION}-snmp php${PHP_VERSION}-soap php${PHP_VERSION}-gd php${PHP_VERSION}-json \
    php${PHP_VERSION}-xml php${PHP_VERSION}-mbstring php${PHP_VERSION}-sqlite3 php${PHP_VERSION}-xmlrpc php${PHP_VERSION}-zip php-pear snmp \
    memcached libapache2-mod-php${PHP_VERSION}

    sleep 2

    # consider moving to a single file in /etc directory
    # config php cli
    sed -i "s/error_reporting = .*/error_reporting = E_ALL/" /etc/php/${PHP_VERSION}/cli/php.ini
    sed -i "s/display_errors = .*/display_errors = ${DISPLAY_ERRORS}/" /etc/php/${PHP_VERSION}/cli/php.ini
    sed -i "s/memory_limit = .*/memory_limit = ${MEMORY_LIMIT}/" /etc/php/${PHP_VERSION}/cli/php.ini
    sed -i "s/;date.timezone.*/date.timezone = UTC/" /etc/php/${PHP_VERSION}/cli/php.ini
    sed -i "s/mail.add_x_header = .*/mail.add_x_header = Off/" /etc/php/${PHP_VERSION}/cli/php.ini
    sed -i "s/session.cookie_httponly = .*/session.cookie_httponly= 1/" /etc/php/${PHP_VERSION}/cli/php.ini
    sed -i "s/session.gc_maxlifetime = .*/session.gc_maxlifetime = ${SESSION_TIMEOUT}/" /etc/php/${PHP_VERSION}/cli/php.ini
    sed -i "s/session.hash_function = .*/session.hash_function = 1/" /etc/php/${PHP_VERSION}/cli/php.ini
    sed -i "s/;session.cookie_secure = .*/session.cookie_secure = /" /etc/php/${PHP_VERSION}/cli/php.ini # uncomment first, if commented
    sed -i "s/session.cookie_secure = .*/session.cookie_secure = 1/" /etc/php/${PHP_VERSION}/cli/php.ini

    # config php apache
    sed -i "s/error_reporting = .*/error_reporting = E_ALL/" /etc/php/${PHP_VERSION}/apache2/php.ini
    sed -i "s/display_errors = .*/display_errors = ${DISPLAY_ERRORS}/" /etc/php/${PHP_VERSION}/apache2/php.ini
    sed -i "s/memory_limit = .*/memory_limit = ${MEMORY_LIMIT}/" /etc/php/${PHP_VERSION}/apache2/php.ini
    sed -i "s/;date.timezone.*/date.timezone = UTC/" /etc/php/${PHP_VERSION}/apache2/php.ini
    sed -i "s/mail.add_x_header = .*/mail.add_x_header = Off/" /etc/php/${PHP_VERSION}/apache2/php.ini
    sed -i "s/session.cookie_httponly = .*/session.cookie_httponly= 1/" /etc/php/${PHP_VERSION}/apache2/php.ini
    sed -i "s/session.gc_maxlifetime = .*/session.gc_maxlifetime = ${SESSION_TIMEOUT}/" /etc/php/${PHP_VERSION}/apache2/php.ini
    sed -i "s/session.hash_function = .*/session.hash_function = 1/" /etc/php/${PHP_VERSION}/apache2/php.ini
    sed -i "s/;session.cookie_secure = .*/session.cookie_secure = /" /etc/php/${PHP_VERSION}/apache2/php.ini # uncomment first, if commented
    sed -i "s/session.cookie_secure = .*/session.cookie_secure = 1/" /etc/php/${PHP_VERSION}/apache2/php.ini

    sleep 2

    echo "Install ImageMagick? (y|n)"
    read imagick

    IMAGICK=${imagick%%/}
    if [[ ${IMAGICK} == "y" ]]; then

        apt-get -y install imagemagick
        apt-get install php${PHP_VERSION}-imagick
    fi

    # restart apache
    /usr/sbin/service apache2 restart
fi

##############################################################
# install sendmail
##############################################################

echo "Install Sendmail? (y|n)"
    read install

INSTALL=${install%%/}
if [[ ${INSTALL} == "y" ]]; then

    # variables
    TODAY=`date`

    # install sendmail
    apt-get -y install sendmail

    # add trusted users
    cd /etc/mail

    if [ ! -f trusted-users ]
        then
            touch trusted-users
            echo 'www-data' >> trusted-users
    else
        echo 'www-data' > trusted-users
    fi

    # append to configuration
    if [ -f submit.mc ]
    then
        # make backup
        cp submit.mc submit.mc.bak

        echo "dnl # Custom added by Jeremy Gibson ${TODAY}" | tee -a submit.mc
        echo "define(\`_USE_CT_FILE_',\`1')dnl" | tee -a submit.mc
        echo "include(\`/etc/mail/tls/starttls.m4')dnl" | tee -a submit.mc
        echo "define(\`confCT_FILE',\`/etc/mail/trusted-users')dnl" | tee -a submit.mc
    fi

    # add STARTTLS
    if [ -f sendmail.mc ]
    then
        # make backup
        cp sendmail.mc sendmail.mc.bak

        echo "dnl # Custom Added Jeremy Gibson ${TODAY}" | tee -a sendmail.mc
        echo "include(\`/etc/mail/tls/starttls.m4')dnl" | tee -a sendmail.mc
    fi

    # update sendmail
    sendmailconfig

    sleep 2

    cd $SCRIPT_PATH
fi

##############################################################
# install curl and composer
##############################################################

echo "Install Curl & Composer? (y|n)"
    read install

INSTALL=${install%%/}
if [[ ${INSTALL} == "y" ]]; then

    # install zip/unzip
    apt-get -y install zip unzip

    # install curl
    apt-get -y install curl

    PHP=`which php`

    if [[ ${PHP} != "" ]]; then

        # install composer
        cd /tmp
        curl -sS https://getcomposer.org/installer | $PHP

        # move composer for global usage
        mv /tmp/composer.phar /usr/local/bin/composer
    fi

    # set permissions
    chmod 755 /usr/local/bin/composer

    users=/home/*

    for user in $users
    do
        u="$(basename $user)"
        p=$user/.composer
        mkdir $p
        chown -R $u:$u $p
    done

    cd ${SCRIPT_PATH}
fi

##############################################################
# create web group and add users
##############################################################

USERGROUP=web

echo "Add ${USERGROUP} group? (y|n)"
    read install

INSTALL=${install%%/}
if [[ ${INSTALL} == "y" ]]; then

    groupadd web

    users=/home/*

    for user in $users
    do
        u="$(basename $user)"

        echo "Add ${u} to ${USERGROUP} group? (y|n)"
            read adduser

        ADDUSER=${adduser%%/}
        if [[ ${ADDUSER} == "y" ]]; then

            usermod -a -G $USERGROUP $u
        fi
    done
fi


############################################################
# install percona db
##############################################################

echo "Install Percona DB? (y|n)"
    read install

INSTALL=${install%%/}
if [[ ${INSTALL} == "y" ]]; then

    cd /tmp 

    # variables
    PERCONA_VERSION='8.0'

    #  get percona
    wget https://repo.percona.com/apt/percona-release_latest.$(lsb_release -sc)_all.deb
    dpkg -i percona-release_latest.$(lsb_release -sc)_all.deb
    apt-get update
    percona-release setup ps80

    # apt-get -y install percona-server-server-${PERCONA_VERSION}
    apt-get -y install percona-server-server

fi

##############################################################
# create default unsecured vhost
##############################################################

#$BASH ${SCRIPT_PATH}/configs/vhost-create.sh
echo "Create non-SSL vhost? (y|n)"
    read install

INSTALL=${install%%/}
if [[ ${INSTALL} == "y" ]]; then

    # variables
    A2ENSITE=`which a2ensite`
    A2DISSITE=`which a2dissite`

    # does FQDN variable exist
    if [ -z ${FQDN+x} ]; then
        FQDN=`hostname -f`

        echo "Enter FQDN for vhost (examples: listings.levelist.local, *.levelist.com), or hit enter to use ${FQDN}: "
            read fqdn

        fqdn=${fqdn%%/}
        if [[ ${fqdn} != "" ]]; then

            FQDN=${fqdn}
        fi

        export FQDN
    fi

    # make directory
    mkdir -p /var/www/${FQDN}/public

    # set perms
    find /var/www -exec chown -R root:${USERGROUP} {} \;
    find /var/www -type f -exec chmod -R 664 {} \;
    find /var/www -type d -exec chmod -R 775 {} \;

# EOF heredoc must be left justified
read -d '' String <<EOF
<VirtualHost *:80>
    RewriteEngine On
    RewriteCond \%\{HTTPS\} \!=on
    RewriteRule ^/?(.*) https://\%\{SERVER_NAME\}/\$1 [NC,R=301,L]

    ServerName ${FQDN}
    ServerAlias ${FQDN}
    DocumentRoot /var/www/${FQDN}/public

    ErrorLog \$\{APACHE_LOG_DIR\}/error.log
    CustomLog \$\{APACHE_LOG_DIR\}/access.log combined
</VirtualHost>

# vim: syntax=apache ts=4 sw=4 sts=4 sr noet
EOF

    # write string to supervisor script
    echo "${String}" | tee /etc/apache2/sites-available/${FQDN}.conf

    # disable default site
    $A2DISSITE 000-default.conf

    $A2ENSITE ${FQDN}.conf
fi

##############################################################
# create default secure vhost
##############################################################

echo "Create SSL vhost? (y|n)"
    read install

INSTALL=${install%%/}
if [[ ${INSTALL} == "y" ]]; then

        cp /etc/apache2/sites-available/default-ssl.conf /etc/apache2/sites-available/${FQDN}-ssl.conf

        LINE=$(grep -n 'ServerAdmin' /etc/apache2/sites-available/${FQDN}-ssl.conf | cut -d: -f1)
        NEXT=$((LINE + 1))

        sed -i "${NEXT}d" /etc/apache2/sites-available/${FQDN}-ssl.conf
        sed -i "s:ServerAdmin .*:ServerName ${FQDN}:"  /etc/apache2/sites-available/${FQDN}-ssl.conf
        sed -i "${NEXT}i \ \t\tServerAlias ${FQDN}" /etc/apache2/sites-available/${FQDN}-ssl.conf
        sed -i "s:DocumentRoot .*:DocumentRoot /var/www/${FQDN}/public:" /etc/apache2/sites-available/${FQDN}-ssl.conf

        a2ensite ${FQDN}-ssl.conf
fi

##############################################################
# add firewall
##############################################################

echo "Install firewall? (y|n)"
    read install

INSTALL=${install%%/}
if [[ ${INSTALL} == "y" ]]; then

    apt-get install -y ufw
    ufw allow 31000/tcp
    ufw allow 80/tcp
    ufw allow 443/tcp
    ufw default allow outgoing
    ufw default deny incoming
    ufw status
    ufw enable
    ufw status
    iptables -S

fi

##############################################################
# install xdebug
##############################################################

#$BASH ${SCRIPT_PATH}/../dev-simple-xdebug-install.sh

echo "Install XDebug? (y|n)"
    read install

INSTALL=${install%%/}
if [[ ${INSTALL} == "y" ]]; then

    # install xdebug
    apt-get -y install php-xdebug

    # variables
    MODS_AVAILABLE="/etc/php/${PHP_VERSION}/mods-available"

    cd ${MODS_AVAILABLE}

    if [ ! -f xdebug.ini ]
        then
            touch xdebug.ini
            echo "zend_extension=xdebug.so" | tee -a xdebug.ini
    fi

    echo ""                                        | tee -a xdebug.ini
    echo "xdebug.remote_autostart=0"               | tee -a xdebug.ini
    echo "xdebug.remote_enable=1"                  | tee -a xdebug.ini
    echo "xdebug.show_local_vars=1"                | tee -a xdebug.ini
    echo "xdebug.remote_connect_back=1"            | tee -a xdebug.ini
    echo "xdebug.remote_port=9000"                 | tee -a xdebug.ini
    echo 'xdebug.idekey="PHPSTORM"'                | tee -a xdebug.ini

    # restart service
    service apache2 restart
fi

##############################################################
# activate mods
##############################################################

A2ENMOD=`which a2enmod`

$A2ENMOD ssl
$A2ENMOD headers
$A2ENMOD expires
$A2ENMOD rewrite
$A2ENMOD suexec

##############################################################
# reload apache
##############################################################

/usr/sbin/service apache2 reload

##############################################################
# update
##############################################################

apt-get -y update
apt-get -y upgrade

##############################################################
# clean up
##############################################################

apt-get -y autoremove

# clear history
history -c

# restart server
shutdown -r now
