#!/bin/sh

set -e

# defaults
LOADER_DIR=/usr/sbin
IFACE_NAME=ndis0
MOD_CONF=/etc/modprobe.conf
WIN_DRIVERS=/lib/windrivers

# routines

error()
{
    echo "$*"
    echo "Aborting due to above errors; fix them and run this script again."
    exit 1
}

warn()
{
    echo "$*"
}

BASE_DIR=$(dirname $0)
if [ ! -z "${BASE_DIR}" ]; then
    cd ${BASE_DIR}
fi

RESP=""

# get response from the user. $1 is the message, the rest is default
# value, if any. Response is stored in RESP
get_resp()
{
    local MSG DEF
    MSG=$1; shift
    if [ "$#" -eq 0 ]; then
	DEF=""
    else
	DEF="$*"
    fi
    while :; do
	echo -n "${MSG}"
	if [ "${DEF}" != "" ]; then
	    echo -n "(${DEF})"
	fi
	read RESP
	if [ "${RESP}" != "" ]; then
	    break
	elif [ "${DEF}" != "" ]; then
	    RESP="${DEF}"
	    break
	else
	    echo "Invalid response; try again."
	fi
    done
}
    

# get kernel directory, check for SMP

KVERS=$(uname -r)

KVERSMINOR=$(echo ${KVERS} | awk -F . '{print $2}')

KSRC=/lib/modules/${KVERS}/build

if [ ! -e "${KSRC}/include/asm" ]; then
    error "You don't seem to have sources for your kernel; \
	install them in /usr/src, link $(KSRC) to it."
fi

if [ -f ${KSRC}/.config ]; then
    grep CONFIG_SMP ${KSRC}/.config | grep -q '^#'
    if [ $? -ne 0 ]; then
	error "SMP is not supported yet; disable SMP in your kernel."
    fi
fi

# this is probably better way to detect SMP
if grep -q ' SMP ' /proc/version; then
    error "SMP is not supported yet; disable SMP in your kernel."
fi

# locate PCI id

NCARDS=$(lspci | grep 'Network controller' | wc -l)

if [ ${NCARDS} -gt 1 ]; then
    error "You seem to have more than one 802.11 card; report output of lspci"
elif [ ${NCARDS} -eq 0 ]; then
    error "Can't find any 802.11 cards; report output of lspci"
fi

PCIID=$(lspci -n | grep `lspci | awk '/Network controller/ {print $1}'` | awk  '{print $4}')

VENDOR_ID=$(echo ${PCIID} | awk -F : '{print $1}')
DEVICE_ID=$(echo ${PCIID} | awk -F : '{print $2}')

# install windows drivers
while :; do
    get_resp "Give the full path to .inf file of windows driver?"
    INF=${RESP}
    if [ ! -f "${INF}" ]; then
	echo "${INF} is not a valid .inf file; try again"
    elif [ "$(dirname ${INF})/$(basename ${INF} .inf).inf" = "${INF}" ]; then
	INF_EXT="inf"
	break
    elif [ "$(dirname ${INF})/$(basename ${INF} .INF).INF" = "${INF}" ]; then
	INF_EXT="INF"
	break
    else
	echo "${INF} is not a valid .inf file; try again"
    fi
done


while :; do
    if [ "${INF_EXT}" = "INF" ]; then
	get_resp  "Give the full path to .sys file of the windows driver?" \
	    "$(dirname ${INF})/$(basename ${INF} .${INF_EXT}).SYS"
    else
	get_resp  "Give the full path to .sys file of the windows driver?" \
	    "$(dirname ${INF})/$(basename ${INF} .${INF_EXT}).sys"
    fi

    SYS=${RESP}
    if [ -f ${SYS} ]; then
	break
    else
	echo "${SYS} is not a valid .sys file; try again"
    fi
done

if [ "$(dirname $INF)" != "${WIN_DRIVERS}" ]; then
    mkdir -p ${WIN_DRIVERS}
    install -m 0644 $INF $SYS ${WIN_DRIVERS}
    INF=${WIN_DRIVERS}/$(basename $INF)
    SYS=${WIN_DRIVERS}/$(basename $SYS)
fi

# install module

echo "Executing make install to build the module and loaddriver."
make install
if [ $? -ne 0 ]; then
    error "Problems building the module and/or loaddriver."
fi

# install loaddriver and create loadndiswrapper

while :; do
    get_resp "Which directory should the loadndisdriver be installed in?" \
	"${LOADER_DIR}"
    LOADER_DIR=${RESP}

    if [ -d ${LOADER_DIR} ]; then
	if install -m 0755 utils/loadndisdriver ${LOADER_DIR}; then
	    LOADER=${LOADER_DIR}/loadndisdriver
	    break
	else
	    echo "Problem copying the loadndisdriver to ${LOADER_DIR}; try again."
	fi
    else
	echo "Directory ${LOADER_DIR} does not exist; try again."
    fi
done

# configure modules

get_resp "What interface should ndiswrapper configure?" "${IFACE_NAME}"
IFACE_NAME=${RESP}

if modprobe -c | grep -q ndiswrapper; then
    warn "It seems modprobe is already configured for ndiswrapper; assuming it is correct. Otherwise, delete the current configuration and try again."
else 

    get_resp "Where should module directives be placed?" "${MOD_CONF}"
    MOD_CONF=${RESP} 
    if :; then
	echo "alias ${IFACE_NAME} ndiswrapper"
	
	if [ ${KVERSMINOR} -gt 4 ]; then
	    echo -n "install ndiswrapper /sbin/modprobe --ignore-install ndiswrapper; "
	else
	    echo -n "post-install ndiswrapper "
	fi
	echo "${LOADER} ${VENDOR_ID} ${DEVICE_ID} ${SYS} ${INF}"
    fi >> ${MOD_CONF}

fi
exit 0
