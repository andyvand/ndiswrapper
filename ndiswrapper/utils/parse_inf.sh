#!/bin/sh -x

# Author: Giridhar Pemmasani (giri@lmc.cs.sunysb.edu)
# Parse inf file of NDIS drivers
# TODO: Make sure it works for all the drivers listed on the
# 'Supported Chipsets' page.
# Enable debug option in BEGIN section to print (lot of) debug output

if [ $# -lt 2 ]; then
    echo "usage: $0 <driver inf file> <driver sys file>"
    exit 1
fi

CONFIG_DIR="/etc/ndiswrapper"
COPY_FILES=1 # should inf, sys files should be copied to CONFIG_DIR?
INF=""
SYS=""

while [ $# -gt 0 ]; do
    if [ "$1" = "-n" ]; then
	COPY_FILES=0
    else
	FILE=$(basename $1)
	if [ $(basename $FILE .inf) != $FILE -o \
	    $(basename $FILE .INF) != $FILE ]; then
	     INF=$1
	elif [ $(basename $FILE .sys) != $FILE -o \
	       $(basename $FILE .SYS) != $FILE ]; then
	       SYS=$1
	else
	    echo "unknown argument: $1 (ignored)"
	fi
    fi
    shift
done
	
if [ -z $INF -o ! -r $INF ]; then
    echo "$0: can't read the driver inf file"
    exit 1
fi

if [ -z $SYS -o ! -r $SYS ]; then
    echo "$0: can't read the driver sys file"
    exit 1
fi

PCI_IDS=$(lspci -n | egrep 'Class 02(8|0)0:' | awk  '{printf "%s,", $4}')

NUM_CARDS=$(awk 'BEGIN {printf "%d\n", split("'$PCI_IDS'", x, ",")}')
if [ $NUM_CARDS -lt 2 ]; then
    echo "No network cards found"
    exit 1
fi

if [ ! -d $CONFIG_DIR ]; then
    install -m 0755 -d $CONFIG_DIR
    if [ $? -ne 0 ]; then
	echo "Can't create directory \"${CONFIG_DIR}\""
	exit 1
    fi
fi

if [ $COPY_FILES -eq 1 ]; then
    DRIVER=${CONFIG_DIR}/$(basename $SYS)
    CONFIG_FILE="${CONFIG_DIR}/config"
    if [ "$(dirname $INF)" != "$CONFIG_DIR" ]; then
	install -m 0644 $INF ${CONFIG_DIR}/
    fi

    if [ "$(dirname $SYS)" != "$CONFIG_DIR" ]; then
	install -m 0644 $SYS ${CONFIG_DIR}/
    fi
else
    DRIVER=$SYS
    CONFIG_FILE="$(dirname $SYS)/config"
fi

#sed 's/;.*//g    # remove comments
#    s/
//g      # remove Ctrl-M characters
#    /^$/d' $INF | tr -dc '[:print:]\n\t' |  # get only printable chars

sed 's/;.*//g
    s/
//g
    /^$/d' $INF | 
    awk '
	function dbg(fmt, msg)
	{
	    if (debug != 0)
		printf(fmt, msg) >> "/dev/stderr"
	}

	function error(msg)
	{
	    printf("%s\naborting...", msg) > "/dev/stderr"
	    exit 1
	}

	# remove white space at the beginning and end
	function trim_string(str)
	{
	    sub(/^[ \t]*/, "", str)
	    sub(/[ \t]*$/, "", str)
	    return str
	}

	# strip quotes around string
	function strip_quotes(str)
	{
	    sub(/^\"([ \t]*)/, "", str)
	    sub(/\"([ \t]*)$/, "", str)
	    return str
	}

	# process version section
	function process_ver(line,	fields)
	{
	    if (split(line, fields, "=") == 2) {
		fields[1] = trim_string(fields[1])
		fields[2] = trim_string(fields[2])
		# check for signature
		if (fields[1] ~ /^Signature$/) {
		    if (tolower(fields[2]) !~ /\"\$chicago\$\"/ &&
			    tolower(fields[2]) !~ /\"\$windows nt\$\"/ &&
			    tolower(fields[2]) !~ /\"\$windows 95\$\"/) {
			error("signature is not $Chicago: " fields[2])
		    }
		} else if (fields[1] ~ /^DriverVer$/)
			driver_version = fields[2]
		else if (fields[1] ~ /^Provider$/)
			driver_provider = fields[2]
	    }
	}

	# process strings section
	function process_str(line,	fields, tmp)
	{
	    # grab strings
	    dbg("processing strings line: %s\n", line)
	    if (split(line, fields, "=") == 2) {
		fields[1] = tolower(trim_string(fields[1]))
		fields[2] = trim_string(fields[2])
		tmp = ("%" fields[1] "%")
		strings[tmp] = strip_quotes(fields[2])
		dbg("setting strings: %s\n", (tmp ":" strings[tmp]))
	    }
	}

	# process Manufacturer section
	function process_mfr(line,	fields, tmp)
	{
	    dbg("looking at mfr line: %s\n", line)
	    if (split(line, fields, "=") == 2) {
		fields[1] = trim_string(fields[1])
		if (fields[1] == driver_provider ||
			match(fields[1], /%.*%/, tmp)) {
		    if (split(fields[2], tmp, ",") > 1)
			target_os = trim_string(tmp[2])
		    dev_desc = trim_string(tmp[1])
		    # multiple os crap is not handled right now
		    dbg("dev_desc: %s\n", dev_desc)
		}
	    }
	}

	# check if device descritption section begins
	function is_dev_desc_section(line,	tmp)
	{
	    tmp[1] = trim_string(line)
	    tmp[2] = sprintf("[%s.%s]", dev_desc, target_os)
	    if (tmp[1] == tmp[2])
		return 1
	    tmp[2] = sprintf("[%s]", dev_desc)
	    if (tmp[1] == tmp[2])
		return 1
	    return 0
	}

	# process device description section
	function process_dev_desc(line,    dev, cur_pci_id, vendor_id, device_id, tmp, i)
	{
	    dbg("processing device line %s\n", line)
	    if (split(line, dev, "=") == 2) {
		match(dev[2], /PCI\\VEN_([0-9a-zA-Z]+)&DEV_([0-9a-zA-Z]+)/,
			    tmp)
		vendor_id = trim_string(tmp[1])
		device_id = trim_string(tmp[2])
		cur_pci_id = sprintf("%s:%s", vendor_id, device_id)
		dbg("pci_id check: %s:", cur_pci_id)
		for (i in pci_ids) {
		    if (tolower(cur_pci_id) == tolower(pci_ids[i])) {
			dbg("pci_id matches: %s\n", cur_pci_id)
			if (split(dev[2], tmp, ",") != 2)
			    error("device registry not found in %s\n", line)
			if ((vendor_id "|" device_id) == pci_id)
			    dbg("device already found: %s\n", pci_id)
			else {
			    pci_id = (vendor_id "|" device_id)
			    dev_reg_sec = sprintf("%s", trim_string(tmp[1]))
			    dbg("dev_reg_sec: %s\n", dev_reg_sec)
			    dbg("set device id: %s\n", pci_id)
			}
		    }
		}
	    }
	}

	# check if it is device section
	function is_dev_section(line,	fields, tmp)
	{
	    match(line, /^\[([0-9a-zA-Z\._]+)\]/, fields)
	    tmp[1] = sprintf("%s.%s", dev_reg_sec, target_os)
	    tmp[2] = sprintf("%s", dev_reg_sec)
	    dbg("checking if dev section: %s\n",
		    (tmp[1] ":" tmp[2] ":" fields[1]))
	    if (tmp[1] == fields[1] || tmp[2] == fields[1]) {
		dbg("dev section found: %s\n", fields[1])
		return 1
	    } else
		return 0
	}

	# process device section
	function process_dev_reg_sec(line,	fields, tmp, x, y, n)
	{
	    dbg("processing dev_reg_sec: %s\n", line)
	    if (split(line, fields, "=") == 2)
		tmp = trim_string(fields[1])
		if (tmp ~ /^AddReg$/) {
		    tmp = trim_string(fields[2])
		    n = split(tmp, fields, ",")
		    dbg("current_reg_sec:%s", "\n")
		    for (x = 1 ; x < 200 ; x++)
			if (x in reg_sec)
			    dbg("%s,", reg_sec[x])
			else
			    break
		    for (y = 1 ; y <= n ; y++)
			reg_sec[x+y-1] = trim_string(fields[y])
		    dbg("added reg sections:%s\n", tmp)
		    dbg("new reg sections=%s", " ")
		    for (x in reg_sec)
			dbg("%s,", reg_sec[x])
		    dbg("%s", "\n")
		}
	}

	# check if looking at registry section
	function is_reg_section(str,	tmp, x, no_os)
	{
	    match(str, /^\[([0-9a-zA-Z\._]+)\]/, tmp)
	    tmp[1] = trim_string(tmp[1])
	    for (x in reg_sec) {
		dbg("matching reg: %s\n", (tmp[1] " as " reg_sec[x]))
		if (reg_sec[x] == tmp[1]) {
		    dbg("matched reg: %s\n", reg_sec[x])
		    return 1
		}
	    }
	    dbg("reg section not matched: %s\n", tmp[1])
	    return 0
	}

	# process registry section
	function process_reg_sec(str,	tmp, fields, case)
	{
	    dbg("looking at reg_sec line: %s\n", str)
	    if (split(str, fields, ",") >= 5) {
		fields[1] = trim_string(fields[1])
		if (fields[1] ~ /^HKR$/) {
		    fields[2] = trim_string(fields[2])
		    fields[3] = strip_quotes(trim_string(fields[3]))
		    fields[5] = strip_quotes(trim_string(fields[5]))

		    case = IGNORECASE
		    IGNORECASE = 1
		    if (match(fields[2], /Ndi\\params\\([^\\]+)/, tmp)) {
			if (fields[3] ~ /^default$/)
			    param_val[tmp[1]] = fields[5]
			else if (fields[3] ~ /^type$/)
			    param_type[tmp[1]] = fields[5]
		    } else if (fields[2] == "") {
			    param_val[fields[3]] = fields[5]
			    fields[4] = strip_quotes(trim_string(fields[4]))
			    if (fields[4] == "")
				param_type[fields[3]] = "none"
			    else
				param_type[fields[3]] = fields[4]
		    }
		    IGNORECASE = case
		}
	    }
	}

	BEGIN { debug = 0; mfr_str = dev_desc = dev_reg_sec = "[NONE]";
		target_os = "NT"; mode="ver";
		split("'$PCI_IDS'", pci_ids, ","); }

	{
	    if ($0 ~ /^\[([[:alnum:]\-\.\_])+\]/) {
#	    if ($0 ~ /^\[([a-zA-Z0-9\-\._]+)\]/) {
		dbg("section begin:%s\n", $0)

		if (tolower($0) ~ /\[version\]/) {
		    mode="ver"
		}
		else if (tolower($0) ~ /^\[manufacturer\]/) {
		    mode="mfr"
		}
		else if (is_dev_desc_section($0)) {
		    dbg("switching to dev section at %s\n", (dev_desc $0))
		    mode="dev_desc"
		}
		else if (is_dev_section($0)) {
		    dbg("switching to dev_reg section at %s\n", 
			    (dev_reg_sec $0))
		    mode="dev_reg_sec"
		}
		else if (tolower($0) ~ /^\[strings\]/) {
		    mode="str"
		}
		else if (is_reg_section($0)) {
		    mode="reg_sec"
		}
		else
		    mode="none"
	    }
	    if (mode == "ver")
		process_ver($0)
	    else if (mode == "mfr")
		process_mfr($0)
	    else if (mode == "dev_desc")
		process_dev_desc($0)
	    else if (mode == "dev_reg_sec")
		process_dev_reg_sec($0)
	    else if (mode == "reg_sec")
		process_reg_sec($0)
	    else if (mode == "str")
		    process_str($0)
	}
	END {
		printf "ndis_driver=none|"; printf "'$DRIVER'\n";
		printf "ndis_pci_id=%s\n", pci_id
		printf "ndis_provider=none|%s\n",
		    strings[tolower(driver_provider)]
		printf "ndis_version=none|%s\n", driver_version
		printf "# predefined settings\n"
		# version = 0x50001 (5.1)
		printf "NdisVersion=0x00000002|0x50001\n"
		printf "Environment=0x00000002|1\n"
		printf "BusType=0x00000002|5\n"
		printf "media_type=0x00000002|Autoselect\n"
		printf "\n"

# sorting would be better, but not all awks have asorti
#		n = asorti(param_val, sort_param)
#		for (i = 1 ; i <= n ; i++) {
#		    type = param_type[sort_param[i]]
#		    if (tolower(param_val[sort_param[i]]) in strings)
#			val = strings[tolower(param_val[sort_param[i]])]
#		    else
#			val = param_val[sort_param[i]]
#		    printf "%s=%s|%s\n", sort_param[i],	type, val
		for (i in param_val) {
		    type = param_type[i]
		    if (tolower(param_val[i]) in strings)
			val = strings[tolower(param_val[i])]
		    else
			val = param_val[i]
		    printf "%s=%s|%s\n", i, type, val
		}
	}' > ${CONFIG_FILE}
