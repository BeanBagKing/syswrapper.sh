#!/bin/sh

. /usr/etc/common.sh
. /usr/etc/platdep_funcs.sh

SCRIPT="$0"
MTK_UAP=`grep radio0 /proc/ubnthal/system.info | grep -c -e MT`
DEFAULT_CFG='/tmp/default.cfg'
SYSTEM_STATE='/var/run/system.state'
LED_LOCK='/var/run/led.lock'
FW_LOCKFILE="/var/run/fwupdate.pid"
FW_MD5SUMFILE="/var/run/fwupdate.md5"
FW_WRITELOG="/tmp/fwupdate.log"
FW_DOWNLOAD_FAILED_FILE="/var/run/download_firmware.failed"
WIFI_10_4="/lib/wifi/qca-wifi-modules"
UAPNANOHD=`grep -c MT7621 /proc/cpuinfo`
NETCONSOLE_PIDFILE=/var/run/netconsole-init.pid
PID_11K=/var/run/11k.pid
ALLOWED_UPLINKS="/var/run/allowed_uplinks"
ISOLATION_LOGS_LOCATION='/etc/persistent/isolation_logs'
PRS_DEVNODE='/dev/ttyACM0'
PRS_MOD='prs_falcon'
PRS_INTC='wlan0'
IPSET_GUEST_AUTHORIZED_MAC='guest_authorized_mac'
SWITCH_IFACE='switch0'
SWITCH_PROC="/proc/$SWITCH_IFACE"
VLANS_FILE=/var/run/vlans

_lockfile() {
        local rc
        dotlockfile -l -p -r $1 "$2"
        rc=$?
        return $rc
}

_unlockfile() {
        dotlockfile -u $1
}

# Set the system LED. (On the UWB-XG Stadium AP, there are two LEDs: a system
# LED and a perimeter LED.) Enables/disables synchronization of system LED
# and perimeter LED for Stadium AP.
#
# Args:
# -- LED pattern (e.g., "12" will alternate blue and white)
# -- LED tempo, in beats per minute, integer
# -- Synchronize system LED with UWB-XG Stadium AP perimeter LED. Integer.
#    If 0, and running on UWB-XG, disables synchronization; else enables
#    sychronization
_set_led() {
        if [ -e "/proc/ubnt_ledbar/sysled_sync" ]; then
                echo "$3" > /proc/ubnt_ledbar/sysled_sync
        fi
        _lockfile 1 ${LED_LOCK}
        echo $1 > /proc/gpio/led_pattern
        echo $2 > /proc/gpio/led_tempo
        _unlockfile ${LED_LOCK}
        if [ -x "/sbin/lcm-ctrl" ]; then
                /sbin/lcm-ctrl -t state
        fi
}

log() {
        logger -s -t "syswrapper" "$*"
}

debug_log() {
        [ -e /tmp/syswrapper.debug ] && logger -s -t "syswrapper" "$*"
}

dump_syslog_to_persistent() {
        local ISOLATION_LOG_TMP='/var/log/isolation'
        # Each log takes up to ~8kB after compression
        local ISOLATION_LOG_LENGTH=500
        local ISOLATION_LOG_LIMIT=5

        logread -l ${ISOLATION_LOG_LENGTH} > ${ISOLATION_LOG_TMP}
        if [ $? -eq 0 ]; then
                mkdir -p ${ISOLATION_LOGS_LOCATION}
                local TIMESTAMP=`date +%s`
                tar -czf ${ISOLATION_LOGS_LOCATION}/isolated_${TIMESTAMP}.tar.gz ${ISOLATION_LOG_TMP}
        fi
        # remove old logs if we have more than a specified limit
        rm -f `ls -d ${ISOLATION_LOGS_LOCATION}/* | head -n -${ISOLATION_LOG_LIMIT}`
}

exit_if_fake() {
        if [ "`uname -a | grep -E \"mips|arm\"`" = "" -o -f "/tmp/FAKE" ] ; then
                # fake, simply dump it to console and exit 0
                logger -s -t "syswrapper" "[fake] skipping $*"
                exit 0
        fi
}

set_state() {
        echo $1 > ${SYSTEM_STATE}
}

# Handles following special cases for LED:
# -- Locating (flashing)
# -- Disabled (off)
# -- Pattern/tempo override
# Overrides LED configuration if special cases apply.
#
# Args:
# -- Desired LED pattern
# -- Desired LED tempo
# Returns:
# -- 0 if special case applied, and LED pattern/tempo
#    has been overridden and set
# -- 1 if no special case applied (and caller can proceed
#    to set LED or Stadium LED bar as desired).
handle_led_special_cases() {
        led_pattern=$1
        led_tempo=$2
        handled=0
        locating="false"
        if [ -f /proc/ubnthal/status/IsLocated ]; then
                locating=$(cat /proc/ubnthal/status/IsLocated)
        fi
        if [ -f /proc/ubnthal/status/IsDefault ]; then
                default=$(cat /proc/ubnthal/status/IsDefault)
        fi
        if [ -f /var/etc/persistent/cfg/mgmt ] ; then
                led_disabled=$(grep mgmt.led_enabled=false /var/etc/persistent/cfg/mgmt)
                led_pattern_override=$(grep mgmt.led_pattern_override /var/etc/persistent/cfg/mgmt | cut -d= -f 2)
                led_tempo_override=$(grep mgmt.led_tempo_override /var/etc/persistent/cfg/mgmt | cut -d= -f 2)
        fi
        if [ ! -z "$led_pattern_override" ]; then
                led_pattern=$led_pattern_override
                handled=1
        fi
        if [ ! -z "$led_tempo_override" ]; then
                led_tempo=$led_tempo_override
                handled=1
        fi
        if [ ! -z "$led_disabled" ]; then
                led_pattern=0
                led_tempo=120
                handled=1
        fi
        if [ "$locating" == "true" ]; then
                if [ "$default" == "true" ]; then
                        led_pattern=20
                        led_tempo=480
                        handled=1
                else
                        led_pattern=10
                        led_tempo=480
                        handled=1
                fi
        fi

        if [ "$handled" -eq 1 ]; then
                # For special cases, system LED and perimeter LED should
                # be synchronized (for UWB-XG).
                _set_led $led_pattern $led_tempo 1
                return 0
        else
                return 1
        fi
}

# Set LED on AP, and for UWB-XG, synchronize sysled with perimeter LED.
#
# Args:
# -- LED pattern (e.g., 12 will alternate blue-white-blue-white...).
# -- LED tempo (in beats per minute)
#
# If special cases apply (LED disabled, LED locating, etc.), LED pattern
# and tempo passed in arguments will be overridden.
set_led() {
        led_pattern=$1
        led_tempo=$2
        # Handle special cases (LED disabled, LED locating, etc.)
        if handle_led_special_cases $led_pattern $led_tempo; then
                # Handled and set
                return;
        else
                # Special case did not apply. Set desired LED and tempo.
                # Ensure sysled is synchronized with perimeter LED on
                # UWB-XG (set_led is called for some cases, like wireless
                # uplink issues).
                _set_led $led_pattern $led_tempo 1
        fi
}

# Sets LED for "ready" color/pattern.
#
# No arguments.
set_ready_led() {
    # Solid blue.
    set_led 1 120
}

lockfile() {
        local rc
        _lockfile 0 "$1.lock"
        rc=$?
        return $rc
}

unlockfile() {
        _unlockfile "$1.lock"
}

state_lock() {
        until lockfile ${SYSTEM_STATE}; do
                log "[state is locked] waiting for lock"
                sleep 1
        done
}

state_unlock() {
        unlockfile ${SYSTEM_STATE}
}

# obtain lock first
set_state_ready() {
        set_state 'ready'
        state_reload
}

exit_if_busy() {
        if [ -f ${SYSTEM_STATE} ] ; then
                state=`cat ${SYSTEM_STATE}`
                if [ "$state" != "ready" ] ; then
                        logger -s -t "syswrapper" "[busy] skipping: $*"
                        exit 0
                fi
        fi
}

# this would lock system state
exit_if_state_lock_failed() {
        lockfile ${SYSTEM_STATE} || \
        {
                log "[state is locked] skipping $*"
                exit 0
        }
}

exit_if_wds() {
        if [ -f /var/run/system.uplink ]; then
                uplink=`cat /var/run/system.uplink`
                if [ "$uplink" == "eth" ]; then
                        return
                fi
        fi
        logger -s -t "syswrapper" "[no eth uplink] skipping: $*"
        exit 0
}

check_if_ip_ready() {
        local x=0
        while [ ! -e /var/run/ipready.* ]; do
                logger "download-firmware: waiting for IP..."
                sleep 1
                x=$((x+1))
                if [ $x -gt 60 ]; then
                        upgrade_err "98" "IPIsNotReady"
                        return 1
                fi
        done
        return 0
}

# obtain lock first
state_reload() {
        state="init"
        uplink="unknown"
        default="true"
        locating="false"
        prev_uplink="unknown"
        uplink_loop="false"
        if [ -f /proc/ubnthal/status/IsDefault ]; then
                default=`cat /proc/ubnthal/status/IsDefault`
        fi
        if [ -f /proc/ubnthal/status/IsLocated ]; then
                locating=`cat /proc/ubnthal/status/IsLocated`
        fi
        if [ -f ${SYSTEM_STATE} ] ; then
                state=`cat ${SYSTEM_STATE}`
        fi
        if [ -f /var/run/system.uplink ]; then
                uplink=`cat /var/run/system.uplink`
                if [ -e /var/run/system.uplink.prev ]; then
                        prev_uplink=`cat /var/run/system.uplink.prev`
                else
                        prev_uplink=$uplink
                fi
                echo $uplink > /var/run/system.uplink.prev
        fi
        if [ -f /var/run/system.uplink.loop ]; then
                uplink_loop=`cat /var/run/system.uplink.loop`
        fi
        if [ "$state" == "upgrading" ]; then
                # echo upgrading
                set_led 12 120
                return
        fi
        if [ "$default" == "true" ]; then
                # echo default-ready
                set_led 2 120
                if [ "$uplink" == "eth" ]; then
                        configure_vap down up up
                else
                        sysid=`awk -F= '/^systemid=/{print $2}' /proc/ubnthal/system.info`
                        if [ "$sysid" == "ec25" ]; then
                                # special handle for UDM-B aplink-test
                                configure_vap up up down
                        else
                                configure_vap up down down
                        fi
                fi
                return
        fi
        if [ -f /var/run/system.selfrun ]; then
                # echo selfrun
                set_selfrun
        else
                # echo managed
                unset_selfrun
        fi

        case $uplink in
        eth)
                # Resolve the "5G vaps stay down" issue sometimes seen when switching between
                # wireless and wired uplink mode on 10.4
                if [ -e "$WIFI_10_4" -a "$prev_uplink" != "eth" ]; then
                        configure_vap down down up
                fi
                if [ "$uplink_loop" == "true" ]; then
                        configure_vap down up down
                else
                        configure_vap down up up
                fi
                set_ready_led
                return
                ;;
        wds)
                if [ -f /var/run/system.mesh ]; then
                        configure_vap up up up
                        if [ "$prev_uplink" != "$uplink" ]; then
                                killall hostapd
                        fi
                else
                        configure_vap up up down
                fi

                set_ready_led
                return
                ;;
        down)
                if [ -f /var/run/system.isolated_wlan_on ]; then
                        configure_vap up up down
                        set_led 11111110 120
                else
                        if [ "$prev_uplink" == wds ]; then
                                configure_vap down down down
                        else
                                configure_vap up down down
                        fi
                        set_led 11111110 120
                fi
                if [ "$default" != "true" -a \
                        "`grep wireless.1.usage=uplink /tmp/system.cfg`" != "" -a \
                        "`grep wireless.1.mode=master /tmp/system.cfg`" != "" ] ; then
                        # for V2 AP using old wireless uplink, we need to _migrate_ the uplink vap
                        # by reset the config but leave
                        cfgmtd -c
                        reboot
                fi
                return
                ;;
        lte_prov)
                # do nothing. lte provisioning wifi network is separate from udhcpc interface.
                ;;
        esac

        if [ "$state" == "ready" ]; then
                # echo ready
                set_ready_led
                return
        fi

        # echo $state
        set_led 2 120
}

set_selfrun() {
        if [ -f /var/run/system.selfrun.lock ]; then
                return
        fi
        touch /var/run/system.selfrun.lock
        if [ "`portal_enabled`" = "yes" ] ; then
                if [ "`selfrun_guest`" = "pass" ]; then
                        # echo selfrun-guest
                        # bypass the guest authorization
                        ebtables -t nat -F AUTHORIZED_GUESTS
                        ebtables -t nat -A AUTHORIZED_GUESTS -j ACCEPT
                else
                        # echo selfrun-no-guest
                        # disable guest wlans
                        for ath in `cat /var/run/guest_devnames` ; do
                                ifconfig $ath down
                        done
                fi
        fi
}

unset_selfrun() {
        if [ -f /var/run/system.selfrun.lock ]; then
                rm -f /var/run/system.selfrun.lock
                if [ "`portal_enabled`" = "yes" ] ; then
                        if [ "`selfrun_guest`" = "pass" ]; then
                                # echo unset-selfrun-guest
                                # re-enforce the guest authorization
                                rm -f /var/run/guest.authorized
                                authorized_guests_updated /var/run/guest.authorized
                        else
                                # echo unset-selfrun-no-guest
                                # re-enable guest wlans -- current disabled
                                for ath in `cat /var/run/guest_devnames` ; do
                                        ifconfig $ath up
                                done
                        fi
                fi
        fi
}

check_if_hostapd_killed() {
        if [ -f "/var/run/schedule_wlan_stop_work.$1" ]; then
                find /etc/ -name "aaa*.cfg" | while read conf; do
                        interface_name=`cat $conf | grep interface=$1`
                        if [ "$interface_name" != "" ]; then
                                pid=`ps | grep $conf | grep -v grep |  awk 'NR==1{print $1}'`
                                # use terminal to kill hostapd
                                kill $pid
                                rm /var/run/schedule_wlan_stop_work.$1
                                echo "true"
                        fi
                done
        else
                echo "false"
        fi
}

schedule_action() {
        if [ -f /var/run/system.uplink ]; then
                # need to check system state busy first in case the deac lock for the syswrapper.sh
                exit_if_busy $cmd $*
                exit_if_state_lock_failed $cmd $*
                state_reload
                state_unlock
        else
                configure_vap down up down
        fi
}

# check if interface is within schedule inside /var/run/schedules/schedule_*.ath* file
within_schedule() {
        schedule="/var/run/schedules/schedule.$1"
        ntpfile="/var/run/ntp.ready"
        now=`date "+%w %H:%M %Y"`
        mode="up"

        [ -f /var/run/schedules/schedule_invert.$1 ] && mode="down"

        # if ntp has not run yet and time is bad, we assume always within schedule
        if [ -e $ntpfile ]; then
                if [ -e $schedule ]; then
                        blocks=`grep ${now:0:1}= $schedule`
                        todayMins=`expr ${now:2:2} \* 60 + ${now:5:2}`
                        for b in $blocks; do
                                b=${b:2}
                                fromMins=`expr ${b:0:2} \* 60 + ${b:3:2}`
                                toMins=`expr ${b:6:2} \* 60 + ${b:9:2}`
                                if [ $todayMins -ge $fromMins ] && [ $todayMins -le $toMins ]; then
                                        if [ "$mode" = "up" ]; then
                                                echo "true"
                                        else
                                                echo "false"
                                        fi
                                        return
                                fi
                        done
                        if [ "$mode" = "up" ]; then
                                echo "false"
                        else
                                echo "true"
                        fi
                else
                        log 'schedules not found in /var/run/schedules'
                        echo "false"
                fi
        else
                log 'current time is not set yet'
                echo "true"
        fi
}

# FIX ME !!Already fix this in gen2 wifi driver after back port to gen3 can remove this one
check_vap_status() {
        vaps=`cat /var/run/wlan_devnames`
        eval "local uplink_vaps=\$$1"
        eval "local run_vap=\$$2"
        is_vport_down_to_up="false"

#       log "[check_vap_status] \$uplink_vaps = $uplink_vaps"
#       log "[check_vap_status] \$run_vap = $run_vap"

        # only do it in gen3
        sysid=`awk -F= '/^systemid=/{print $2}' /proc/ubnthal/system.info`
        if [ "$sysid" != "e530" -o "$sysid" != "e540" -o "$sysid" != "e550" -o "$sysid" != "e560" -o \
                "$sysid" != "e570" -o "$sysid" != "e580" -o "$sysid" != "e585" -o "$sysid" != "e590" ]; then
                return
        fi

        for uplink_vap in $uplink_vaps; do
                for ath in $run_vap; do
                        if [ "$ath" == "$uplink_vap" ] && [ -z "`ifconfig $uplink_vap | grep UP`" ]; then
                                is_vport_down_to_up="true"
                                break 2
                        fi
                done
        done

#       log "[check_vap_status] \$is_vport_down_to_up = $is_vport_down_to_up"

        if [ "$is_vport_down_to_up" == "true" ]; then
                for ath in $run_vap; do
                        usage="unknown"
                        if [ -f /var/run/vapusage.$ath ]; then
                                usage=`cat /var/run/vapusage.$ath`
                        fi
                        case $usage in
                        user|guest|downlink)
                                log "Force $ath down upon vport up"
                                ifconfig $ath down
                        ;;
                        esac
                done
        fi
}

configure_vap() {
        [ ! -z "$3" ] && [ -f /var/run/wlan_devnames ] || return
        vaps=`cat /var/run/wlan_devnames`
        run_vap=
        stop_vap=
        uplink_vaps=
        allowed_uplinks=
        n_uplink_vaps=0
        uplink_states=
        uplink_state=$1
        service_state=$2
        downlink_state=$3
        if [ -f $ALLOWED_UPLINKS ]; then
                allowed_uplinks=`cat $ALLOWED_UPLINKS`
        fi

        for ath in $vaps; do
                usage="unknown"
                if [ -f /var/run/vapusage.$ath ]; then
                        usage=`cat /var/run/vapusage.$ath`
                fi
                if [ -f /var/run/cfg_error.$ath ]; then
                        usage=unusable
                fi
                case $usage in
                uplink)
                        n_uplink_vaps=`expr $n_uplink_vaps + 1`
                        uplink_vaps="$uplink_vaps $ath"
                        if [ "$uplink_state" == "down" ]; then
                                stop_vap="$stop_vap $ath"
                                uplink_states="$uplink_states down"
                        else
                                # 3 cases to "up" a vport interface when uplink_state = up
                                # 1. no ALLOWED_UPLINKS file, wpa_supplicant will run
                                # 2. ALLOWED_UPLINKS file is empty, wpa_supplicant will not run
                                #    (assume device with multiple vport, set all vports up for scanning)
                                # 3. interface listed in ALLOWED_UPLINKS file, wpa_supplicant will run
                                #    (assume device with multiple vport, set selected vport for uplink)
                                if [ ! -f $ALLOWED_UPLINKS ]; then
                                        # case 1 above
                                        run_vap="$run_vap $ath"
                                        uplink_states="$uplink_states up"
                                else
                                        if [ -z "$allowed_uplinks" ]; then
                                                # case 2 above
                                                run_vap="$run_vap $ath"
                                                uplink_states="$uplink_states down"
                                        else
                                                # case 3 above
                                                is_allowed_uplink="false"
                                                for allowed_uplink in $allowed_uplinks; do
                                                        if [ $ath == $allowed_uplink ]; then
                                                                run_vap="$run_vap $ath"
                                                                uplink_states="$uplink_states up"
                                                                is_allowed_uplink="true"
                                                                break
                                                        fi
                                                done
                                                if [ $is_allowed_uplink == "false" ]; then
                                                        stop_vap="$stop_vap $ath"
                                                        uplink_states="$uplink_states down"
                                                fi
                                        fi
                                fi
                        fi
                        ;;
                user)
                        if [ "$service_state" == "down" ]; then
                                stop_vap="$stop_vap $ath"
                        else
                                scheduled=`within_schedule $ath`
                                if [ $scheduled == "true" ]; then
                                        run_vap="$run_vap $ath"
                                else
                                        stop_vap="$stop_vap $ath"
                                        touch "/var/run/schedule_wlan_stop_work.$ath"
                                fi
                        fi
                        ;;
                guest)
                        if [ "$service_state" == "down" ]; then
                                stop_vap="$stop_vap $ath"
                        elif [ -f /var/run/system.selfrun -a "`portal_enabled`" = "yes" -a "`selfrun_guest`" = "off" ]; then
                                stop_vap="$stop_vap $ath"
                        else
                                scheduled=`within_schedule $ath`
                                if [ $scheduled == "true" ]; then
                                        run_vap="$run_vap $ath"
                                else
                                        stop_vap="$stop_vap $ath"
                                        touch "/var/run/schedule_wlan_stop_work.$ath"
                                fi
                        fi
                        ;;
                downlink)
                        if [ "$downlink_state" == "down" ]; then
                                stop_vap="$stop_vap $ath"
                        else
                                run_vap="$run_vap $ath"
                        fi
                        ;;
                wireless-bridge)
                        run_vap="$run_vap $ath"
                        ;;
                wireless-bridge-failover)
                        # Bring down the failover link in default state no matter
                        # udhcpc lease fail or not
                        if [ "$ath" == "${PRS_INTC}" ]; then
                                brctl delif br0 $ath
                        fi
                        stop_vap="$stop_vap $ath"
                        ;;
                esac
        done

        # Currently we set vap_ind = 1 for wds vap, simply relying
        # on uplink-monitor to adjust vap status.
        # QCA requires wds vap to be up before all ap vap.

        for ath in $stop_vap; do
                ifconfig $ath down
        done
        for ath in $run_vap; do
                if [ "${MTK_UAP}" == "1" -a `check_if_hostapd_killed $ath` == "true" ]; then
                        :
                else
                        ifconfig $ath up
                fi
        done
#       log "[configure_vap] \$n_uplink_vaps = $n_uplink_vaps"
#       log "[configure_vap] \$uplink_vaps = $uplink_vaps"
#       log "[configure_vap] \$uplink_states = $uplink_states"
        for i in `seq 1 $n_uplink_vaps`; do
                ath=`echo $uplink_vaps | cut -d " " -f $i`
                action=`echo $uplink_states | cut -d " " -f $i`
                configure_uplink $ath $action
        done
}

# obtain lock first
cfg_save() {
        set_state 'cfgupdate'
        cfgmtd -w -p /etc /tmp/system.cfg
        set_state_ready
}

# add_mac <file> <mac>
add_mac() {
        del_mac "$1" "$2"
        echo "$2" >> $1
}

# del_mac <file> <mac>
del_mac() {
        file=$1
        mac=$2
        tmp=/tmp/macs.`basename $file`

        grep -vi "$mac" $file > $tmp
        cp $tmp $file
}

# mac2serial <mac>
mac2serial() {
        echo $1 | sed -e 's/://g' -e 'y/ABCDEF/abcdef/'
}

# pkill_generic <process_name> [signal] [args]
pkill_generic() {
        local process=$1
        local signal=$2
        shift; shift;
        local SIG_FIRST=$(/usr/bin/pkill 2>&1 | grep Usage | grep -c "\-SIGNAL")
        if [ $SIG_FIRST -eq 1 ]; then
                /usr/bin/pkill $signal $* "$process";
        else
                /usr/bin/pkill $* $signal "$process";
        fi
}

# returns "yes" | "no"
portal_enabled() {
        portal_status=`cat /tmp/system.cfg|grep redirector.status=enabled`
        if [ "$portal_status" = "" ]; then
                echo "no"
        else
                echo "yes"
        fi
}

selfrun_guest() {
        selfrun_guest_mode=`grep selfrun_guest_mode /etc/persistent/cfg/mgmt | cut -d= -f 2`
        if [ "$selfrun_guest_mode" = "off" ]; then
                echo "off"
        else
                echo "pass"
        fi
}

# authorized_guests_updated
authorized_guests_updated() {
        if [ "`portal_enabled`" = "yes" ] ; then
                ebtables -t nat -F AUTHORIZED_GUESTS
                ipset -q list ${IPSET_GUEST_AUTHORIZED_MAC} >/dev/null 2>&1
                if [ $? -eq 0 ]; then
                        # ipset exists, flush its contents.
                        ipset flush ${IPSET_GUEST_AUTHORIZED_MAC}
                else
                        # ipset does not exist, create it.
                        ipset create ${IPSET_GUEST_AUTHORIZED_MAC} hash:mac
                fi
                        if [ -s "$1" ]; then
                        # read through all authorized guests and add them to ipset
                                while IFS='' read -r mac || [[ -n "$mac" ]]; do
                                        ipset add ${IPSET_GUEST_AUTHORIZED_MAC} $mac
                                done < "$1"
                        fi
                ebtables -t nat -A AUTHORIZED_GUESTS --set  ${IPSET_GUEST_AUTHORIZED_MAC} --set-flags src -j ACCEPT
                else
                # portal is disabled, flush ipset and AUTHORIZED_GUESTS
                ebtables -t nat -F AUTHORIZED_GUESTS
                ipset flush ${IPSET_GUEST_AUTHORIZED_MAC}
        fi
}

abort_60g_radio_scan() {
        if [ -c ${PRS_DEVNODE} ] && [ -n "`lsmod | grep ${PRS_MOD}`" ]; then
                prsnl dev ${PRS_INTC} scan abort
        fi
}

do_upgrade() {
        local rc
        set_state 'upgrading'
        abort_60g_radio_scan
        _set_led 12 120 1
        _upgrade
        rc=$?
        set_state_ready
        return ${rc}
}

do_upgrade_keeprunning() {
        local rc
        set_state 'upgrading'
        _set_led 12 120 1
        _upgrade_keep_running
        rc=$?
        set_state_ready
        return ${rc}
}

do_fast_apply() {
        rm -rf /tmp/apply.sh
        if ubntconf -c /tmp/system.cfg -p /tmp/running.cfg -d /tmp/apply.sh; then
                log "[apply-config] using fast apply"
                if [ -f /tmp/apply.sh ]; then
                        if /bin/sh /tmp/apply.sh; then
                                cp -f /tmp/running.cfg /tmp/previous.cfg
                                cp -f /tmp/system.cfg /tmp/running.cfg
                                return 0
                        fi
                        log "[error] fast-apply failed"
                        return 1
                fi
                return 0
        fi
        return 1
}

do_custom_alert() {
        if [ `expr $# % 2` -ne 0 ];then
                echo "$# not pairwise input!!"
                return 1
        fi

        if [ "$2" = "STA_ASSOC_TRACKER" ]; then
                grep ^mgmt.capability.*notif-assoc-stat /var/etc/persistent/cfg/mgmt >/dev/null 2>&1
                if [ $? -ne 0 ]; then
                        return 1
                fi
        fi

        input_key_value=
        while [ $# -ne 0 ];do
                key=$(echo "$1" | tr '\n' ' '| sed 's/ $//')
                val=$(echo "$2" | tr '\n' ' '| sed 's/ $//')
                input_key_value="$input_key_value -k \"$key\" -v \"$val\""
                shift
                shift
        done
        sh -c "/usr/bin/mca-custom-alert.sh ${input_key_value}"
}

helper_ssid_war() {
        default="false"
        if [ -f /proc/ubnthal/status/IsDefault ]; then
                default=`cat /proc/ubnthal/status/IsDefault`
        fi
        if [ "$default" = "true" ]; then
                sysid=`awk -F= '/^systemid=/{print $2}' /proc/ubnthal/system.info`
                if [ "$sysid" = "e302" -o "$sysid" = "e502" -o "$sysid" = "e512" -o "$sysid" = "e532" -o "$sysid" = "e562" -o "$sysid" = "e592" ]; then
                        killall -1 hostapd
                fi
        fi
}

renew_ip_on_subnet_change() {
        local ifname=$1
        local newSubnet=$2
        local newNetmask=$3
        local startRetry=$4
        local retryTimer=$5
        local stopRetry=$6
        local pid=`cat /var/run/udhcpc.$ifname.pid`
        #sleep for a while to give some time for subnet change, dhcp server restart
        log "renew_ip_on_subnet_change sleeps for $startRetry seconds"
        sleep $startRetry
        # try to renew ip for at most stopRetry(300) seconds.
        while [ $stopRetry -gt 0 ]; do
                #release current release and obtain a new lease
                kill -SIGUSR2 $pid
                kill -SIGUSR1 $pid
                log "renew_ip_on_subnet_change sleeps for $retryTimer seconds"
                sleep $retryTimer
                stopRetry=$((stopRetry - retryTimer))

                local ip=`ifconfig $ifname | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*'`
                if [ ! -z "$ip" ]; then
                        local valid=1
                        #check if the device ip is in the new subnet. If so, we are done.
                        for i in 1 2 3 4; do
                                local ip_octet=`echo "$ip" | cut -d . -f $i`
                                local netmask_octet=`echo "$newNetmask" | cut -d . -f $i`
                                local subnet_octet=`echo "$newSubnet" | cut -d . -f $i`
                                if [ $(( $ip_octet & $netmask_octet )) -ne $subnet_octet ]; then
                                        valid=0
                                        break
                                fi
                        done
                        if [ "$valid" -eq 1 ]; then
                                log "dchp renew: got a valid ip. ip: $ip. exiting."
                                break
                        else
                                log "dhcp renew: ip is not in the new subnet. ip: $ip, subnet: $newSubnet, netmask: $newNetmask. retrying..."
                        fi
                fi
        done
        if [ $stopRetry -le 0 ]; then
                log "dhcp renew: unable to renew ip. timeout expired!"
        fi
}

renew_ip_on_dhcp_range_change() {
        local ifname=$1
        local newDhcpStart=$2
        local newDhcpStop=$3
        local startRetry=$4
        local retryTimer=$5
        local stopRetry=$6
        local pid=`cat /var/run/udhcpc.$ifname.pid`
        log "renew_ip_on_dhcp_range_change sleeps for $startRetry seconds"
        sleep $startRetry
        while [ $stopRetry -gt 0 ]; do
                /usr/bin/kill -SIGUSR2 $pid
                /usr/bin/kill -SIGUSR1 $pid
                log "renew_ip_on_dhcp_range_change sleeps for $retryTimer seconds"
                sleep $retryTimer
                stopRetry=$((stopRetry - retryTimer))

                local ip=`ifconfig $ifname | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*'`
                if [ ! -z "$ip" ]; then
                        local ip_long=0
                        local dhcpStart_long=0
                        local dhcpStop_long=0
                        #check if the device ip is within the dhcp range. If so, we are done.
                        for i in 1 2 3 4; do
                                local ip_octet=`echo "$ip" | cut -d . -f $i`
                                local dhcpStart_octet=`echo "$newDhcpStart" | cut -d . -f $i`
                                local dhcpStop_octet=`echo "$newDhcpStop" | cut -d . -f $i`
                                ip_long=$((ip_long<<8))
                                ip_long=$((ip_long+ip_octet))
                                dhcpStart_long=$((dhcpStart_long<<8))
                                dhcpStart_long=$((dhcpStart_long+dhcpStart_octet))
                                dhcpStop_long=$((dhcpStop_long<<8))
                                dhcpStop_long=$((dhcpStop_long+dhcpStop_octet))
                        done
                        if [ "$ip_long" -ge "$dhcpStart_long" ] && [ "$ip_long" -le "$dhcpStop_long" ]; then
                                log "dhcp renew: got a valid ip. ip: $ip. exiting."
                                break
                        else
                                log "dhcp renew: dhcprange failed. ip: $ip, required range: $newDhcpStart - $newDhcpStop. retrying..."
                        fi
                fi
        done
        if [ $stopRetry -le 0 ]; then
                log "dhcp renew: unable to renew ip. timeout expired!"
        fi
}

cmd="$1"
shift

debug_log "cmd: $cmd $*"

elevenk_run() {
    period_all=$1; shift
    scans=$1; shift
    msg=$1; shift
    radios="$@"
    shift
    msg="$msg radios:$radios"
    if [ "$radios" = "all" -o ! "$radios" ]
    then
        scan_cmd="syswrapper.sh scan"
    else
        scan_cmd="("
        for radio in $radios; do
            scan_cmd="$scan_cmd syswrapper.sh scan_radio $radio; "
        done
        scan_cmd="$scan_cmd )"
    fi

    delay=10
    for i in `seq 1 $scans`
    do
        period_all=$((period_all-delay))
        if [ "$period_all" -lt 1 ]; then period_all=1; fi
        rand_delay=$(( `tr -cd 0-9 </dev/urandom | head -c 8 | sed 's/^0*//'` % $period_all ))
        if [ "$period_all" -lt 1 ]; then period_all=1; fi
        period_all=$((period_all-rand_delay))
        logger "11k scan: sleeping for $delay + $rand_delay seconds, then $scan_cmd"
        sleep $delay && sleep $rand_delay && logger "scan nr $i of $scans for 11k ($msg)" && eval $scan_cmd
    done
    rm -f $PID_11K
}

# Kill pending scans for 11k
elevenk_stop() {
    if [ -f $PID_11K ]; then
        kill -9 `cat $PID_11K`
        rm -f $PID_11K
    fi
}

elevenk_sched() {
    elevenk_stop
    elevenk_run "$@" &
    echo $! > $PID_11K
}

# Scan neighbours every day.
# Executes 2 scans during 1h time slot. Every scan is executed randomly during 60min/2 window.
elevenk_scan() {
    elevenk_sched 3600 2 nightly all
}

# Scan neighbours after boot/re-configuration.
# Executes 2 scans during 5min time slot. Every scan is executed randomly during 5min/2 window.
elevenk_boot() {
    elevenk_sched 300 2 init "$@"
}

# Reset DFS channel
#
# Automatic Channel and Power Selection on UniFi
# Stage 0 - DFS retry
#
# For APs for which manual DFS channels have been chosen, attempt to switch back to DFS channels at 2AM local time.
#
# Concerns: 5G devices, like AP PRO, AP PRO AC, AP PRO AC Lite.
# Does not apply to: AP v2 (no 5G radio)
#
# Any logs will be logged to syslog (usually /var/log/messages).
#
dfs_reset_mtk() {
        # AP configuration - here we read channels for radio interfaces
        FILE_CFG=/tmp/running.cfg

        # Get list of interfaces to check (with non-empty ESSID)]
        IF_LIST=`iwconfig 2>&1 | grep ESSID | grep -v 'ESSID:""' | awk '{print $1}'`

        # Compute actual frequency and channels and compare with configured channels
        for i in $IF_LIST
        do
                # Find actual frequency and test 5G channels only
                CHAN=`iwconfig $i | grep Channel | awk '{print $2}' | awk -F= '{print $2}'`
                MODE=`iwconfig $i | grep Mode | sed -e 's/^.*Mode://' | awk '{print $1}'`

                if [ "$CHAN" -lt "36" -o "$MODE" != "Master" ]
                then
                        continue
                fi

                # Obtain actual channel
                CH_ACT=`iwlist $i frequency | grep Current | sed -e 's/^.*Channel://'`

                # Obtain configured channel
                IF_INDEX=`grep radio.[0-9][0-9]*.virtual.[0-9][0-9]*.devname=$i ${FILE_CFG} | awk -F. '{print $2}' | uniq`
                # Retry finding index if virtual BSS has not been found
                if [ -z "${IF_INDEX}" ]
                then
                        IF_INDEX=`grep radio.[0-9][0-9]*.devname=$i ${FILE_CFG} | awk -F. '{print $2}' | uniq`
                fi
                # Skip if no index was found
                if [ -z "${IF_INDEX}" ]
                then
                        continue
                fi
                CH_CFG=`grep radio.${IF_INDEX}.channel ${FILE_CFG} | awk -F= '{print $2}' | uniq`
                # Skip if auto or 0 (synonym), or not found
                if [ -z "${CH_CFG}" -o "${CH_CFG}" == "auto" -o "${CH_CFG}" == "0" ]
                then
                        continue
                fi
                # Debug info
                LOG_MSG="$i ${CHAN}: actual:${CH_ACT} conf(${IF_INDEX}):${CH_CFG} "
                # Set radio back to DFS channel, if actual is different than configured
                if [ "${CH_ACT}" == "${CH_CFG}" ]
                then
                        : # skip dfs reset
                else
                        iwpriv ${i} set Channel="${CH_CFG}" 2>&1 > /dev/null
                        RET_CODE=$?
                        if [ $RET_CODE -eq 0 ]
                        then
                                RET_MSG="OK "
                        else
                                #interesting info is logged in `dmesg | tail -1`
                                RET_MSG="FAIL(${RET_CODE}) "
                        fi
                        logger "${LOG_MSG}dfs reset chan: ${CH_ACT}=>${CH_CFG} ${RET_MSG}"
                        #mca-custom-alert.sh -k CH_ACT -v ${CH_ACT} -k CH_CFG -v ${CH_CFG} -k RET_MSG -v ${RET_MSG}
                fi
        done
}

dfs_reset() {
        if [ "${MTK_UAP}" == "1" ]; then
                dfs_reset_mtk
        else
        # AP configuration - here we read channels for radio interfaces
        FILE_CFG=/tmp/running.cfg

        # Get list of interfaces to check (with non-empty ESSID)
        IF_LIST=`iwconfig 2>&1 | grep ESSID | grep -v 'ESSID:""' | awk '{print $1}'`

        # Compute actual frequency and channels and compare with configured channels
        for i in $IF_LIST
        do
                # Find actual frequency and test 5G channels only
                FREQ=`iwconfig $i | grep Frequency | awk '{print $2}' | awk -F: '{print $2}' | sed 's/\.//'`
                MODE=`iwconfig $i | grep Mode | sed -e 's/^.*Mode://' | awk '{print $1}'`
                FCHAR="$(echo $FREQ | head -c 1)"
                if [ "$FCHAR" != "5" -o "$MODE" != "Master" ]
                then
                        continue
                fi
                # Append zero-s if frequency is eg. 526 for 5260 MHz
                FLEN=`expr length $FREQ`
                while [ $FLEN -lt 4 ]
                do
                        FREQ="${FREQ}0"
                        FLEN=`expr length $FREQ`
                done
                # Obtain actual channel
                CH_ACT=`iwlist $i frequency | grep Current | sed -e 's/^.*Channel //' -e 's/)//'`
                # Obtain configured channel
                IF_INDEX=`grep radio.[0-9][0-9]*.virtual.[0-9][0-9]*.devname=$i ${FILE_CFG} | awk -F. '{print $2}' | uniq`
                # Retry finding index if virtual BSS has not been found
                if [ -z "${IF_INDEX}" ]
                then
                        IF_INDEX=`grep radio.[0-9][0-9]*.devname=$i ${FILE_CFG} | awk -F. '{print $2}' | uniq`
                fi
                # Skip if no index was found
                if [ -z "${IF_INDEX}" ]
                then
                        continue
                fi
                CH_CFG=`grep radio.${IF_INDEX}.channel ${FILE_CFG} | awk -F= '{print $2}' | uniq`
                # Skip if auto or 0 (synonym), or not found
                if [ -z "${CH_CFG}" -o "${CH_CFG}" == "auto" -o "${CH_CFG}" == "0" ]
                then
                        continue
                fi
                # Debug info
                LOG_MSG="$i ${FREQ}MHz: actual:${CH_ACT} conf(${IF_INDEX}):${CH_CFG} "
                # Set radio back to DFS channel, if actual is different than configured
                if [ "${CH_ACT}" == "${CH_CFG}" ]
                then
                        : # skip dfs reset
                else
                        iwconfig ${i} channel ${CH_CFG} 2>&1 > /dev/null
                        RET_CODE=$?
                        if [ $RET_CODE -eq 0 ]
                        then
                                RET_MSG="OK "
                        else
                                #interesting info is logged in `dmesg | tail -1`
                                RET_MSG="FAIL(${RET_CODE}) "
                        fi
                        logger "${LOG_MSG}dfs reset chan: ${CH_ACT}=>${CH_CFG} ${RET_MSG}"
                        #mca-custom-alert.sh -k CH_ACT -v ${CH_ACT} -k CH_CFG -v ${CH_CFG} -k RET_MSG -v ${RET_MSG}
                fi
        done
        fi
}

err() {
        local rc msg
        rc=$1
        shift
        msg=$*
        >&2 echo "ERROR: ${msg}"
        exit ${rc}
}

upgrade_err_notify() {
        local issued_by rc notify
        issued_by=$1
        rc=$2
        notify=$3

        if [ "${issued_by}" != "cmdline" ] ; then
                upgrade_err "${rc}" "${notify}"
        fi
}

err_internal() {
        local STATUSFILE=$1
        local LOG_PREFIX=$2
        local failed_type=$3
        local issued_by=$4
        local result="failed_internal"
        local status_msg err_msg
        upgrade_err_notify "${issued_by}" "99" "DeviceInternalFailed"
        case "${failed_type}" in
                1)
                        status_msg="(cannot upgrade and keep running)"
                        err_msg="Device does not support keep running upgrade!"
                        ;;
                2)
                        status_msg="(upgrade from exist files, doesn't support download only)"
                        err_msg="upgrade from exist files, doesn't support download only"
                        ;;
                3)
                        local url=$5
                        status_msg="(no curl)"
                        err_msg="Cannot retrieve non-local firmware ${url} (missing curl)!"
                        ;;
                4)
                        local TMPDIR=$5
                        status_msg="(mkdir -p ${TMPDIR})"
                        err_msg="Cannot create directory ${TMPDIR}!"
                        ;;
                5)
                        local file=$5
                        status_msg="(mv ${file} /tmp/fwupdate.bin)"
                        err_msg="Failed moving ${file} to /tmp/fwupdate.bin"
                        ;;
                6)
                        local file=$5
                        status_msg="(get md5sum from ${file})"
                        err_msg="Failed to get md5sum from ${file}"
                        ;;
                7)
                        local file=$5
                        status_msg="(check md5sum from ${file})"
                        err_msg="md5sum mismatch from ${file} and original downloaded firmware"
                        ;;
                *)
                        status_msg="unknow failed type ${failed_type}!"
                        err_msg="Unknow internal failed type ${failed_type}!"
                        ;;
        esac

        set_status "${STATUSFILE}" "${LOG_PREFIX}" "${result}" "${status_msg}"
        unlock_and_err ${FW_LOCKFILE} 6 "${err_msg}"
}

fw_status_handle() {
        local STATUSFILE=$1
        local LOG_PREFIX=$2
        local fw_status=$3
        local issued_by=$4
        local ver=$5
        local result ace_notify error_msg fw_sum
        case "${fw_status}" in
                1)
                        result="failed_fwcheck"
                        ace_notify="FirmwareCheckFailed"
                        error_msg="Firmware: ${ver} doesn't fit the system!\n"
                        ;;
                2)
                        result="done_fw_download"
                        ace_notify="FWDownloadOK"
                        fw_sum=$6
                        ;;
                3)
                        result="done_fwwrite"
                        ace_notify="FWWriteOK"
                        fw_sum=$6
                        ;;
                *)
                        result="unknown_fw_status"
                        ace_notify="FWStateInternalFailed"
                        error_msg="Unknow firmware status type ${fw_status}!"
                        ;;
        esac

        set_status ${STATUSFILE} "${LOG_PREFIX}" "${result}" "(${ver})"
        if [ -n "${error_msg}" ]; then
                upgrade_err_notify "${issued_by}" "99" "${ace_notify}"
                unlock_and_err ${FW_LOCKFILE} 10 "${error_msg}"
        else
                upgrade_stage_notify "${issued_by}" "${ace_notify}" "${ver}" "${fw_sum}"
                _unlockfile ${FW_LOCKFILE}
        fi
}

upgrade_stage_notify() {
        local issued_by notify ver fw_sum
        issued_by=$1
        notify=$2
        ver=$3
        fw_sum=$4
        if [ "${issued_by}" != "cmdline" ] ; then
                upgrade_download_ready "${notify}" "${ver}" "${fw_sum}"
        fi
}

unlock_and_err() {
        local lockfile
        lockfile=$1
        _unlockfile ${lockfile}
        shift
        err $*
}

is_support_keeprunning() {
        need_ramfs
        local rc=$?
        if [ `grep -c ubntboot /proc/cmdline` -lt 1 -a `grep -c cpu=BCM53003 /proc/ubnthal/system.info` -lt 1 -a $rc -eq 0 ]; then
                return 1
        else
                return 0
        fi
}

set_status() {
        local result statusfile logprefix endtime extra_note
        statusfile=$1
        logprefix="$2"
        result="$3"
        if [ $# -gt 3 ]; then
                extra_note=" $4"
        else
                extra_note=""
        fi
        local LASTSTATUS="/var/run/fwupdate.last"
        local FWUPDATELOG="/var/log/fwupdate.log"
        endtime=$(date +"%F_%T")
        echo -e "${logprefix}\t${endtime}\t${result}\t" >> ${FWUPDATELOG}
        set_fwupdate_status "${statusfile}" "${result}${extra_note}"
        set_last_status "${statusfile}" "${LASTSTATUS}"
}

set_fwupdate_status() {
        local statusfile status
        statusfile=$1
        shift
        status=$*
        echo ${status} > ${statusfile}
}

set_last_status() {
        local lastfile statusfile
        lastfile=$2
        statusfile=$1
        [ ! -f ${lastfile} ] || rm -rf ${lastfile}
        ln -s ${statusfile} ${lastfile}
}

curl_with_retry() {
        local cmd=$1
        local tries=18
        for x in $(seq ${tries}); do
                http_code=$(${cmd})
                rc=$?
                if [ "$rc" = "0" ]; then
                        if [ "${http_code}" = "200" ]; then
                                break
                        elif echo "$cmd" | grep -i -q 'ftp://' && [ "${http_code}" = "226" ]; then
                                http_code=200
                                break
                        fi
                fi
                logger "unable to download fw (rc: ${rc} http: ${http_code})"
                if [ $(expr ${x}) -ne $tries ]; then
                        sleep 10
                fi
        done

        echo ${http_code}
        return $rc
}

do_getcurrentfwupdatestatus() {
        local PID STATUSFILE
        _lockfile 0 ${FW_LOCKFILE}
        rc=$?
        if [ $rc -ne 0 ]; then
                PID=$(cat ${FW_LOCKFILE})
                STATUSFILE="/var/log/fwupdate.status.${PID}"
                [ ! -f ${STATUSFILE} ] || cat ${STATUSFILE}
                return 0
        fi
        _unlockfile ${FW_LOCKFILE}
        echo "none"
        return 1
}

do_getlastfwupdateresult() {
        local LASTSTATUS
        LASTSTATUS="/var/run/fwupdate.last"
        [ ! -f ${LASTSTATUS} ] || cat ${LASTSTATUS}
}

# --issued-by           == who issued the fwupdate
# --dl-only             == firmware download only, don't do firmware update
# --md5sum              == pre-download firmware md5sum, to confirm the firmware is what we want
# --keep-firmware       == keep firmware file even firmware check failed
# --keep-running        == keep system running even after firmware update successfully
# --reboot-sys          == reboot system after firmware update successfully
do_fwupdate() {
        local file ver rc
        local url opt
        local arguments starttime endtime result
        if [ -z "${1}" ]; then
                err 2 "No update url or file!"
        fi

        starttime=$(date +"%F_%T")
        arguments="$*"
        url=${1}
        shift

        local fwbin_sum=
        local dl_tries=-1
        local dl_retry_delay=-1
        local keeprunning=0
        local dl_only=0
        local keepfw=0
        local rebootsys=0
        local issued_by="cmdline"
        for opt in $*; do
                case ${opt} in
                --md5sum=*)
                        fwbin_sum=${opt:9}
                        ;;
                --dl-only)
                        dl_only=1
                        ;;
                --dl-tries=*)
                        dl_tries=${opt:11}
                        ;;
                --dl-retry-delay=*)
                        dl_retry_delay=${opt:17}
                        ;;
                --issued-by=*)
                        issued_by=${opt:12}
                        ;;
                --reboot-sys)
                        rebootsys=1
                        ;;
                --keep-firmware)
                        keepfw=1
                        ;;
                --keep-running)
                        keeprunning=1
                        ;;
                esac
        done
        local PID=$$
        local STATUSFILE="/var/log/fwupdate.status.${PID}"
        local LOG_PREFIX="${PID}\t[${issued_by}]\t${arguments}\t${starttime}"
        _lockfile 0 ${FW_LOCKFILE}
        rc=$?
        if [ $rc -ne 0 ]; then
                result="failed_lockfile"
                set_status ${STATUSFILE} "${LOG_PREFIX}" "${result}"
                err 1 "cannot aquire lock file (${FW_LOCKFILE}) !"
        fi
        if ! is_support_keeprunning ; then
                if [ ${keeprunning} -gt 0 ]; then
                        err_internal "${STATUSFILE}" "${LOG_PREFIX}" "1" "${issued_by}"
                fi
        fi

        if [ -e "${url}" ]; then
                file="${url}"
        elif [ -e "/tmp/${url}" ]; then
                file="/tmp/${url}"
        fi

        if [ -e "${file}" ]; then
                if [ ${dl_only} -gt 0 ]; then
                        err_internal "${STATUSFILE}" "${LOG_PREFIX}" "2" "${issued_by}"
                fi
                if [ -z "${fwbin_sum}" ]; then
                        err_internal "${STATUSFILE}" "${LOG_PREFIX}" "6" "${issued_by}" "${file}"
                fi
                # upgrade from a exist local files
                result=$(md5sum ${file} | grep -c ${fwbin_sum})
                rc=$?
                if [ $rc -ne 0 ]; then
                        err_internal "${STATUSFILE}" "${LOG_PREFIX}" "7" "${issued_by}" "${file}"
                fi
        else
                # upgrade from remote files
                local curl_cmd curl_opt
                curl_cmd=$(command -v curl 2>/dev/null)
                curl_opt="-s -L"

                if [ ! -n "${curl_cmd}" ] ; then
                        err_internal "${STATUSFILE}" "${LOG_PREFIX}" "3" "${issued_by}" "${url}"
                fi
                [ -n "${TMPDIR}" ] || TMPDIR=/tmp
                mkdir -p "${TMPDIR}"
                rc=$?
                if [ ${rc} -ne 0 ] ; then
                        err_internal "${STATUSFILE}" "${LOG_PREFIX}" "4" "${issued_by}" "${TMPDIR}"
                fi
                local http_code=0
                rm -f ${TMPDIR}/fwupdate.??????????
                file=$(mktemp -p "${TMPDIR}" fwupdate.XXXXXXXXXX)
                rc=0
                set_status ${STATUSFILE} "${LOG_PREFIX}" "downloading"
                if [ -n "${curl_cmd}" ]; then
                        [ ${dl_tries} -gt 0 ] && curl_opt="${curl_opt} --retry ${dl_tries}"
                        [ ${dl_retry_delay} -gt 0 ] && curl_opt="${curl_opt} --retry-delay ${dl_retry_delay}"
                        full_cmd="${curl_cmd} ${curl_opt} -o ${file} -w %{http_code} ${url}"
                        http_code=$(curl_with_retry "$full_cmd")
                        rc=$?
                        if [ $rc -ne 0 ]; then
                                curl_opt="${curl_opt} -4"
                                full_cmd="${curl_cmd} ${curl_opt} -o ${file} -w %{http_code} ${url}"
                                http_code=$(curl_with_retry "$full_cmd")
                                rc=$?
                        fi
                else
                        # should never get here..
                        rc=69
                fi

                if [ "${http_code}" != "200" ]; then
                        rm -f ${file}
                        result="failed_download"
                        set_status ${STATUSFILE} "${LOG_PREFIX}" "${result}" "(${url}) rc: ${rc}, http_code: ${http_code}"
                        if [ "${issued_by}" != "cmdline" ] ; then
                                download_err "${rc}" "${http_code}"
                        fi
                        unlock_and_err ${FW_LOCKFILE} 3 "Failed downloading firmware from ${url}, rc: ${rc}, http_code: ${http_code}"
                fi
        fi

        set_status ${STATUSFILE} "${LOG_PREFIX}" "fw checking"
        if command -v fwupdate.real >/dev/null 2>&1; then
                fwupdate.real -c ${file} 2>&1
                rc=$?
                ver=$(fwupdate.real -c -d ${file} 2>&1 | awk -F. '/New ver/ { printf "%s.%s\n", $3, $4 }')
                if [ $rc -ne 0 ]; then
                        [ ${keepfw} -gt 0 ] || rm -f ${file}
                        fw_status_handle "${STATUSFILE}" "${LOG_PREFIX}" "1" "${issued_by}" "${ver}"
                fi
        fi
        >&2 echo "Firmware: ${ver}"

        set_status ${STATUSFILE} "${LOG_PREFIX}" "fw moving"
        if [ "/tmp/fwupdate.bin" != "${file}" ]; then
                mv -f "${file}" /tmp/fwupdate.bin
                rc=$?
                if [ $rc -ne 0 ]; then
                        [ ${keepfw} -gt 0 ] || rm -f ${file}
                        err_internal "${STATUSFILE}" "${LOG_PREFIX}" "5" "${issued_by}" "${file}"
                fi
        fi

        set_status ${STATUSFILE} "${LOG_PREFIX}" "md5sum create"
        fwbin_sum=$(md5sum /tmp/fwupdate.bin | awk '{print $1}')
        rc=$?
        if [ $rc -ne 0 ]; then
                [ ${keepfw} -gt 0 ] || rm -f ${file}
                err_internal "${STATUSFILE}" "${LOG_PREFIX}" "6" "${issued_by}" "${file}"
        fi

        if [ ${dl_only} -gt 0 ]; then
                # notify status and unlock fwupdate
                fw_status_handle "${STATUSFILE}" "${LOG_PREFIX}" "2" "${issued_by}" "${ver}" "${fwbin_sum}"
                echo ${fwbin_sum} > ${FW_MD5SUMFILE}
                return 0
        fi

        upgrade_stage_notify "${issued_by}" "FWDownloadOK" "${ver}" "${fwbin_sum}"
        set_status ${STATUSFILE} "${LOG_PREFIX}" "updating"
        >&2 echo "Firmware file looks good - updating..."
        state_lock
        if [ ${keeprunning} -gt 0 ]; then
                do_upgrade_keeprunning
                rc=$?
        else
                do_upgrade
                rc=$?
        fi
        [ ${keepfw} -gt 0 ] || rm -f /tmp/fwupdate.bin
        [ ${keepfw} -gt 0 ] || rm -f ${FW_MD5SUMFILE}
        state_unlock
        if [ $rc -ne 0 ]; then
                result="failed_fwwrite"
                set_status ${STATUSFILE} "${LOG_PREFIX}" "${result}"
                if [ ${keeprunning} -gt 0 ]; then
                        upgrade_err_notify "${issued_by}" "${rc}" "FWWriteFailed"
                fi
                unlock_and_err ${FW_LOCKFILE} 11 "Failed writing firmware to flash"
        fi
        echo "${ver}" > /var/run/fwversion.next
        fw_status_handle "${STATUSFILE}" "${LOG_PREFIX}" "3" "${issued_by}" "${ver}" "${fwbin_sum}"
        if [ ${rebootsys} -gt 0 ] ; then
                reboot
        fi
}

upgrade_err() {
        local err_code=$1
        local reason=$2
        local sub_reason=${3:-""}
        local err_info=${4:-'{}'}
        mca-custom-alert.sh -k "event_string" -v "Upgrade" -k "up_type" -v "UpgradeError" -k "rc" -v "${err_code}" -k "reason" -v "${reason}"
        ubntbox trace -n 'unifi:network:firmware:event' -t 'anomaly' "{
                \"reason\": \"system\",
                \"anomaly\": \"firmware upgrade failed\",
                \"ppid_cmdline\": \"$(ppid_cmdline)\",
                \"error\": {
                        \"code\": \"${err_code}\",
                        \"reason\": \"${reason}\",
                        \"sub_reason\": \"${sub_reason}\",
                        \"info\": ${err_info}
                }
        }"
        #sleep for send out the notification to the controller
        sleep 2
}

upgrade_err_and_restart() {
    upgrade_err "$@"
    $SCRIPT restart "fwupgrade-err"
    sleep 30
}

download_err() {
        local curl_err_code=$1
        shift
        local http_code=$1
        shift
        mca-custom-alert.sh -k "event_string" -v "Upgrade" -k "up_type" -v "UpgradeError" -k "curl_rc" -v "${curl_err_code}" -k "http_rc" -v "${http_code}" -k "reason" -v "FirmwareDownloadFailed"
        ubntbox trace -n 'unifi:network:firmware:event' -t 'anomaly' "{
                \"reason\": \"system\",
                \"anomaly\": \"firmware download failed\",
                \"curl_rc\": \"${curl_err_code}\",
                \"http_code\": \"${http_code}\",
                \"ppid_cmdline\": \"$(ppid_cmdline)\"
        }"
        #sleep for send out the notification to the controller
        sleep 2
}

download_err_and_restart() {
    download_err "$@"
    $SCRIPT restart "fwupgrade-download-err"
    sleep 30
}

upgrade_ready() {
        local msg
        msg=$*
        mca-custom-alert.sh -k "event_string" -v "Upgrade" -k "up_type" -v "UpgradeReady" -k "up_stage" -v "${msg}"
        sleep 2
}

upgrade_download_ready() {
        local dl_event ver fw_sum
        dl_event=$1
        ver=$2
        fw_sum=$3
        mca-custom-alert.sh -k "event_string" -v "Upgrade" -k "up_type" -v "UpgradeReady" -k "up_stage" -v "${dl_event}" -k "version" -v "${ver}" -k "md5sum" -v "${fw_sum}"
        sleep 2
}

update_hostapd_nas_ip_addr() {
        local ipaddr=$1
        find /etc/ -name "aaa*.cfg" | while read conf; do
                sed -i '/own_ip_addr/d' $conf
                echo "own_ip_addr=$ipaddr" >> $conf
                i_face=`grep -w "interface" $conf  | awk -F "=" '{print $NF}'`
                res=`hostapd_cli -p /var/run/hostapd -i $i_face set own_ip_addr $ipaddr`
                log "hostapd update: conf=$conf iterface=$i_face nas_ip=$ipaddr res=$res"
        done
}

host_lookup() {
  host=$(nslookup "$1" 2>/dev/null)
  if [ $? -ne 0 ]; then return 1; fi
  echo "$host" | grep "Address 1" | tail -n1 | awk '{print $3}'
}

random_ready() {
        if [ -f /proc/sys/kernel/random/entropy_avail ]; then
                [ $(cat /proc/sys/kernel/random/entropy_avail) -gt 0 ] && return 0
        fi
        return 1
}

netconsole_init() {
  local port=${2:-514}
  local key=${3:-""}
  ip=$(host_lookup "$1")
  if [ $? -ne 0 ]; then return 1; fi

  ping "$ip" -c 1 -W 3 >/dev/null 2>&1
  if nettool -i "$ip"; then
    # Is on LAN
    local lan_ip="$ip"
  else
    local lan_ip=$(route -n | grep "^0\.0\.0\.0" | awk '{print $2}')
  fi
  local ipready_file=$(ls -tr1 /var/run/ipready.* | tail -n1)
  local my_ip=$(cat "$ipready_file")
  local esc_lan_ip=$(echo "$lan_ip" | sed -e 's/\./\\./g')
  local arp=$(cat /proc/net/arp | awk "/^$esc_lan_ip[[:space:]]/"'{
    if ($4 == "00:00:00:00:00:00")
      return;
    print $4;
    exit;
  }')
  if [ -z "$arp" ]; then return 2; fi
  rmmod netconsole 2>/dev/null
  if [ -z "${key}" ]; then
    insmod netconsole "netconsole=514@$my_ip/eth0,$port@$ip/$arp"
  else
    random_ready || return 1;

    local hashid=$(cat /proc/ubnthal/system.info | grep "device.hashid" | awk -F '=' '{print $2}')
    insmod netconsole "netconsole=514@$my_ip/eth0,$port@$ip/$arp,$key,$hashid"
  fi
}

netconsole_loop() {
  local tries=10
  dmesg -n 8
  while [ $tries -gt 0 ]; do
    netconsole_init "$@"
    rc=$?
    if [ $rc -ne 0 ]; then
      logger "netconsole init failed, error $rc"
    else
      break
    fi
    sleep 60
    tries=$((tries-1))
  done
  rm -f $NETCONSOLE_PIDFILE
}

netconsole_daemon() {
  if [ -e $NETCONSOLE_PIDFILE ]; then
    kill -9 $(cat $NETCONSOLE_PIDFILE)
    rm -f $NETCONSOLE_PIDFILE
  fi
  ( netconsole_loop "$@") &
  echo $! > $NETCONSOLE_PIDFILE
}

do_linkswitch() {
        if [ -n "`ifconfig ${PRS_INTC} | grep UP`" ]; then
                prsnl dev ${PRS_INTC} scan abort
        fi

        vaps=`cat /var/run/wlan_devnames`

        for ath in $vaps; do
                usage="unknown"
                if [ -f /var/run/vapusage.$ath ]; then
                        usage=`cat /var/run/vapusage.$ath`
                fi
                if [ -f /var/run/cfg_error.$ath ]; then
                        usage=unusable
                fi
                case $usage in
                wireless-bridge)
                        echo "wireless-bridge-failover" > /var/run/vapusage.$ath
                        ;;
                wireless-bridge-failover)
                        echo "wireless-bridge" > /var/run/vapusage.$ath
                        ;;
                esac
        done
}

# helper to output opkg output to log
_opkg() {
        set -o pipefail
        opkg "$@" 2>&1 | logger -s -t "opkg"
        rc=$?
        set +o pipefail
        return $rc
}

# wrapper for opkg update && opkg install with retry logic
# (similar to curl --retry $retries --retry-delay $retry_delay)
install_runtime_package() {
        local package=$1
        local retries=${2:-6}
        local retry_delay=${3:-10}

        for x in $(seq $retries); do
                _opkg update && _opkg install --force-space $package && break

                if [ $x -ne $retries ]; then
                        sleep $retry_delay
                else
                        logger -s -t "opkg" "failed to install $package"
                fi
        done
}

# Assumes lock is held
clear_vlan_detected() {
        rm -f "$VLANS_FILE"
}

cache_vlan_detected() {
        if [ ! -d "$SWITCH_PROC" ]; then
                return 0
        fi

        if ! grep -q ^"$1"$ "$VLANS_FILE" 2>/dev/null; then
                logger -s -t vlan "vlan $1 detected"
                echo "$1" >> "$VLANS_FILE"
                return 1
        fi
        return 0
}

vlan_detected() {
        if [ ! -d "$SWITCH_PROC" ]; then
                return 0
        fi

        if ! cache_vlan_detected "$@"; then
                swconfig dev "$SWITCH_IFACE" set vlan_detected "$1"
        fi
}

ppid_comm() {
        local ppid=${1:-$PPID}
        cat /proc/$ppid/comm
}

ppid_cmdline() {
        local ppid=${1:-$PPID}
        cat /proc/$ppid/cmdline | xargs -0
}

del_bridge_vlans() {
        for br in $(ifconfig | grep "^$1\(\.\| \)" | sed -e "s/ .*//"); do
                for _iface in $(ls -1 /sys/class/net/${br}/brif); do
                        local iface=$(basename "$_iface")
                        if echo "$iface" | grep -q "\."; then
                                vconfig rem "$iface"
                        fi
                done
                ifconfig "$br" down
                brctl delbr "$br"
        done
}

sensitive_data_filter() {
        BYTE='(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])'
        IPV4="\<(${BYTE}\.){3}${BYTE}\>"
        HEXTET='[0-9a-fA-F]{1,4}'
        HEXBYTE='[a-fA-F0-9]{2}'

        # 6 hexadecimal bytes with optional separator from set ' :-' and none
        MAC_SED0="s/\<(${HEXBYTE}){6}\>/censored-mac/g"
        MAC_SED1="s/\<(${HEXBYTE} ){5}${HEXBYTE}\>/censored-mac/g"
        MAC_SED2="s/\<(${HEXBYTE}:){5}${HEXBYTE}\>/censored-mac/g"
        MAC_SED3="s/\<(${HEXBYTE}-){5}${HEXBYTE}\>/censored-mac/g"

        # IPv4 address
        IPV4_SED="s/${IPV4}/censored-ipv4/g"

        # filter out serial number
        SERIAL_NUM=$(cat /proc/ubnthal/system.info | grep "serialno" | cut -d '=' -f 2)
        SERNUM_SED="s/${SERIAL_NUM}/censored-sn/g"

        sed -E \
            -e "s@\<(${HEXTET}:){5}${HEXTET}?:$IPV4@censored-ipv4m6@g" \
            -e "s@\<(${HEXTET}:){4}(:${HEXTET}){0,1}:$IPV4@censored-ipv4m6@g" \
            -e "s@\<(${HEXTET}:){3}(:${HEXTET}){0,2}:$IPV4@censored-ipv4m6@g" \
            -e "s@\<(${HEXTET}:){2}(:${HEXTET}){0,3}:$IPV4@censored-ipv4m6@g" \
            -e "s@\<(${HEXTET}:){1}(:${HEXTET}){0,4}:$IPV4@censored-ipv4m6@g" \
            -e "s@:(:${HEXTET}){0,5}:$IPV4@censored-ipv4m6@g" \
            -e "s@\<(${HEXTET}:){7}${HEXTET}\>@censored-ipv6@g" \
            -e "s@\<(${HEXTET}:){6}(:${HEXTET})\>@censored-ipv6@g" \
            -e "s@\<(${HEXTET}:){5}(:${HEXTET}){1,2}\>@censored-ipv6@g" \
            -e "s@\<(${HEXTET}:){4}(:${HEXTET}){1,3}\>@censored-ipv6@g" \
            -e "s@\<(${HEXTET}:){3}(:${HEXTET}){1,4}\>@censored-ipv6@g" \
            -e "s@\<(${HEXTET}:){2}(:${HEXTET}){1,5}\>@censored-ipv6@g" \
            -e "s@\<(${HEXTET}:){1}(:${HEXTET}){1,6}\>@censored-ipv6@g" \
            -e "s@\<(${HEXTET}:){1,7}:@censored-ipv6@g" \
            -e "s@:(:${HEXTET}){1,7}\>@censored-ipv6@g" \
            -e "$SERNUM_SED" \
            -e "$MAC_SED0" -e "$MAC_SED1" -e "$MAC_SED2" -e "$MAC_SED3"\
            -e "$IPV4_SED" <&0
}

case $cmd in
set-tmp-ip)
        exit_if_fake $cmd $*
        ;;
set-adopt)
        # set-adopt <url> <authkey>
        mca-ctrl -t connect -s "$1" -k "$2"
        ;;
set-channel)
        # set-channel <radio> <channel>
        # FIXME: dual radio
        for ath in `ls /proc/sys/net/*/%parent | cut -d '/' -f 5`; do
                iwconfig $ath channel $1
        done
        ;;
ip-changed)
        # ip-changed <interface> <ip>
        OLDIP=`cat /var/run/ipready.$1`
        echo "$2" > /var/run/ipready.$1
        if [ "$OLDIP" = "$2" ]; then
                # No actual change - ignore
                return
        fi
        log "ipready.$1 = $2"
        # Notify processes that needs to know
        pkill_generic dropbear -KILL -x
        pkill_generic ntpclient -x
        pkill_generic uplink-monitor -USR1 -x
        pkill_generic wevent -USR1 -x
        # tmp workaround for nanohd snmpd issue
        if [ "${UAPNANOHD}" == "1" ]; then
                pkill_generic snmpd -x
        fi
        if ! route -n | grep "^0\.0\.0\.0.*br0" >/dev/null; then
                # Sleep if using uplink for default gateway, to avoid race with mca-cli-op inform
                sleep 5
        fi
        if [ -f /var/run/lldpd_para.sh ]; then
                pkill_generic lldpd -x
                sh /var/run/lldpd_para.sh
        fi
        [ $1 = "br0" ] && update_hostapd_nas_ip_addr $2
        # For downlink AP speed up wireless adoption process
        if [ -f "/var/run/uplink.url" ]; then
                url=`cat /var/run/uplink.url`
                mca-ctrl -t connect -s $url
        else
                mca-cli-op inform
        fi
        /bin/walled_action.sh /tmp/allowed.1.txt /tmp/restricted.1.txt &
        # activate tunnels, if any
        if [ -d /etc/tunnels ]; then
           for i in $(ls /etc/tunnels);
           do /usr/etc/activate_tunnel.sh $i up;
           done
        fi

        if [ -d /var/run/schedules -a ! -f /tmp/.factorytest ]; then
                timeout=30
                timer=2
                while [ $timeout -gt 0 ]; do
                        if [ $(date +%s) -gt $(date +%s -d "2017-01-01 00:00:00") ]; then
                                schedule_action
                                break
                        else
                                sleep $timer
                                timeout=$((timeout - timer))
                        fi
                done
        fi
        ;;
dhclient-restart)
        ifname=$1
        if [ -f /var/run/udhcpc.$ifname.pid ]; then
                killall udhcpc
        fi
        ;;
dhclient-renew-subnet)
        ifname=$1
        #do not renew ip if the device has static ip. if /var/run/udhcpc.eth0.pid file exists => dhcp and not static.
        if [ -f /var/run/udhcpc.$ifname.pid ]; then
                renew_ip_on_subnet_change "$@"
        fi
        ;;
dhclient-renew-dhcprange)
        ifname=$1
        if [ -f /var/run/udhcpc.$ifname.pid ]; then
                renew_ip_on_dhcp_range_change "$@"
        fi
        ;;
led-locate)
        exit_if_busy $cmd $*
        # led-locate <duration>
        pkill_generic led_locate.sh -f
        # background this one so we'll return immediately
        /usr/etc/led_locate.sh $1 &
        ;;
set-locate)
        exit_if_busy $cmd $*
        exit_if_state_lock_failed $cmd $*
        pkill_generic led_locate.sh -f
        echo "true" > /proc/ubnthal/status/IsLocated
        state_reload
        state_unlock
        ;;
unset-locate)
        exit_if_busy $cmd $*
        exit_if_state_lock_failed $cmd $*
        pkill_generic led_locate.sh -f
        echo "false" > /proc/ubnthal/status/IsLocated
        state_reload
        state_unlock
        ;;
set-custom-sysled)
        # used in bootup led pattern
        exit_if_state_lock_failed $cmd $*
        led_pattern=$1
        set_led $led_pattern 120
        state_unlock
        ;;
unset-custom-sysled)
        # used in bootup led pattern
        exit_if_state_lock_failed $cmd $*
        state_reload
        state_unlock
        ;;
set-volume)
        exit_if_busy $cmd $*
        if [ -c /dev/dsp ]; then
                ubnt-vorbis-player -V $1
        fi
        ;;
set-stream)
        exit_if_busy $cmd $*
        baresip_enabled=`grep baresip.status=enabled /tmp/system.cfg`
        if [ -c /dev/dsp -a -z $baresip_enabled ]; then
                pkill_generic ubnt-vorbis-player -f
                [ -f /var/run/stream.token ] && sleep 1
                token=$1
                echo $token > /var/run/stream.token
                shift
                CODEC_FILE="/var/run/codecbytes_c$1_r$2_q$3"
                [ -s "$CODEC_FILE" ] || (ubnt-vorbis-codecbytes -c $1 -r $2 -q $3 > $CODEC_FILE)
                OPTIONS="-i $4 -p $5"
                [ -z $6 ] || OPTIONS="$OPTIONS -v $6"
                [ -z $7 ] || OPTIONS="$OPTIONS -I $7"
                [ -z $8 ] || OPTIONS="$OPTIONS -P $8"
                [ -z ${10} ] || OPTIONS="$OPTIONS -k $9 -K ${10}"
                log "playing stream $token with options: -c $1 -r $2 -q $3 | $OPTIONS"
                (ubnt-vorbis-player $OPTIONS < $CODEC_FILE; rm -f /var/run/stream.token; mca-cli-op inform) &
        fi
        ;;
set-stream-media)
        exit_if_busy $cmd $*
        baresip_enabled=`grep baresip.status=enabled /tmp/system.cfg`
        if [ -c /dev/dsp -a -z $baresip_enabled ]; then
                pkill_generic ubnt-vorbis-player -f
                [ -f /var/run/stream.token ] && sleep 1
                token=$1
                echo $token > /var/run/stream.token
                shift
                OPTIONS="-u $1 -v $2"
                log "playing stream $token with options: $OPTIONS"
                (ubnt-vorbis-player $OPTIONS; rm -f /var/run/stream.token; mca-cli-op inform) &
        fi
        ;;
unset-stream)
        exit_if_busy $cmd $*
        baresip_enabled=`grep baresip.status=enabled /tmp/system.cfg`
        if [ -c /dev/dsp -a -z $baresip_enabled ]; then
                token=$(cat /var/run/stream.token)
                if [ "$1" = "$token" ]; then
                        log "stopping stream $1"
                        rm -f /var/run/stream.token
                fi
                pkill_generic ubnt-vorbis-player -f
        fi
        ;;
set-uboot-var)
        if [ -e /etc/fw_env.config ]; then
                var_name=$1
                new_value=$2
                stored_value=$(fw_printenv -n "${var_name}" 2>&1)
                if [ "${stored_value}" != "${new_value}" ]; then
                        fw_setenv "${var_name}" "${new_value}"
                fi
        fi
        ;;
11k-scan)
        exit_if_busy $cmd $*
        elevenk_scan
        ;;
11k-boot)
        exit_if_busy $cmd $*
        elevenk_boot $@
        ;;
11k-stop)
        elevenk_stop $@
        ;;
scan)
        exit_if_busy $cmd $*
        scan $@
        sleep 1
        mca-cli-op inform
        ;;
scan_radio)
        exit_if_busy $cmd $*
        scan_radio $@
        ;;
scan_band)
        exit_if_busy $cmd $*
        scan_band $@
        sleep 1
        mca-cli-op inform
        ;;
spectrum-scan)
        exit_if_busy $cmd $*
        spectrum_scan $@
        ;;
spectrum-scan-restore)
        exit_if_busy $cmd $*
        if [ -f /var/run/rftable_wifi0.complete ] ; then
                rm /var/run/rftable_wifi0.complete
        fi
        if [ -f /var/run/rftable_wifi1.complete ] ; then
                rm /var/run/rftable_wifi1.complete
        fi
        state_lock
        /usr/etc/rc.d/rc restart
        state_reload
        state_unlock
        ;;
apply-config)
        # apply-config <file>
        exit_if_busy $cmd $*
        state_lock
        cfg_save "$1"
        if ! do_fast_apply; then
                /usr/etc/rc.d/rc restart
        fi
        state_reload
        state_unlock
        mca-ctrl -t notify-bg-provision-done
        ;;
if-up-event)
        # if-up-event <interface>
        ifname=$1
        if [ -f /var/run/if_up_hook.$ifname ]; then
                /bin/sh /var/run/if_up_hook.$ifname
        fi
        ;;
soft-restart)
        exit_if_busy $cmd $*
        state_lock
        /usr/etc/rc.d/rc restart
        state_reload
        state_unlock
        ;;
save-config)
        state_lock
        cfg_save
        state_unlock
        ;;
reload)
        exit_if_busy $cmd $*
        exit_if_state_lock_failed $cmd $*
        state_reload
        state_unlock
        helper_ssid_war
        ;;
set-ready)
        # called by mcagent
        state_lock
        set_state_ready
        state_unlock
        ;;
*able-vwire-bcast)
        exit_if_fake $cmd $*
        exit_if_busy $cmd $*
        payload=`cat /var/run/vwire.payload`
        [ "$cmd" = "enable-vwire-bcast" ] && payload=`cat /var/run/vwire.payloadbcast`
        for ath in `ls /proc/sys/net | grep vwire`; do
                /bin/vwirectl -i $ath -p $payload
        done
        ;;
set-meshv3-payload)
        killall -SIGUSR1 mesh-monitor
        ;;
unset-meshv3-payload)
        killall -SIGUSR2 mesh-monitor
        ;;
dump-isolation-log)
        state_lock
        dump_syslog_to_persistent
        cfg_save
        state_unlock
        ;;
set-element-payload)
    killall -SIGUSR1 element-adopt-monitor
    ;;
unset-element-payload)
    killall -SIGUSR2 element-adopt-monitor
    ;;
ssh-adopt)
        ip=$1
        url=`grep mgmt.servers.1.url /etc/persistent/cfg/mgmt | cut -d '=' -f 2`
        # use the most ordinary form to set-inform
        DROPBEAR_PASSWORD=ubnt ssh ubnt@$ip -y mca-ctrl -t connect -s $url
        ;;
set-selfrun)
        set_selfrun
        ;;
unset-selfrun)
        unset_selfrun
        ;;
restart)
        exit_if_fake $cmd $*
        exit_if_busy $cmd $*
        _restart $1
        ;;
restore-default)
        exit_if_fake $cmd $*
        exit_if_busy $cmd $*
        reason=${1:-'unknown'}
        ubntbox trace -n 'unifi:network:firmware:event' -t 'restore-default' "{
                \"ppid_comm\": \"$(ppid_comm)\",
                \"ppid_cmdline\": \"$(ppid_cmdline)\",
                \"reason\": \"$reason\"
        }"
        state_lock
        _restore_default
        state_unlock
        _restart 'restore-default'
        ;;
download-firmware)
        check_if_ip_ready
        if [ "$?" = "1" ]; then
                $0 restart "fwupgrade-ip-not-ready"
        else
                $0 _download-firmware "$@" &
        fi
        ;;
_download-firmware)
        # prior to download check for memfree
        memfree=`awk '{if ($1 == "MemFree:") {print $2}}' /proc/meminfo`
        if [ "$memfree" -lt 9800 ]; then
                sed -i '/mesh-monitor\|stamgr\|utermd\|hostapd\|wevent/d' /etc/inittab
                init -q
        fi
        # download-firmware <url> md5 <md5> sha256 <sha256>
        url="$1"
        if [ "$2" = "md5" ]; then
                if [ "$3" != "sha256" ]; then
                        md5="$3"
                        shift 2
                else
                        shift 1
                fi
        fi
        if [ "$2" = "sha256" ]; then
                sha256="$3"
        fi
        fw_path="/tmp/fwupdate.bin"
        rc=1
        fwutil_cmd=$(command -v fwutil 2>/dev/null)
        http_code=0
        if [ -n "${fwutil_cmd}" ]; then
                logger "Upgrade FW Downloading:"
                $fwutil_cmd -d "$url" -p "$fw_path"
                rc=$?
                if [ $rc -eq 0 ]; then
                        http_code=200
                else
                        logger "Download ...Failed, rc:$rc. Try Again"
                fi
        fi
        if [ $rc -ne 0 ]; then
                logger "Upgrade Firmware Downloading:"
                full_cmd="curl -s --retry 3 --retry-delay 3 -L -o $fw_path -w %{http_code} $url"
                http_code=$(curl_with_retry "$full_cmd")
                rc=$?
        fi
        if [ "${http_code}" != "200" ]; then
                echo "error http code: ${http_code}" | logger
                download_err "${rc}" "${http_code}"
                rm -f ${fw_path}
                touch ${FW_DOWNLOAD_FAILED_FILE}
                exit 1
        else
                logger "Download ...OK"
                upgrade_ready "FWDownloadOK"

                if [ -n "$sha256" ]; then
                        fw_sha256=$(sha256sum "$fw_path" | awk '{ print $1; }')
                        if [ "$sha256" != "$fw_sha256" ]; then
                                logger "SHA-256 does not match."
                                upgrade_err "1" "FirmwareCheckFailed" "SHA256Mismatch" "{\"sha256\": \"${fw_sha256}\", \"file_size\": \"$(stat -c %s ${fw_path})\"}"
                                rm -f ${fw_path}
                                touch ${FW_DOWNLOAD_FAILED_FILE}
                                exit 1
                        fi
                elif [ -n "$md5" ]; then
                        fw_md5=$(md5sum "$fw_path" | awk '{ print $1; }')
                        if [ "$md5" != "$fw_md5" ]; then
                                logger "MD5 does not match."
                                upgrade_err "1" "FirmwareCheckFailed" "MD5Mismatch" "{\"md5\": \"${fw_md5}\", \"file_size\": \"$(stat -c %s ${fw_path})\"}"
                                rm -f ${fw_path}
                                touch ${FW_DOWNLOAD_FAILED_FILE}
                                exit 1
                        fi
                fi

                EXEC_OUT=$(fwupdate.real -c 2>&1)
                EXEC_STATUS=$?
                logger "Upgrade Firmware Check:"
                if [ "${EXEC_STATUS}" != "0" ]; then
                        echo "${EXEC_OUT}" | logger
                        upgrade_err_and_restart "${EXEC_STATUS}" "FirmwareCheckFailed"
                else
                        logger "Check ...OK"
                        upgrade_ready "FWCheckOK"
                        cat /proc/uptime > /var/run/download_firmware.finished
                        mca-cli-op inform
                        exit 0
                fi
        fi
        ;;
upgrade)
        exit_if_fake $cmd $*
        # upgrade <url>
        mca-cli-op upgrade "$1"
        ;;
upgrade2)
        exit_if_fake $cmd $*
        # upgrade2
        state_lock
        do_upgrade
        state_unlock
        ;;
getlastfwupdate)
        exit_if_fake $cmd $*
        do_getlastfwupdateresult
        rc=$?
        return $rc
        ;;
getcurrentfwupdate)
        exit_if_fake $cmd $*
        do_getcurrentfwupdatestatus
        rc=$?
        return $rc
        ;;
fwupdate)
        exit_if_fake $cmd $*
        do_fwupdate $*
        rc=$?
        return $rc
        ;;
kick-sta)
        exit_if_fake $cmd $*
        kick_sta $1
        ;;
kick-sta-on)
        exit_if_fake $cmd $*
        kick_sta_on $2 $1 $3
        ;;
block-sta)
        exit_if_fake $cmd $*
        driver_kick_block_sta $1
        add_mac /etc/persistent/cfg/blocked_sta "$1"
        state_lock
        cfg_save
        state_unlock
        ;;
unblock-sta)
        exit_if_fake $cmd $*
        del_mac /etc/persistent/cfg/blocked_sta "$1"
        driver_unblock_sta $1
        state_lock
        cfg_save
        state_unlock
        ;;
apply-blocked-sta)
        driver_apply_blocklist
        ;;
apply-blocked-sta-ifup)
        driver_apply_blocklist_ifup $1
        ;;
authorize-guest)
        exit_if_fake $cmd $*
        add_mac /var/run/guest.authorized $1
        ipset -q list ${IPSET_GUEST_AUTHORIZED_MAC} >/dev/null 2>&1
        if [ $? -eq 0 ]; then
                # ipset exists, add to it.
                ipset add ${IPSET_GUEST_AUTHORIZED_MAC} $1
        else
                # ipset does not exist, call authorized_guests_updated to create and populate
                authorized_guests_updated /var/run/guest.authorized
        fi
        ;;
unauthorize-guest)
        exit_if_fake $cmd $*
        del_mac /var/run/guest.authorized $1
        ipset -q list ${IPSET_GUEST_AUTHORIZED_MAC} >/dev/null 2>&1
        if [ $? -eq 0 ]; then
                # ipset exists, delete from it.
                ipset del ${IPSET_GUEST_AUTHORIZED_MAC} $1
        else
                # ipset does not exist, call authorized_guests_updated to create and populate
                authorized_guests_updated /var/run/guest.authorized
        fi
        kick_sta $1
        ;;
apply-authorized-guests)
        exit_if_fake $cmd $*
        if [ "`cat /var/run/guest.authorized`" != "" ] ; then
                authorized_guests_updated /var/run/guest.authorized
        fi
        ;;
clear-authorized-guests)
        exit_if_fake $cmd $*
        rm -f /var/run/guest.authorized
        authorized_guests_updated /var/run/guest.authorized
        ;;
refresh-walled-garden)
        exit_if_fake $cmd $*
        if_seq=$1
        /bin/walled_action.sh /tmp/allowed.${if_seq}.txt /tmp/restricted.${if_seq}.txt &
        ;;
kill-mcad)
        log "kill-mcad. reason: $*"
        killall mcad
        sleep 1
        killall -9 mcad
        # rely on /etc/inittab to start it
        ;;
mca-custom-alert)
        do_custom_alert "$@"
        ;;
mca-send-inform)
        mca-ctrl -t inform
        ;;
gen-sup-file)
        supdir="`mktemp -d -p /tmp`"
        supfile="$supdir.tgz"
        support -d $supdir
        tar -C $supdir -czf $supfile .
        mca-custom-alert.sh -d -k supportfile -f $supfile
        rm -rf $supdir $supfile
        ;;
lcm-sync)
        src_mac="$1"
        screen="$2"
        timestamp="$3"
        if [ -x "/sbin/lcm-ctrl" ]; then
                /sbin/lcm-ctrl -t screen -o $screen -s $src_mac -m $timestamp
        fi
        ;;
lcm-tracker)
        op="$1"
        if [ -x "/sbin/lcm-ctrl" ]; then
                /sbin/lcm-ctrl -t ar -o "$op"
        fi
        ;;
schedule-action)
        schedule_action
        ;;
run)
        eval $* &
        ;;
dfs-reset)
        dfs_reset
        ;;
netconsole)
        for moddir in /etc/modules*.d /lib/modules/$(uname -r); do
                if [ -f $moddir/netconsole.ko ]; then
                        netconsole_daemon "$@"
                        break;
                fi
        done
        ;;
wireless-bridge-link-switch)
        exit_if_busy $cmd $*
        state_lock
        do_linkswitch
        state_reload
        state_unlock
        ;;
service-restarted)
        CALLER="$1"
        PROCESS="$2"
        EXIT_CODE="$4"
        exit_if_busy $cmd $*
        mca-custom-alert.sh -k event_string -v EVT_AP_RestartProc -k caller -v "$CALLER" -k proc -v "$PROCESS" -k exit_status -v "$EXIT_CODE"
        ;;
install-runtime-package)
        install_runtime_package "$@"
        ;;
clear-vlan-detected)
        clear_vlan_detected "%@"
        ;;
cache-vlan-detected)
        cache_vlan_detected "$@"
        ;;
vlan-detected)
        vlan_detected "$@"
        ;;
vlan-detected-lock)
        state_lock
        vlan_detected "$@"
        state_unlock
        ;;
del-bridge-vlans)
        del_bridge_vlans "$@"
        ;;
reboot-trace)
        ppid=${1}
        reason=${2:-'unknown'}
        ubntbox trace -n 'unifi:network:firmware:event' -t 'reboot' "{
                \"ppid_comm\": \"$(ppid_comm $ppid)\",
                \"ppid_cmdline\": \"$(ppid_cmdline $ppid)\",
                \"reason\": \"$reason\"
        }"
        ;;
sensitive-data-filter)
        sensitive_data_filter
        ;;
*)
        exit 1
        ;;
esac
