#!/usr/bin/env bash

set -Eeuo pipefail

readonly RSYSLOG_CONFIG="/etc/rsyslog.d/10-log-collector-relp.conf"
readonly LOGROTATE_CONFIG="/etc/logrotate.d/log-collector-clients"

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    printf 'Error: run this installer as root (for example: curl ... | sudo bash).\n' >&2
    exit 1
fi

if [[ ! -r /dev/tty || ! -w /dev/tty ]]; then
    printf 'Error: this interactive installer requires a terminal (/dev/tty).\n' >&2
    exit 1
fi
exec 3<>/dev/tty

say() {
    printf '%s\n' "$*" >&3
}

ask() {
    local prompt=$1 default=${2-} answer
    if [[ -n $default ]]; then
        printf '%s [%s]: ' "$prompt" "$default" >&3
    else
        printf '%s: ' "$prompt" >&3
    fi
    IFS= read -r answer <&3
    printf '%s' "${answer:-$default}"
}

confirm() {
    local prompt=$1 default=${2:-y} answer suffix
    if [[ $default == y ]]; then suffix='Y/n'; else suffix='y/N'; fi
    while true; do
        printf '%s [%s]: ' "$prompt" "$suffix" >&3
        IFS= read -r answer <&3
        answer=${answer:-$default}
        case ${answer,,} in
            y|yes) return 0 ;;
            n|no) return 1 ;;
            *) say 'Please answer yes or no.' ;;
        esac
    done
}

ask_number() {
    local prompt=$1 default=$2 min=$3 max=$4 value
    while true; do
        value=$(ask "$prompt" "$default")
        if [[ $value =~ ^[0-9]+$ ]] && (( value >= min && value <= max )); then
            printf '%s' "$value"
            return
        fi
        say "Enter a number from $min to $max."
    done
}

if ! command -v apt-get >/dev/null 2>&1; then
    say 'Error: this installer currently supports Ubuntu and Debian systems using apt.'
    exit 1
fi

say ''
say 'Log Collector RELP Receiver Setup'
say '================================='
say 'This installs rsyslog/RELP and stores events by client hostname and source.'
say ''

mapfile -t DETECTED_IPS < <(
    ip -o -4 addr show scope global 2>/dev/null |
        awk '{split($4, address, "/"); print address[1]}' |
        sort -u
)

say 'Receiver bind address:'
say '  1) All interfaces (0.0.0.0) [recommended]'
for index in "${!DETECTED_IPS[@]}"; do
    say "  $((index + 2))) ${DETECTED_IPS[$index]}"
done

while true; do
    bind_choice=$(ask 'Select an address' '1')
    if [[ $bind_choice == '1' ]]; then
        bind_address='0.0.0.0'
        break
    fi
    if [[ $bind_choice =~ ^[0-9]+$ ]]; then
        ip_index=$((bind_choice - 2))
        if (( ip_index >= 0 && ip_index < ${#DETECTED_IPS[@]} )); then
            bind_address=${DETECTED_IPS[$ip_index]}
            break
        fi
    fi
    say 'Select one of the listed numbers.'
done

relp_port=$(ask_number 'RELP TCP port' '2514' 1 65535)
log_root=$(ask 'Log storage directory' '/var/log/clients')
while [[ $log_root != /* || $log_root == *'..'* || ! $log_root =~ ^/[A-Za-z0-9._/-]+$ ]]; do
    say 'Enter a safe absolute path without spaces or "..".'
    log_root=$(ask 'Log storage directory' '/var/log/clients')
done
log_root=${log_root%/}

retention=$(ask_number 'Number of daily rotations to retain' '14' 1 3650)
queue_entries=$(ask_number 'Maximum queued events' '50000' 1000 10000000)
queue_disk_mb=$(ask_number 'Maximum receiver queue disk usage (MB)' '256' 16 1048576)
max_message_kb=$(ask_number 'Maximum RELP message size (KiB)' '4096' 128 65536)

manage_firewall=false
if confirm "Add a UFW allow rule for TCP port $relp_port" y; then
    manage_firewall=true
fi

say ''
say 'Planned configuration:'
say "  Bind address:       $bind_address"
say "  RELP port:          $relp_port/tcp"
say "  Log directory:      $log_root/<hostname>/<source>.log"
say "  Retention:          $retention daily rotations"
say "  Queue:              $queue_entries events, ${queue_disk_mb} MB disk"
say "  Maximum message:    ${max_message_kb} KiB"
say "  Add UFW rule:       $manage_firewall"
say ''

if ! confirm 'Apply this configuration' y; then
    say 'No changes made.'
    exit 0
fi

say ''
say 'Installing required packages...'
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y rsyslog rsyslog-relp logrotate iproute2
if [[ $manage_firewall == true ]]; then
    apt-get install -y ufw
fi

install -d -o syslog -g adm -m 0750 "$log_root"
install -d -o syslog -g syslog -m 0750 /var/spool/rsyslog

backup_dir=$(mktemp -d /tmp/log-collector-receiver.XXXXXX)
had_rsyslog_config=false
had_logrotate_config=false
if [[ -e $RSYSLOG_CONFIG ]]; then
    cp -a "$RSYSLOG_CONFIG" "$backup_dir/rsyslog.conf"
    had_rsyslog_config=true
fi
if [[ -e $LOGROTATE_CONFIG ]]; then
    cp -a "$LOGROTATE_CONFIG" "$backup_dir/logrotate.conf"
    had_logrotate_config=true
fi

rollback() {
    say 'Restoring the previous receiver configuration...'
    if [[ $had_rsyslog_config == true ]]; then
        cp -a "$backup_dir/rsyslog.conf" "$RSYSLOG_CONFIG"
    else
        rm -f "$RSYSLOG_CONFIG"
    fi
    if [[ $had_logrotate_config == true ]]; then
        cp -a "$backup_dir/logrotate.conf" "$LOGROTATE_CONFIG"
    else
        rm -f "$LOGROTATE_CONFIG"
    fi
    systemctl restart rsyslog 2>/dev/null || true
}

trap 'say "Setup failed on line $LINENO."; rollback' ERR

bind_line=""
if [[ $bind_address != '0.0.0.0' ]]; then
    bind_line="    address=\"$bind_address\""
fi

tmp_rsyslog=$(mktemp)
tmp_logrotate=$(mktemp)

{
    printf '%s\n' '# Managed by receiver.sh - Log Collector RELP receiver'
    printf 'global(maxMessageSize="%sk")\n\n' "$max_message_kb"
    printf '%s\n\n' 'module(load="imrelp")'
    printf '%s\n' 'template(name="PerEndpointLog" type="string"'
    printf '    string="%s/%%HOSTNAME:::secpath-replace%%/%%PROGRAMNAME:::secpath-replace%%.log")\n\n' "$log_root"
    printf '%s\n\n' 'template(name="RawForward" type="string" string="%rawmsg%\\n")'
    printf '%s\n' 'ruleset(name="logcollector") {'
    printf '%s\n' '    action(type="omfile"'
    printf '%s\n' '        dynaFile="PerEndpointLog"'
    printf '%s\n' '        template="RawForward"'
    printf '%s\n' '        dynaFileCacheSize="64"'
    printf '%s\n' '        dirCreateMode="0750"'
    printf '%s\n' '        fileCreateMode="0640"'
    printf '%s\n' '        ioBufferSize="64k"'
    printf '%s\n' '        flushOnTXEnd="off"'
    printf '%s\n' '        asyncWriting="on"'
    printf '%s\n' '        queue.type="LinkedList"'
    printf '        queue.size="%s"\n' "$queue_entries"
    printf '%s\n' '        queue.dequeueBatchSize="256"'
    printf '%s\n' '        queue.workerThreads="1"'
    printf '%s\n' '        queue.filename="logcollector_action"'
    printf '        queue.maxDiskSpace="%sm"\n' "$queue_disk_mb"
    printf '%s\n' '        queue.saveOnShutdown="on")'
    printf '%s\n\n' '    stop'
    printf '%s\n' '}'
    printf '%s\n' 'input(type="imrelp"'
    if [[ -n $bind_line ]]; then printf '%s\n' "$bind_line"; fi
    printf '    port="%s"\n' "$relp_port"
    printf '    maxDataSize="%sk"\n' "$max_message_kb"
    printf '%s\n' '    ruleset="logcollector")'
} > "$tmp_rsyslog"

{
    printf '%s\n' "$log_root/*/*.log {"
    printf '%s\n' '    daily'
    printf '    rotate %s\n' "$retention"
    printf '%s\n' '    compress' '    delaycompress' '    missingok' '    notifempty'
    printf '%s\n' '    create 0640 syslog adm' '    sharedscripts' '    postrotate'
    printf '%s\n' '        /usr/lib/rsyslog/rsyslog-rotate 2>/dev/null || systemctl kill -s HUP rsyslog.service'
    printf '%s\n' '    endscript' '}'
} > "$tmp_logrotate"

install -o root -g root -m 0644 "$tmp_rsyslog" "$RSYSLOG_CONFIG"
install -o root -g root -m 0644 "$tmp_logrotate" "$LOGROTATE_CONFIG"
rm -f "$tmp_rsyslog" "$tmp_logrotate"

say 'Validating rsyslog configuration...'
rsyslogd -N1

systemctl enable rsyslog
systemctl restart rsyslog
systemctl is-active --quiet rsyslog

if [[ $manage_firewall == true ]]; then
    ufw allow "$relp_port/tcp" comment 'Log collector RELP'
    if ! ufw status | grep -q '^Status: active'; then
        say 'UFW rule added, but UFW remains inactive. The script did not enable it.'
    fi
fi

if ! ss -lnt | awk '{print $4}' | grep -Eq "(^|:)$relp_port$"; then
    say "Error: rsyslog restarted but TCP port $relp_port is not listening."
    false
fi

logrotate --debug "$LOGROTATE_CONFIG" >/dev/null

trap - ERR
rm -rf "$backup_dir"

receiver_ips=$(hostname -I 2>/dev/null | xargs || true)
say ''
say 'Receiver setup complete.'
say "  Listening on: $bind_address:$relp_port/tcp"
say "  Receiver IPs: ${receiver_ips:-unknown}"
say "  Logs:         $log_root/<hostname>/<source>.log"
say ''
say 'Test from a Linux client:'
say "  nc -zv <receiver-ip> $relp_port"
say ''
say 'Test from Windows PowerShell:'
say "  Test-NetConnection <receiver-ip> -Port $relp_port"
say ''
say 'Note: the log directory stays empty until a configured collector sends an event.'
