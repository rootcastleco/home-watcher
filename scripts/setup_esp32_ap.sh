#!/usr/bin/env bash
# ==============================================================================
# MIL-STD-498 INTERFACE SEGREGATION & AP CONFIGURATOR
# ==============================================================================
# SYSTEM:             Rootcastle Home Watcher Stack
# SUBSYSTEM:          Network AP Segregation Subsystem
# FILE NAME:          setup_esp32_ap.sh
# VERSION:            1.2.0
# DATE:               2026-06-15
# SECURITY CLASSIF:   UNCLASSIFIED
# DESCRIPTION:        Installs hostapd, dnsmasq, and configures an isolated 
#                     access point on interface wlan0 to host wireless cameras
#                     with packet forwarding disabled to prevent WAN leakage.
# ==============================================================================
set -euo pipefail

SSID="${ESP_AP_SSID:-frigate-esp-local}"
PASSWORD="${ESP_AP_PASSWORD:-}"
IFACE="${ESP_AP_IFACE:-wlan0}"
AP_CIDR="${ESP_AP_CIDR:-192.168.50.1/24}"
DHCP_START="${ESP_AP_DHCP_START:-192.168.50.20}"
DHCP_END="${ESP_AP_DHCP_END:-192.168.50.80}"

log() { printf '[INFO] %s\n' "$*"; }
die() { printf '[ERROR] %s\n' "$*" >&2; exit 1; }

if [[ "${EUID}" -ne 0 ]]; then
  die "Run with sudo"
fi

if [[ -z "${PASSWORD}" || "${#PASSWORD}" -lt 12 ]]; then
  die "Set ESP_AP_PASSWORD to a 12+ character WPA2 password"
fi

apt-get update
apt-get install -y hostapd dnsmasq iptables iproute2

systemctl unmask hostapd
systemctl enable hostapd dnsmasq

if systemctl list-unit-files NetworkManager.service >/dev/null 2>&1; then
  nmcli device disconnect "${IFACE}" >/dev/null 2>&1 || true
  mkdir -p /etc/NetworkManager/conf.d
  cat >/etc/NetworkManager/conf.d/frigate-esp-unmanaged.conf <<EOF
[keyfile]
unmanaged-devices=interface-name:${IFACE}
EOF
  systemctl reload NetworkManager || true
fi

iw dev "${IFACE}" disconnect >/dev/null 2>&1 || true
systemctl stop "wpa_supplicant@${IFACE}.service" >/dev/null 2>&1 || true

cat >/etc/systemd/system/frigate-esp-ap-ip.service <<EOF
[Unit]
Description=Assign static IP to Frigate ESP32 AP interface
After=network-pre.target
Before=hostapd.service dnsmasq.service

[Service]
Type=oneshot
ExecStart=/bin/sh -c '/usr/sbin/ip link set ${IFACE} up && /usr/sbin/ip addr flush dev ${IFACE} && /usr/sbin/ip addr add ${AP_CIDR} dev ${IFACE}'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

cat >/etc/hostapd/hostapd.conf <<EOF
country_code=TR
interface=${IFACE}
driver=nl80211
ssid=${SSID}
hw_mode=g
channel=6
wmm_enabled=1
auth_algs=1
wpa=2
wpa_passphrase=${PASSWORD}
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
EOF

cat >/etc/default/hostapd <<'EOF'
DAEMON_CONF="/etc/hostapd/hostapd.conf"
EOF

cat >/etc/dnsmasq.d/frigate-esp-local.conf <<EOF
interface=${IFACE}
bind-dynamic
dhcp-range=${DHCP_START},${DHCP_END},255.255.255.0,24h
# Deliberately do not advertise an internet gateway to ESP32 devices.
dhcp-option=3,0.0.0.0
dhcp-option=6,${AP_CIDR%/*}
EOF

cat >/etc/systemd/system/frigate-esp-block-wan.service <<EOF
[Unit]
Description=Block ESP32 AP clients from forwarding to WAN
After=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/sh -c '/usr/sbin/iptables -C FORWARD -i ${IFACE} -j REJECT 2>/dev/null || /usr/sbin/iptables -I FORWARD -i ${IFACE} -j REJECT'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now frigate-esp-ap-ip.service
systemctl restart hostapd dnsmasq
systemctl enable --now frigate-esp-block-wan.service

log "ESP32 isolated AP is configured: ${SSID} on ${AP_CIDR}"
log "Connect the ESP32-CAM to this SSID, then set its stream address in Frigate."
