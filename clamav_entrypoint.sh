#!/usr/bin/env sh

set -eu

mkdir /run/clamav
chown -R clamav /run/clamav

# start up freshclam to pull the definitions. In our deployment, these will be pulled
# from a cluster-local mirror
echo "Starting Freshclam daemon ..."
freshclam --daemon
# we need to sleep a while here since we start freshclam as a daemon in the background.
# Give it time to download the definitions.
echo "Sleeping for 45 seconds to give freshclam time to download the virus definitions ..."
sleep 45
echo "Starting ClamD ..."
clamd

# watch logfile
mkdir -p /var/log/clamav
touch /var/log/clamav/clamd.log
tail -f /var/log/clamav/clamd.log &

echo 'launching clamav-worker'
exec python3 -m malware