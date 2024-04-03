#!/usr/bin/env sh

set -eu

# start up freshclam to pull the definitions. In our deployment, these will be pulled
# from a cluster-local mirror
freshclam --daemon
# we need to sleep a while here since we start freshclam as a daemon in the background.
# Give it time to download the definitions.
echo "Sleeping for 45 seconds to give freshclam time to download the virus definitions ..."
sleep 45
echo "Done"

mkdir /run/clamav
chown -R clamav /run/clamav
clamd

# watch logfile
mkdir -p /var/log/clamav
touch /var/log/clamav/clamd.log
tail -f /var/log/clamav/clamd.log &

echo 'launching clamav-worker'
exec python3 -m malware