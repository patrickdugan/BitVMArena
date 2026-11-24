#!/usr/bin/env bash
# A local SSH fleet for the bitvm3-setup track. One container per party role on a docker
# bridge, each with its own hostname and /etc/machine-id, running sshd with root login by key
# only. The key is a throwaway ed25519 key made in the fleet directory; `down` deletes it.
#
#   tools/ssh_fleet.sh up DIR           build the image, start the fleet, write DIR/ssh_config,
#                                       DIR/known_hosts and DIR/hosts.args (the --host flags)
#   tools/ssh_fleet.sh netem DIR on|off delay and loss on both directions of every container link
#   tools/ssh_fleet.sh rtt DIR          ping every container from the hub
#   tools/ssh_fleet.sh down DIR         remove the containers, the network, the image and the key
#
# DIR must be on a filesystem with Unix permissions (ssh refuses a world-readable key).
# Run the hub with:  native run --track bitvm3-setup $(cat DIR/hosts.args) --ssh-config DIR/ssh_config
set -euo pipefail

ROLES=(garbler desk guardian watch)
NET=bvsetup
PREFIX=10.231.97
IMAGE=bitvm-setup-party:1
NETEM=${NETEM:-delay 40ms 10ms loss 0.5%}   # per direction; the round trip sees both

cmd=${1:?usage: ssh_fleet.sh up|netem|rtt|down DIR [on|off]}
dir=${2:?usage: ssh_fleet.sh up|netem|rtt|down DIR [on|off]}
SUDO=
[ "$(id -u)" -eq 0 ] || SUDO=sudo

ip_of() {
  local i
  for i in "${!ROLES[@]}"; do
    if [ "${ROLES[$i]}" = "$1" ]; then echo "$PREFIX.$((11 + i))"; fi
  done
}

up() {
  mkdir -p "$dir/image"
  chmod 700 "$dir"
  dir=$(cd "$dir" && pwd)
  [ -f "$dir/key" ] || ssh-keygen -q -t ed25519 -N '' -C bitvm-setup-fleet -f "$dir/key"
  # The build context holds only these two files, never the key.
  cat > "$dir/image/Dockerfile" <<'EOF'
FROM python:3.12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd /root/.ssh && chmod 700 /root/.ssh
COPY start.sh /start.sh
CMD ["sh", "/start.sh"]
EOF
  cat > "$dir/image/start.sh" <<'EOF'
set -e
printf '%s\n' "$MACHINE_ID" > /etc/machine-id
ssh-keygen -A >/dev/null
install -m 600 /fleet/key.pub /root/.ssh/authorized_keys
exec /usr/sbin/sshd -D -e -o PermitRootLogin=prohibit-password -o PasswordAuthentication=no \
  -o KbdInteractiveAuthentication=no
EOF
  docker build -q -t "$IMAGE" "$dir/image" >/dev/null
  docker network inspect "$NET" >/dev/null 2>&1 || docker network create --subnet "$PREFIX.0/24" "$NET" >/dev/null
  for role in "${ROLES[@]}"; do
    docker rm -f "bvsetup-$role" >/dev/null 2>&1 || true
    docker run -d --name "bvsetup-$role" --hostname "bvsetup-$role" --network "$NET" --ip "$(ip_of "$role")" \
      -e MACHINE_ID="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')" \
      -v "$dir/key.pub:/fleet/key.pub:ro" "$IMAGE" >/dev/null
  done
  : > "$dir/known_hosts"
  args=
  for role in "${ROLES[@]}"; do
    ip=$(ip_of "$role")
    for _ in $(seq 1 100); do
      if ssh-keyscan -T 2 -t ed25519 "$ip" 2>/dev/null | grep "^$ip " >> "$dir/known_hosts"; then break; fi
      sleep 0.2
    done
    grep -q "^$ip " "$dir/known_hosts" || { echo "sshd on $role ($ip) did not come up" >&2; exit 1; }
    args+="--host $role=ssh:root@$ip "
  done
  cat > "$dir/ssh_config" <<EOF
Host $PREFIX.*
  User root
  IdentityFile $dir/key
  IdentitiesOnly yes
  IdentityAgent none
  UserKnownHostsFile $dir/known_hosts
  StrictHostKeyChecking yes
  BatchMode yes
  LogLevel ERROR
EOF
  printf '%s\n' "$args" > "$dir/hosts.args"
  for role in "${ROLES[@]}"; do
    ssh -F "$dir/ssh_config" "root@$(ip_of "$role")" \
      'python3 -c "import platform; print(platform.node(), platform.python_version())"'
  done
  echo "fleet up: $args"
}

netem() {
  local mode=${1:?netem DIR on|off} br pid
  br="br-$(docker network inspect -f '{{.Id}}' "$NET" | cut -c1-12)"
  for role in "${ROLES[@]}"; do
    pid=$(docker inspect -f '{{.State.Pid}}' "bvsetup-$role")
    if [ "$mode" = on ]; then
      # container -> hub
      # shellcheck disable=SC2086
      $SUDO nsenter -t "$pid" -n tc qdisc replace dev eth0 root netem $NETEM
    else
      $SUDO nsenter -t "$pid" -n tc qdisc del dev eth0 root 2>/dev/null || true
    fi
  done
  if [ "$mode" = on ]; then
    # hub -> containers
    # shellcheck disable=SC2086
    $SUDO tc qdisc replace dev "$br" root netem $NETEM
    echo "netem on ($NETEM per direction) on $br and every container's eth0"
  else
    $SUDO tc qdisc del dev "$br" root 2>/dev/null || true
    echo "netem off"
  fi
}

rtt() {
  for role in "${ROLES[@]}"; do
    printf '%s ' "$role"
    ping -q -c "${PINGS:-50}" -i 0.2 "$(ip_of "$role")" | tail -2 | tr '\n' ' '
    echo
  done
}

down() {
  for role in "${ROLES[@]}"; do docker rm -f "bvsetup-$role" >/dev/null 2>&1 || true; done
  docker network rm "$NET" >/dev/null 2>&1 || true
  docker rmi "$IMAGE" >/dev/null 2>&1 || true
  rm -f "$dir/key" "$dir/key.pub" "$dir/known_hosts" "$dir/ssh_config" "$dir/hosts.args"
  rm -rf "$dir/image"
  rmdir "$dir" 2>/dev/null || true
  echo "fleet down"
}

case "$cmd" in
  up) up ;;
  netem) netem "${3:-}" ;;
  rtt) rtt ;;
  down) down ;;
  *) echo "unknown command $cmd" >&2; exit 2 ;;
esac
