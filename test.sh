#!/bin/bash


#create a none networked docker container and create it's network namespace.
# This will be handled by the container runtime which will create and provide the container network namespace.
cid=$(docker container run -d --name test --network none alpine tail -f /dev/null)
trap "docker container rm -f test" EXIT
# Get the container's PID
pid=$(docker inspect -f '{{.State.Pid}}' test)
sudo mkdir -p /var/run/netns
sudo ln -sf /proc/"$pid"/ns/net /var/run/netns/test

: "${ENV:=prod}"
# Execute CNI plugin
CNI_COMMAND=ADD CNI_CONTAINERID=$cid CNI_NETNS=/var/run/netns/test CNI_IFNAME=eth0 CNI_ARGS="" CNI_PATH=./bin ./bin/ecni < conf/ebpf-cni.conf

#make assertion
if ! docker container exec -i test ip addr show | grep -q eth0; then
		docker container exec -i test ip addr show
    echo "No eth interface found, exiting."
    exit 1
fi

if [[ $ENV == "dev" ]]; then
  echo "Breakpoint reached. Press ^C to continue..."
  trap "break" SIGINT
  while true; do
      sleep 1
  done
  trap - SIGINT  # reset the SIGINT trap
fi



# Execute CNI plugin
CNI_COMMAND=DEL CNI_CONTAINERID=test CNI_NETNS=/var/run/netns/test CNI_IFNAME=eth0 CNI_ARGS="" CNI_PATH=./bin ./bin/ecni < conf/ebpf-cni.conf

if docker container exec -i test ip addr show | grep -q eth0; then
		docker container exec -i test ip addr show
    echo "eth interface found, exiting."
    exit 1
fi

echo "Tests Passed!"

