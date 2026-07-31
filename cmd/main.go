package main

import "C"

// #cgo LDFLAGS: -lz -lelf
import (
	"encoding/json"
	"fmt"
	"net"
	"runtime"
	"syscall"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
)

type PluginConf struct {
	types.NetConf
	BPFProgPath   string `json:"bpf_prog_path"`
	HostInterface string `json:"host_interface"`
	GatewayIP     string `json:"gateway_ip"`
	ContainerIP   string `json:"container_ip"`
}

const BPF_ELF_NAME = "./ecni.bpf.o"
const TC_PROG_NAME_INGRESS = "tc_ingress"
const TC_PROG_NAME_EGRESS = "tc_egress"

func setupVeth(netns ns.NetNS, ifName string, mtu int) (*current.Interface, *current.Interface, error) {
	hostIface := &current.Interface{}
	contIface := &current.Interface{}

	err := netns.Do(func(hostNS ns.NetNS) error {
		// Create veth pair inside container namespace
		hostVeth, contVeth, err := ip.SetupVeth(ifName, mtu, "", hostNS)
		if err != nil {
			return err
		}

		contIface.Name = contVeth.Name
		contIface.Mac = contVeth.HardwareAddr.String()
		contIface.Sandbox = netns.Path()
		hostIface.Name = hostVeth.Name
		return nil
	})

	return hostIface, contIface, err
}

func cmdAdd(args *skel.CmdArgs) error {
	config := PluginConf{}
	if err := json.Unmarshal(args.StdinData, &config); err != nil {
		return fmt.Errorf("failed to parse config: %v", err)
	}

	netns, err := ns.GetNS(args.Netns)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", args.Netns, err)
	}
	defer netns.Close()

	hostIface, contIface, err := setupVeth(netns, args.IfName, 1500)
	if err != nil {
		return fmt.Errorf("failed to setup veth: %v", err)
	}

	gatewayIP := config.GatewayIP
	if gatewayIP == "" {
		gatewayIP = "10.0.0.1/24"
	}
	containerIP := config.ContainerIP
	if containerIP == "" {
		containerIP = "10.0.0.2/24"
	}

	// On the HOST side (outside the container namespace):
	hostVeth, err := netlink.LinkByName(hostIface.Name)
	if err != nil {
		return fmt.Errorf("failed to find host veth: %v", err)
	}

	// Add the gateway IP to the host-side interface
	hostAddr, err := netlink.ParseAddr(gatewayIP)
	if err != nil {
		return fmt.Errorf("failed to parse host IP: %v", err)
	}

	if err := netlink.AddrAdd(hostVeth, hostAddr); err != nil {
		return fmt.Errorf("failed to assign IP to host veth: %v", err)
	}

	// Bring the host-side interface up
	if err := netlink.LinkSetUp(hostVeth); err != nil {
		return fmt.Errorf("failed to set host veth up: %v", err)
	}

	// Parse the gateway for use as route target (IP only, no prefix)
	gatewayParsed, _, err := net.ParseCIDR(gatewayIP)
	if err != nil {
		return fmt.Errorf("failed to parse gateway IP: %v", err)
	}
	// IPAM management
	var result *current.Result
	// Set up IP address (from config or default)
	if config.IPAM.Type == "host-local" {
		// Get container IP from configuration
		addr, err := netlink.ParseAddr(containerIP)
		if err != nil {
			return err
		}

		//Equivalent to netns exec. Assign IP and bring up interfaces
		err = netns.Do(func(_ ns.NetNS) error {
			link, err := netlink.LinkByName(contIface.Name)
			if err != nil {
				return err
			}

			if err := netlink.AddrAdd(link, addr); err != nil {
				return fmt.Errorf("failed to add IP address: %v", err)
			}

			if err := netlink.LinkSetUp(link); err != nil {
				return fmt.Errorf("failed to set link up: %v", err)
			}

			// Add default route via 10.1.1.1
			_, defaultDst, err := net.ParseCIDR("0.0.0.0/0")
			if err != nil {
				return fmt.Errorf("failed to parse default route destination: %v", err)
			}

			route := &netlink.Route{
				Dst: defaultDst,
				Gw:  gatewayParsed,
			}

			if err := netlink.RouteAdd(route); err != nil {
				return fmt.Errorf("failed to add default route: %v", err)
			}

			return nil
		})

		result = &current.Result{
			CNIVersion: config.CNIVersion,
			Interfaces: []*current.Interface{hostIface, contIface},
			IPs: []*current.IPConfig{{
				Address: net.IPNet{IP: addr.IP, Mask: addr.Mask},
				Gateway: gatewayParsed,
			}},
		}

	} else {
		return fmt.Errorf("unsupported IPAM type: %s", config.IPAM.Type)
	}
	// Load eBPF program
	bpfModule, err := bpf.NewModuleFromFile(BPF_ELF_NAME)
	if err != nil {
		return fmt.Errorf("failed to load BPF module: %v", err)
	}
	defer bpfModule.Close() // Keep this, but pin first
	hostInterface := config.HostInterface
	if hostInterface == "" {
		hostInterface = "eth0"
	}
	if err := loadBPFProgram(bpfModule, hostInterface, contIface.Name, netns); err != nil {
		return fmt.Errorf("failed to load BPF program: %v", err)
	}
	return types.PrintResult(result, config.CNIVersion)
}

type BPFFunc struct {
	FuncName  string
	Type      bpf.TcAttachPoint
	Interface string
}

func loadBPFProgram(bpfModule *bpf.Module, hostIface, containerIface string, netns ns.NetNS) error {
	// Attach ingress to host interface (host namespace)
	if err := bpfModule.BPFLoadObject(); err != nil {
		return err
	}
	for _, f := range []BPFFunc{
		{"tc_ingress", bpf.BPFTcIngress, hostIface},
		{"tc_egress", bpf.BPFTcEgress, containerIface},
	} {
		hook := bpfModule.TcHookInit()
		if f.Interface == containerIface {
			netns.Do(func(_ ns.NetNS) error {
				if err := hook.SetInterfaceByName(f.Interface); err != nil {
					return err
				}
				hook.SetAttachPoint(f.Type)
				if err := hook.Create(); err != nil {
					if errno, ok := err.(syscall.Errno); ok && errno != syscall.EEXIST {
						return err
					}
				}
				prog, e := bpfModule.GetProgram(f.FuncName)
				if e != nil {
					return e
				}
				tcOpts := bpf.TcOpts{ProgFd: prog.FileDescriptor()}
				if err := hook.Attach(&tcOpts); err != nil {
					return err
				}
				return nil
			})
		} else {
			if err := hook.SetInterfaceByName(f.Interface); err != nil {
				return err
			}
			hook.SetAttachPoint(f.Type)
			if err := hook.Create(); err != nil {
				if errno, ok := err.(syscall.Errno); ok && errno != syscall.EEXIST {
					return err
				}
			}
			prog, e := bpfModule.GetProgram(f.FuncName)
			if e != nil {
				return e
			}
			tcOpts := bpf.TcOpts{ProgFd: prog.FileDescriptor()}
			if err := hook.Attach(&tcOpts); err != nil {
				return err
			}
		}

	}
	return nil
}

func cmdDel(args *skel.CmdArgs) error {
	// Cleanup network namespace
	if args.Netns == "" {
		return nil
	}

	netns, err := ns.GetNS(args.Netns)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", args.Netns, err)
	}
	defer netns.Close()

	return netns.Do(func(_ ns.NetNS) error {
		_, err := ip.DelLinkByNameAddr(args.IfName)
		return err
	})
}

func main() {
	// Lock the OS Thread to prevent namespace switches
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	skel.PluginMainFuncs(skel.CNIFuncs{
		Check: cmdCheck,
		Add:   cmdAdd,
		Del:   cmdDel,
	}, version.All, "ebpf-cni")
}

func cmdCheck(args *skel.CmdArgs) error {
	config := PluginConf{}
	if err := json.Unmarshal(args.StdinData, &config); err != nil {
		return fmt.Errorf("failed to parse config: %v", err)
	}

	if args.Netns == "" {
		return nil
	}

	containerIP := config.ContainerIP
	if containerIP == "" {
		containerIP = "10.0.0.2/24"
	}

	netns, err := ns.GetNS(args.Netns)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", args.Netns, err)
	}
	defer netns.Close()

	return netns.Do(func(_ ns.NetNS) error {
		link, err := netlink.LinkByName(args.IfName)
		if err != nil {
			return fmt.Errorf("interface %s not found in container: %v", args.IfName, err)
		}

		addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
		if err != nil {
			return fmt.Errorf("failed to list addresses on %s: %v", args.IfName, err)
		}

		expectedAddr, err := netlink.ParseAddr(containerIP)
		if err != nil {
			return fmt.Errorf("failed to parse container IP %s: %v", containerIP, err)
		}

		found := false
		for _, addr := range addrs {
			if addr.IP.Equal(expectedAddr.IP) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("expected IP %s not assigned to interface %s", containerIP, args.IfName)
		}

		routes, err := netlink.RouteList(link, netlink.FAMILY_V4)
		if err != nil {
			return fmt.Errorf("failed to list routes: %v", err)
		}

		for _, r := range routes {
			if r.Dst == nil || r.Dst.String() == "0.0.0.0/0" {
				return nil
			}
		}
		return fmt.Errorf("no default route found in container namespace")
	})
}
