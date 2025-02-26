package main

import (
	"encoding/json"
	"fmt"
	"net"
	"runtime"

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
	BPFProgPath string `json:"bpf_prog_path"`
}

const BPF_ELF_NAME = "./bpf/ebpf_prog.o"
const TC_PROG_NAME = "tc_ingress"

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

	// On the HOST side (outside the container namespace):
	hostVeth, err := netlink.LinkByName(hostIface.Name)
	if err != nil {
		return fmt.Errorf("failed to find host veth: %v", err)
	}

	// Add the gateway IP to the host-side interface
	hostAddr, err := netlink.ParseAddr("10.0.0.1/24")
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

	gateway := "10.0.0.1"
	// IPAM management
	var result *current.Result
	// Set up IP address (example - should come from config)
	if config.IPAM.Type == "host-local" {
		// Get subnet from configuration
		addr, err := netlink.ParseAddr("10.0.0.2/24")
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
				Gw:  net.ParseIP(gateway),
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
				Gateway: net.ParseIP(gateway),
			}},
		}

	} else {
		return fmt.Errorf("unsupported IPAM type: %s", config.IPAM.Type)
	}
	// if err := loadBPFProgram(hostIface.Name); err != nil {
	// 	return fmt.Errorf("failed to load BPF program: %v", err)
	// }
	return types.PrintResult(result, config.CNIVersion)
}

// func loadBPFProgram(ifaceName string) error {
// 	// Load eBPF program
// 	bpfModule, err := bpf.NewModuleFromFile(BPF_ELF_NAME)
// 	if err != nil {
// 		return fmt.Errorf("failed to load BPF module: %v", err)
// 	}
// 	defer bpfModule.Close() // Keep this, but pin first

// 	// TC initialization
// 	hook := bpfModule.TcHookInit()
// 	err = hook.SetInterfaceByName(ifaceName)
// 	if err != nil {
// 		return fmt.Errorf("failed to set tc hook hook on interfgace %s: %v", ifaceName, err)
// 	}

// 	hook.SetAttachPoint(bpf.BPFTcIngress)
// 	err = hook.Create()
// 	if err != nil {
// 		if errno, ok := err.(syscall.Errno); ok && errno != syscall.EEXIST {
// 			return fmt.Errorf("failed to create tc hook on interface %s: %v", ifaceName, err)
// 		}
// 	}

// 	tcProg, err := bpfModule.GetProgram(TC_PROG_NAME)
// 	if err != nil {
// 		return fmt.Errorf("failed to get program %s: %v", TC_PROG_NAME, err)
// 	}
// 	if tcProg == nil {
// 		return fmt.Errorf("could not find program %s: ", TC_PROG_NAME)
// 	}
// 	var tcOpts bpf.TcOpts
// 	pinPath := "/sys/fs/bpf/tc_ingress"
// 	if err := tcProg.Pin(pinPath); err != nil {
// 		return fmt.Errorf("failed to pin program: %v", err)
// 	}

//		// Attach using pinned program
//		tcOpts.ProgFd = int(tcProg.FileDescriptor())
//		if err := hook.Attach(&tcOpts); err != nil {
//			return fmt.Errorf("failed to attach: %v (fd: %d)", err, tcOpts.ProgFd)
//		}
//		return nil
//	}

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
	// Implement if needed
	return nil
}
