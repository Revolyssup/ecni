package main

import (
	"encoding/json"
	"fmt"
	"net"
	"runtime"

	"github.com/cilium/ebpf"
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

func loadEBPFProgram(path string) (*ebpf.Collection, error) {
	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		return nil, fmt.Errorf("failed to load spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("failed to create collection: %v", err)
	}

	return coll, nil
}

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

	// Load eBPF program
	// coll, err := loadEBPFProgram(config.BPFProgPath)
	// if err != nil {
	// 	return fmt.Errorf("failed to load eBPF program: %v", err)
	// }
	// defer coll.Close()

	// // Attach eBPF program to host interface
	// hostLink, err := netlink.LinkByName(hostIface.Name)
	// if err != nil {
	// 	return fmt.Errorf("failed to find host interface: %v", err)
	// }

	// Attach TC eBPF program
	// l, err := link.AttachTCX(link.TCXOptions{
	// 	Interface: hostLink.Attrs().Index,
	// 	Program:   coll.Programs["tc_ingress"],
	// })
	// if err != nil {
	// 	return fmt.Errorf("failed to attach TC program: %v", err)
	// }
	// defer l.Close()

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

			return nil
		})

		result = &current.Result{
			CNIVersion: config.CNIVersion,
			Interfaces: []*current.Interface{hostIface, contIface},
			IPs: []*current.IPConfig{{
				Address: net.IPNet{IP: addr.IP, Mask: addr.Mask},
				Gateway: net.ParseIP("10.0.0.1"),
			}},
		}

	} else {
		return fmt.Errorf("unsupported IPAM type: %s", config.IPAM.Type)
	}

	return types.PrintResult(result, config.CNIVersion)
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
	// Implement if needed
	return nil
}
