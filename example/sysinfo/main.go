package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/shirou/gopsutil/host"
	"github.com/shirou/gopsutil/mem"
	psnet "github.com/shirou/gopsutil/net"
)

//GetMacineId
func GetMacineId() string {
	var mcid string
	_, err := os.Stat(`/etc/machine-id`)
	if err == nil {
		data, _ := ioutil.ReadFile("/etc/machine-id")
		mcid = string(data)
	}
	return mcid
}

//GetMeneinfo
func GetMeneinfo() string {

	v, _ := mem.VirtualMemory()
	// meminfo := []Meninfo{}
	type meninfo struct {
		Total       uint64  `json:"total"`
		Free        uint64  `json:"free"`
		UsedPercent float64 `json:"usedpercent"`
	}
	meminfo := meninfo{
		// "Total":       v.Total,
		// "Free":        v.Free,
		// "UsedPercent": v.UsedPercent,
		v.Total,
		v.Free,
		v.UsedPercent,
	}

	jsons, errs := json.Marshal(meminfo)

	if errs != nil {
		fmt.Println(errs.Error())
	}
	return string(jsons)

}

//Gethostinfo
func Gethostinfo() string {

	type hostnfo struct {
		Hostname             string `json:"hostname"`
		Uptime               uint64 `json:"uptime"`
		BootTime             uint64 `json:"bootTime"`
		Procs                uint64 `json:"procs"`           // number of processes
		OS                   string `json:"os"`              // ex: freebsd, linux
		Platform             string `json:"platform"`        // ex: ubuntu, linuxmint
		PlatformFamily       string `json:"platformFamily"`  // ex: debian, rhel
		PlatformVersion      string `json:"platformVersion"` // version of the complete OS
		KernelVersion        string `json:"kernelVersion"`   // version of the OS kernel (if available)
		VirtualizationSystem string `json:"virtualizationSystem"`
		VirtualizationRole   string `json:"virtualizationRole"` // guest or host
		HostID               string `json:"hostid"`             // ex: uuid
		MachinesID           string `json:"machinesID"`
	}

	v, error := host.Info()
	if error != nil {
		fmt.Println(error.Error())
	}

	hostInfo := hostnfo{
		Hostname:             v.Hostname,
		Uptime:               v.Uptime,
		BootTime:             v.BootTime,
		Procs:                v.Procs,
		OS:                   v.OS,
		Platform:             v.Platform,
		PlatformFamily:       v.PlatformFamily,
		PlatformVersion:      v.PlatformVersion,
		KernelVersion:        v.KernelVersion,
		VirtualizationSystem: v.VirtualizationSystem,
		VirtualizationRole:   v.VirtualizationRole,
		HostID:               v.HostID,
		MachinesID:           GetMacineId(),
	}

	jsons, errs := json.Marshal(hostInfo)
	if errs != nil {
		fmt.Println(errs.Error())
	}
	return string(jsons)
}

func Getinterface() string {

	type Inter struct {
		Name         string `json:"name"`
		HardwareAddr string `json:"hardwareaddr"`
		Flag         string `json:"flags"`
		Addrs        string `json:"addrs"`
	}
	type Interlist struct {
		Ifaces []Inter `json:"interface"`
	}
	// type InterfaceAddr struct {
	// 	Addr string `json:"addr"`
	// }
	// type InterfaceStat struct {
	// 	MTU          int             `json:"mtu"`          // maximum transmission unit
	// 	Name         string          `json:"name"`         // e.g., "en0", "lo0", "eth0.100"
	// 	HardwareAddr string          `json:"hardwareaddr"` // IEEE MAC-48, EUI-48 and EUI-64 form
	// 	Flags        []string        `json:"flags"`        // e.g., FlagUp, FlagLoopback, FlagMulticast
	// 	Addrs        []InterfaceAddr `json:"addrs"`
	// }

	var ifaces []Inter
	Iface := Inter{}

	i, err := psnet.Interfaces()
	if err != nil {
		fmt.Println(err.Error())
	}
	for _, inter := range i {
		if len(inter.HardwareAddr) != 0 {
			Iface.Name = inter.Name
			Iface.HardwareAddr = inter.HardwareAddr

			for _, flag := range inter.Flags {
				switch flag {
				case "up":
					Iface.Flag = "up"
				case "down":
					Iface.Flag = "down"
				}
			}
			for _, addr := range inter.Addrs {

				if len(addr.Addr) < len("fe80::10fc:9e2f:53a6:ec80/64") {
					Iface.Addrs = addr.Addr
				}
			}

			ifaces = append(ifaces, Iface)
		}

	}

	jsons, errs := json.Marshal(ifaces)
	if errs != nil {
		fmt.Println(errs.Error())
	}
	return string(jsons)
}

func main() {

	y := GetMeneinfo()
	fmt.Println(y)
	z := Gethostinfo()
	fmt.Println(z)

	uu := Getinterface()
	fmt.Println(uu)

}
