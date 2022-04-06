package main

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/n0ncetonic/nmapxml"
)

var nmap_template string = "sudo nmap -sS -sU -Pn -T4 -A -v -n --open --max-retries 2 --host-timeout 3m --script-timeout 5m -p %s -oA %s %s\n"
var name_template string = "nmap_%s"

func main() {
	scanData, err := nmapxml.Readfile(os.Args[1])
	if err != nil {
		fmt.Println(err)
		return
	}
	for _, host := range scanData.Host {
		ports := make([]string, 0)
		if host.Ports.Port == nil {
			continue
		}
		for _, port := range *host.Ports.Port {
			if port.State.State == "open" {
				if port.Protocol == "tcp" {
					ports = append(ports, fmt.Sprintf("T:%s", port.PortID))
				} else {
					ports = append(ports, fmt.Sprintf("U:%s", port.PortID))
				}
			}
		}
		if len(ports) > 0 {
			portListStr := strings.Join(ports, ",")

			if host.Hostnames.Hostname.Name != nil && !hostnameEmpty(*host.Hostnames.Hostname.Name) {
				fmt.Printf(nmap_template, portListStr, fmt.Sprintf(name_template, *host.Hostnames.Hostname.Name), *host.Hostnames.Hostname.Name)
			}
			if net.ParseIP(host.Address.Addr) != nil {
				fmt.Printf(nmap_template, portListStr, fmt.Sprintf(name_template, host.Address.Addr), host.Address.Addr)
			}
		}

	}

}

func hostnameEmpty(hostname string) bool {
	return hostname == ""
}
