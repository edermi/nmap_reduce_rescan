package main

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/n0ncetonic/nmapxml"
)

// Template for the generated scan string
var nmap_template string = "sudo nmap -sS -sU -Pn -T4 -A -v -n --version-light --script \"default,safe,discovery\" --open --max-retries 2 --host-timeout 3m --script-timeout 5m -p %s -oA %s %s\n"
var name_template string = "nmap_%s"

func main() {
	// Read the data
	scanData, err := nmapxml.Readfile(os.Args[1])
	if err != nil {
		fmt.Println(err)
		return
	}

	// Store all hosts
	known_hosts := make(map[string][]string)

	// Iterate all hosts, collect port information and store it in the map
	for _, host := range scanData.Host {
		var hostname string

		// Filter empty as well as short names without '.' (e.g. NetBIOS names)
		if host.Hostnames.Hostname.Name != nil && !hostnameEmpty(*host.Hostnames.Hostname.Name) && strings.Contains(*host.Hostnames.Hostname.Name, ".") {
			hostname = *host.Hostnames.Hostname.Name
		} else if net.ParseIP(host.Address.Addr) != nil {
			hostname = host.Address.Addr
		} else {
			continue
		}

		if host.Ports.Port == nil {
			continue
		}
		for _, port := range *host.Ports.Port {
			if port.State.State == "open" {
				if port.Protocol == "tcp" {
					addPort(known_hosts, hostname, fmt.Sprintf("T:%s", port.PortID))
				} else {
					addPort(known_hosts, hostname, fmt.Sprintf("U:%s", port.PortID))
				}
			}
		}
	}

	// Iterate the map and create the relevant output
	for hostname, ports := range known_hosts {
		if len(ports) > 0 {
			fmt.Printf(nmap_template, strings.Join(ports, ","), fmt.Sprintf(name_template, hostname), hostname)
		}
	}
}

func addPort(known_hosts map[string][]string, hostname string, port string) {
	ports, exists := known_hosts[hostname]
	if !exists {
		// If the hostname does not exist, add it with the new port
		known_hosts[hostname] = []string{port}
	} else {
		// Check if the port already exists to avoid duplicates
		found := false
		for _, p := range ports {
			if p == port {
				found = true
				break
			}
		}
		// If the port is not found, append it to the list of ports
		if !found {
			known_hosts[hostname] = append(ports, port)
		}
	}
}

func hostnameEmpty(hostname string) bool {
	return hostname == ""
}
