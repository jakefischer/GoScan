// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// implements ARP scanning of all interfaces' local networks using
// gopacket and its subpackages.  This example shows, among other things:
//   * Generating and sending packet data
//   * Reading in packet data and interpreting it
//   * Use of the 'pcap' subpackage for reading/writing


// This is largely taken from google but hacked to make it work for windows
// due to issues with opening up a pcap handle

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"net"
    "fmt"
	"time"
    "strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func GoScan(hwaddr string) (string, error){
	// Get a list of all interfaces.
	ifaces, err := net.Interfaces()
	if err != nil {
		panic(err)
	}
    
    //as of now just using wireless interfaces found
    found_ip := ""
	for _, iface := range ifaces {
		// Start up a scan on each interface.
        if !strings.Contains(iface.Name, "Wireless"){
            continue
        }
        found_ip, err = scan(&iface, hwaddr)
        if err != nil {
            return "", err
        }
        return found_ip, nil
    }
    return found_ip, errors.New("IP not found for this device address")
}


// Example of request IP Method
// func RequestIpFromHw(HwAddr string) (string, error){
    // params := url.Values{}
    // params.Add("HwAddr", HwAddr)
    
    // resp, err := http.PostForm("http://K0262:8081/SearchHwAddr", params)
    // if err != nil {   
        // fmt.Printf("Request Failed: %s", err)
        // return "", err
    // }
    
    // defer resp.Body.Close()
    // body, err := ioutil.ReadAll(resp.Body)
    // if err != nil {   
        // return "", err
    // }
    // found_ip := string(body)
    // if net.ParseIP(found_ip) == nil{
        // return "", errors.New("Invalid IP address returned from search")
    // }
    // return found_ip, nil
// }


// scans an interface's network for a matching hardware address using ARP requests
func scan(iface *net.Interface, hwaddr string) (string, error) {
	// We just look for IPv4 addresses, so try to find if the interface has one.
	var addr *net.IPNet
	if addrs, err := iface.Addrs(); err != nil {
		return "", err
	} else {
        outboundIP := GetOutboundIP().String()
        // loop through addrs on interface until used one is found
        // if the interfaces ip4 matches the outbout IP we assume it if the one used
        // for the outer world
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				if ip4 := ipnet.IP.To4(); ip4 != nil {
                    if ip4.String() == outboundIP{
                        addr = &net.IPNet{
						IP:   ip4,
						Mask: ipnet.Mask[len(ipnet.Mask)-4:],
                        }
                        break
                    }
				}
			}
		}
	}
    
	// Sanity-check that the interface has a good address.
	if addr == nil {
		return "", errors.New("no good IP network found")
	} else if addr.IP[0] == 127 {
		return "", errors.New("skipping localhost")
	} else if addr.Mask[0] != 0xff || addr.Mask[1] != 0xff {
		return "", errors.New("mask means network is too large")
	}
    
    // Try to find a match between device and interface
    // this is a hack to make it work on windows
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return "", err
	}
	var deviceName string
    // match  net.interface to the pcap device by IP
	for _, d := range devices {
		if strings.Contains(fmt.Sprint(d.Addresses), fmt.Sprint(addr.IP)) {
			deviceName = d.Name
		}
	}
	if deviceName == "" {
		return "", errors.New(fmt.Sprintf("Cannot find the corresponding device for the interface %s", iface.Name))
	}
    

	// Open up a pcap handle for packet reads/writes.
	handle, err := pcap.OpenLive(deviceName, 65536, true, pcap.BlockForever)
	if err != nil {
		return "", err
	}
	defer handle.Close()

	// Start up a goroutine to read in packet data.
    ip_chan := make(chan string)
	go readARP(handle, iface, hwaddr, ip_chan)
    
    // Write our scan packets out to the handle.
    if err := writeARP(handle, iface, addr); err != nil {
        return "", err
    }
    
    found_ip := <-ip_chan
    if (found_ip == ""){
       return "", errors.New("IP of given hardware ID was not found")
    }
       
    return found_ip, nil
}

// readARP watches a handle for incoming ARP responses we might care about, and prints them.
// hwLinkAddr is the hardware address of the device we're looking for
// returns the ip of the device
func readARP(handle *pcap.Handle, iface *net.Interface, 
            hwLinkAddr string, ip_chan chan string){
	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	in := src.Packets()
    scanTimer := time.NewTimer(4* time.Second)
	for {
		var packet gopacket.Packet
		select {
            case <-scanTimer.C:
                    ip_chan <- ""
                    return
            case packet = <-in:
                arpLayer := packet.Layer(layers.LayerTypeARP)
                if arpLayer == nil {
                    continue
                }
                arp := arpLayer.(*layers.ARP)
                if arp.Operation != layers.ARPReply || bytes.Equal([]byte(iface.HardwareAddr), arp.SourceHwAddress) {
                    // This is a packet I sent.
                    continue
                }
                // Note:  we might get some packets here that aren't responses to ones we've sent,
                if (net.HardwareAddr(arp.SourceHwAddress).String() == hwLinkAddr){
                    ip_chan <- net.IP(arp.SourceProtAddress).String()
                    return
                }
		}
	}
}

// writeARP writes an ARP request for each address on our local network to the
// pcap handle.
func writeARP(handle *pcap.Handle, iface *net.Interface, addr *net.IPNet) error {
	// Set up all the layers' fields we can.
	eth := layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(iface.HardwareAddr),
		SourceProtAddress: []byte(addr.IP),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
	}
	// Set up buffer and options for serialization.
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	// Send one packet for every address.
	for _, ip := range ips(addr) {
		arp.DstProtAddress = []byte(ip)
		gopacket.SerializeLayers(buf, opts, &eth, &arp)
		if err := handle.WritePacketData(buf.Bytes()); err != nil {
			return err
		}
	}
	return nil
}

// ips is a simple and not very good method for getting all IPv4 addresses from a
// net.IPNet.  It returns all IPs it can over the channel it sends back, closing
// the channel when done.
func ips(n *net.IPNet) (out []net.IP) {
	num := binary.BigEndian.Uint32([]byte(n.IP))
	mask := binary.BigEndian.Uint32([]byte(n.Mask))
	network := num & mask
	broadcast := network | ^mask
	for network++; network < broadcast; network++ {
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], network)
		out = append(out, net.IP(buf[:]))
	}
	return
}

// get preferred outbound ip address
func GetOutboundIP() net.IP {
    conn, err := net.Dial("udp", "8.8.8.8:80")
    if err != nil {
        log.Fatal(err)
    }
    defer conn.Close()
    localAddr := conn.LocalAddr().(*net.UDPAddr)
    return localAddr.IP
}