package main

import (
	"fmt"
	"os"
	"time"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

var (
	deviceName  string = "ens33"
	snapshotLen int32  = 1024
	promiscuous bool   = false
	err         error
	timeout     time.Duration = -1 * time.Second
	handle      *pcap.Handle
	packetCount int = 0
  	fileCounter int = 0
)

func get_file_handler() *os.File{
  //  Create file if not exists
  if fi, err := os.Stat(fmt.Sprintf("test%d.pcap", fileCounter)); os.IsNotExist(err) {
  	fmt.Println(fmt.Sprintf("Creating new file test%d.pcap", fileCounter))
    f, _ := os.Create(fmt.Sprintf("test%d.pcap", fileCounter))
    return f
  } else if fi.Size() > 10000 {
	  fmt.Println(fmt.Sprintf("File test%d.pcap reached max! WIll blow!", fileCounter))
  	if fileCounter == 5 {
  		panic("All files filled.")
	}
    fileCounter++
    f, _ := os.Create(fmt.Sprintf("test%d.pcap", fileCounter))
    return f
  } else {
  	fmt.Println(fmt.Sprintf("File test%d.pcap appending time!", fileCounter))
    f, err := os.OpenFile(fmt.Sprintf("test%d.pcap", fileCounter), os.O_APPEND|os.O_WRONLY, 0600)
    if err != nil {
        panic(err)
    }
    return f
  }
}

func get_input_output() (input *gopacket.PacketSource,output *pcapgo.Writer)  {
	// Open output pcap file and write header
	f := get_file_handler()
	output = pcapgo.NewWriter(f)
	output.WriteFileHeader(uint32(snapshotLen), layers.LinkTypeEthernet)
	defer f.Close()

	// Open the device for capturing
	handle, err = pcap.OpenLive(deviceName, snapshotLen, promiscuous, timeout)
	if err != nil {
		fmt.Printf("Error opening device %s: %v", deviceName, err)
		os.Exit(1)
	}

	input = gopacket.NewPacketSource(handle, handle.LinkType())
	return
}

func main() {
	packetSource, w := get_input_output()

	counter := 0
	for packet := range packetSource.Packets() {
		if counter > 20 {
			packetSource, w = get_input_output()
		}
		w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		packetCount++

		counter++
	}
}
