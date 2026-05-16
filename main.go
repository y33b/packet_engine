package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"nexus/detector"
	"nexus/engine"
	"nexus/model"
	storepkg "nexus/store"
	"nexus/ws"
)

func cleanPacket(packet gopacket.Packet, eng *engine.Engine) {

	netlayer := packet.NetworkLayer()
	if netlayer == nil {
		return
	}

	src, dst := netlayer.NetworkFlow().Endpoints()

	tcplayer := packet.TransportLayer()
	if tcplayer == nil {
		return
	}

	tcp, ok := tcplayer.(*layers.TCP)
	if !ok {
		return
	}

	event := model.Event{
		SrcIP:     src.String(),
		DstIP:     dst.String(),
		DstPort:   int(tcp.DstPort),
		Syn:       tcp.SYN,
		Size:      len(packet.Data()),
		Timestamp: time.Now().Unix(),
	}

	eng.Process(event)
}

func main() {

	// -----------------------
	// INIT
	// -----------------------
	store := storepkg.NewStorage()
	hub := ws.NewHub()

	eng := engine.NewEngine()
	eng.Detector = &detector.Detector{}

	// -----------------------
	// WS SERVER
	// -----------------------
	http.HandleFunc("/ws", hub.HandleWS)

	go func() {
		fmt.Println("WebSocket running on :8080")
		_ = http.ListenAndServe(":8080", nil)
	}()

	go hub.Run()

	// -----------------------
	// ALERT DISPATCHER
	// -----------------------
	go func() {
		for alert := range eng.Alerts {

			hub.Broadcast <- ws.WSMessage{
				Type: "alert",
				Data: alert,
			}

			go store.SaveAlert(alert)

			fmt.Printf("🚨 ALERT: %s IP=%s Risk=%.2f\n",
				model.AlertTypeName[alert.Type],
				alert.IP,
				alert.Risk,
			)
		}
	}()

	// -----------------------
	// ML DISPATCHER
	// -----------------------
	go func() {
		for e := range eng.ML {

			hub.Broadcast <- ws.WSMessage{
				Type: "ml",
				Data: e,
			}

			fmt.Printf("🧠 ML EVENT: %s packets=%d ports=%d\n",
				e.SrcIP,
				e.PacketRate,
				e.UniquePorts,
			)
		}
	}()

	// -----------------------
	// PACKET CAPTURE
	// -----------------------
	handle, err := pcap.OpenLive("wlp0s20f3", 1600, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		cleanPacket(packet, eng)
	}
}
