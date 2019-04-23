package simple

import (
	"fmt"
	"net"
)

func main() {
	fmt.Println("connecting...")
	inet := &net.UDPAddr{net.IPv4zero, 7000, ""}
	udpConn, err := net.ListenUDP("udp", inet)
	if err != nil {
		panic(err)
	}
	b := make([]byte, 1500)
	oob := make([]byte, 1500)
	//n, b2, err := udpConn.ReadFromUDP(b);
	n, oobn, flags, b2, err := udpConn.ReadMsgUDP(b, oob)
	if err != nil {
		panic(err)
	}
	fmt.Println("connecting... %i, %v, %v, %i, %i", n, b2, oob, oobn, flags)
}
