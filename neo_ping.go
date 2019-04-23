package main

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

func main() {
	fmt.Println("connecting...")
	//check: http://monitor.cityofzion.io/
	remote, err := net.Dial("tcp", "seed4.aphelion-neo.com:10333")
	if err != nil {
		panic(err)
	}
	defer remote.Close()

	//we get the version from the remote, display it
	read := make([]byte, 200)
	n, err := remote.Read(read)
	plen := decodeHeader(read)
	payloadRet := read[24 : 24+plen]
	tmp := sha256.Sum256(payloadRet)
	hash := sha256.Sum256(tmp[:])
	checkRet := binary.LittleEndian.Uint32(hash[0:4])
	fmt.Printf("got check: 0x%x\n", checkRet)
	decodeVersion(payloadRet)
	fmt.Printf("read version: %v, %d\n", read[:n], n)

	payloadVersion := encodeVersion("/The NEO client/")
	packetVersion := encodeHeader("version", payloadVersion)
	packetVerack := encodeHeader("verack", []byte{})
	n, err = remote.Write(append(packetVersion, packetVerack...))
	if err != nil {
		panic(err)
	}
	fmt.Printf("wrote version: %v, %d\n", append(packetVersion, packetVerack...), n)

	read = make([]byte, 200)
	n, err = remote.Read(read)
	decodeHeader(read)
	fmt.Printf("read verack array: %d\n", n)

	//packetVerack := encodeHeader("verack", []byte{})
	//n, err = remote.Write(packetVerack);
	//if err != nil {
	//	panic(err)
	//}
	//fmt.Printf("wrote verack: %v, %d\n", packetVerack, n)

	//read = make([]byte, 200)
	//n, err = remote.Read(read)
	//fmt.Printf("read array: %v, %d\n", read[:n], n)

	packet2 := encodeHeader("ping", encodePing())
	n, err = remote.Write(packet2)
	if err != nil {
		panic(err)
	}
	fmt.Printf("wrote ping: %v, %d\n", packet2, n)

	read2 := make([]byte, 36)
	n, err = remote.Read(read2)
	decodeHeader(read2)
	payloadRet2 := read2[24 : 24+12]
	decodePing(payloadRet2)
	fmt.Printf("read array: %v\n", read2[:n])

	remote.Close()

}

func encodeHeader(cmd string, payload []byte) []byte {
	b := make([]byte, 24+len(payload))
	//magic
	binary.LittleEndian.PutUint32(b[0:], 0x00746E41)
	//command
	copy(b[4:], cmd)
	//payload length
	binary.LittleEndian.PutUint32(b[16:], uint32(len(payload)))
	//payload checksum
	tmp := sha256.Sum256(payload)
	hash := sha256.Sum256(tmp[:])
	copy(b[20:], hash[0:4])
	//payload
	copy(b[24:], payload)
	return b
}

func encodeVersion(userAgent string) []byte {
	userAgentLen := len(userAgent)
	b := make([]byte, 27+userAgentLen+1)

	//version
	binary.LittleEndian.PutUint32(b[0:], 0)
	//service
	binary.LittleEndian.PutUint64(b[4:], 1)
	//timestamp
	binary.LittleEndian.PutUint32(b[12:], uint32(time.Now().Unix()))
	//port
	binary.LittleEndian.PutUint16(b[16:], uint16(0))
	//nonce
	binary.LittleEndian.PutUint32(b[18:], 77)
	//length of user agent
	b[22] = uint8(userAgentLen)
	//user agent
	copy(b[23:], userAgent)
	//blockheight
	binary.LittleEndian.PutUint32(b[23+userAgentLen:], 3657605)
	//relay
	b[27+userAgentLen] = 0
	return b
}

func encodePing() []byte {
	b := make([]byte, 12)
	binary.LittleEndian.PutUint32(b[0:], 3657605)
	binary.LittleEndian.PutUint32(b[4:], uint32(time.Now().Unix()))
	binary.LittleEndian.PutUint32(b[8:], 33)
	return b
}

func decodeHeader(b []byte) uint32 {
	fmt.Printf("magic: 0x%x\n", binary.LittleEndian.Uint32(b))
	fmt.Printf("command: %v\n", string(b[4:16]))
	len := binary.LittleEndian.Uint32(b[16:])
	fmt.Printf("payload len: %d\n", len)
	fmt.Printf("checksum: 0x%x\n", binary.LittleEndian.Uint32(b[20:]))
	return len
}

func decodeVersion(b []byte) {
	fmt.Printf("version: %d\n", binary.LittleEndian.Uint32(b))
	fmt.Printf("service: %d\n", binary.LittleEndian.Uint64(b[4:]))
	fmt.Printf("time: %v\n", time.Unix(int64(binary.LittleEndian.Uint32(b[12:])), 0))
	fmt.Printf("port: %d\n", binary.LittleEndian.Uint16(b[16:]))
	fmt.Printf("nonce: 0x%x\n", binary.LittleEndian.Uint32(b[18:]))
	userAgentLen := b[22]
	fmt.Printf("user agent: %v\n", string(b[23:23+userAgentLen]))
	fmt.Printf("block height: %d\n", binary.LittleEndian.Uint32(b[23+userAgentLen:]))
	fmt.Printf("relay: %d\n", b[27+userAgentLen])
}

func decodePing(b []byte) {
	fmt.Printf("last block: %d\n", binary.LittleEndian.Uint32(b))
	fmt.Printf("time: %v\n", time.Unix(int64(binary.LittleEndian.Uint32(b[4:])), 0))
	fmt.Printf("nonce: 0x%x\n", binary.LittleEndian.Uint32(b[8:]))
}
