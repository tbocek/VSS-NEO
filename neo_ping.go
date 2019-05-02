package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/hashicorp/go-version"
	"io"
	"math/rand"
	"net"
	"strings"
	"time"
)

func main() {
	remote, err := net.Dial("tcp", "seed.neoeconomy.io:10333") //check: http://monitor.cityofzion.io/
	if err != nil {
		panic(err)
	}
	defer remote.Close()
	fmt.Println("Conneced to: %v", remote.RemoteAddr())

	payloadVersion := encodeVersion("/The HSR NEO client:0.0.1/")
	packetVersion := encodeHeader("version", payloadVersion)
	n, err := remote.Write(packetVersion)
	if err != nil {
		panic(err)
	}
	fmt.Printf("wrote version packet: %v, %d\n", packetVersion, n)

	//we get the version from the remote, display it
	read := make([]byte, 24)
	n, err = io.ReadFull(remote, read) //read header
	plen, rcvChecksum := decodeHeader(read)
	read = make([]byte, plen)
	n, err = io.ReadFull(remote, read) //read payload
	userAgent := decodeVersion(read)

	tmp := sha256.Sum256(read)
	hash := sha256.Sum256(tmp[:])
	checksum := binary.LittleEndian.Uint32(hash[0:4])
	fmt.Printf("read version payload: %v, %d\n", read, n)
	if rcvChecksum != checksum {
		panic(errors.New("checksum mismatch in version!"))
	}

	//check if we have a good version
	start := strings.Index(userAgent, ":")
	end := strings.Index(userAgent[start:], "/")
	if start < 0 && end < 0 {
		panic(errors.New(fmt.Sprintf("cannot parse version in %s", userAgent)))
	}
	semVer := userAgent[start+1 : start+end]
	fmt.Printf("parsed semver: %v\n", semVer)
	v1, err := version.NewVersion(semVer)
	min, err := version.NewVersion("2.10.1")
	if v1.LessThan(min) {
		panic(errors.New(fmt.Sprintf("%s is less than %s", v1, min)))
	}

	////////// got version, send ack
	packetVerack := encodeHeader("verack", []byte{})
	n, err = remote.Write(packetVerack)
	if err != nil {
		panic(err)
	}

	///////// wait for verack confirmation
	read = make([]byte, 24)
	n, err = io.ReadFull(remote, read)
	plen, rcvChecksum = decodeHeader(read)
	fmt.Printf("read verack array: %v, %d\n", read, plen)
	if rcvChecksum != 3806393949 {
		panic(errors.New("checksum mismatch in verack!"))
	}

	/////// send ping
	packet2 := encodeHeader("ping", encodePing())
	n, err = remote.Write(packet2)
	if err != nil {
		panic(err)
	}
	fmt.Printf("wrote ping: %v, %d\n", packet2, n)

	//////// receive pong
	read = make([]byte, 36)
	_, err = io.ReadFull(remote, read)
	_, rcvChecksum = decodeHeader(read)
	decodePing(read[24 : 24+12])
	fmt.Printf("read array: %v\n", read)

	tmp = sha256.Sum256(read[24 : 24+12])
	hash = sha256.Sum256(tmp[:])
	checksum = binary.LittleEndian.Uint32(hash[0:4])

	if rcvChecksum != checksum {
		panic(errors.New("checksum mismatch in pong!"))
	}

	//getaddr
	packet := encodeHeader("getaddr", []byte{})
	n, err = remote.Write(packet)
	if err != nil {
		panic(err)
	}
	fmt.Printf("wrote getaddr: %v, %d\n", packet, n)

	read = make([]byte, 10000)
	n, err = remote.Read(read)
	fmt.Printf("read getaddr: %v, %d\n", read[:n], n)

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
	b := make([]byte, 28+userAgentLen)
	//version
	binary.LittleEndian.PutUint32(b[0:], 0)
	//service
	binary.LittleEndian.PutUint64(b[4:], 1)
	//timestamp
	binary.LittleEndian.PutUint32(b[12:], uint32(time.Now().Unix()))
	//port
	binary.LittleEndian.PutUint16(b[16:], uint16(0))
	//nonce
	binary.LittleEndian.PutUint32(b[18:], rand.Uint32())
	//length of user agent
	b[22] = uint8(userAgentLen)
	//user agent
	copy(b[23:], userAgent)
	//blockheight
	binary.LittleEndian.PutUint32(b[23+userAgentLen:], 0)
	//relay
	b[27+userAgentLen] = 0
	return b
}

func encodePing() []byte {
	b := make([]byte, 12)
	//blockheight
	binary.LittleEndian.PutUint32(b[0:], 0)
	//timestamp
	binary.LittleEndian.PutUint32(b[4:], uint32(time.Now().Unix()))
	//nonce
	binary.LittleEndian.PutUint32(b[8:], rand.Uint32())
	return b
}

func decodeHeader(b []byte) (uint32, uint32) {
	fmt.Printf("magic: 0x%x\n", binary.LittleEndian.Uint32(b))
	fmt.Printf("command: %v\n", string(bytes.Trim(b[4:16], "\x00")))
	len := binary.LittleEndian.Uint32(b[16:])
	fmt.Printf("payload len: %d\n", len)
	checksum := binary.LittleEndian.Uint32(b[20:])
	fmt.Printf("checksum: 0x%x\n", checksum)
	return len, checksum
}

func decodeVersion(b []byte) string {
	fmt.Printf("version: %d\n", binary.LittleEndian.Uint32(b))
	fmt.Printf("service: %d\n", binary.LittleEndian.Uint64(b[4:]))
	fmt.Printf("time: %v\n", time.Unix(int64(binary.LittleEndian.Uint32(b[12:])), 0))
	fmt.Printf("port: %d\n", binary.LittleEndian.Uint16(b[16:]))
	fmt.Printf("nonce: 0x%x\n", binary.LittleEndian.Uint32(b[18:]))
	userAgentLen := b[22]
	userAgent := string(bytes.Trim(b[23:23+userAgentLen], "\x00"))
	fmt.Printf("user agent: %v\n", userAgent)
	fmt.Printf("block height: %d\n", binary.LittleEndian.Uint32(b[23+userAgentLen:]))
	fmt.Printf("relay: %d\n", b[27+userAgentLen])
	return userAgent
}

func decodePing(b []byte) {
	fmt.Printf("last block: %d\n", binary.LittleEndian.Uint32(b))
	fmt.Printf("time: %v\n", time.Unix(int64(binary.LittleEndian.Uint32(b[4:])), 0))
	fmt.Printf("nonce: 0x%x\n", binary.LittleEndian.Uint32(b[8:]))
}
