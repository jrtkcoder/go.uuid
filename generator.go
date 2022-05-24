// Copyright (C) 2013-2018 by Maxim Bublis <b@codemonkey.ru>
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package uuid

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"regexp"
	"hash"
	"net"
	"os"
	"sync"
	"time"
	//"fmt"
)

// Difference in 100-nanosecond intervals between
// UUID epoch (October 15, 1582) and Unix epoch (January 1, 1970).
const epochStart = 122192928000000000

const hexPattern = "[A-Fa-f0-9]{8}"

var re = regexp.MustCompile(hexPattern)

var (
	global = newDefaultGenerator()

	epochFunc = unixTimeFunc
	posixUID  = uint32(os.Getuid())
	posixGID  = uint32(os.Getgid())
)

func NewIncUUID(name string) UUID {
	return global.NewIncUUID(name)
}

// NewV1 returns UUID based on current timestamp and MAC address.
func NewV1() UUID {
	return global.NewV1()
}

// NewV2 returns DCE Security UUID based on POSIX UID/GID.
func NewV2(domain byte) UUID {
	return global.NewV2(domain)
}

// NewV3 returns UUID based on MD5 hash of namespace UUID and name.
func NewV3(ns UUID, name string) UUID {
	return global.NewV3(ns, name)
}

// NewV4 returns random generated UUID.
func NewV4() UUID {
	return global.NewV4()
}

// NewV5 returns UUID based on SHA-1 hash of namespace UUID and name.
func NewV5(ns UUID, name string) UUID {
	return global.NewV5(ns, name)
}

// Generator provides interface for generating UUIDs.
type Generator interface {
	NewIncUUID(name string) UUID
	NewV1() UUID
	NewV2(domain byte) UUID
	NewV3(ns UUID, name string) UUID
	NewV4() UUID
	NewV5(ns UUID, name string) UUID
}

// Default generator implementation.
type generator struct {
	storageOnce  sync.Once
	storageMutex sync.Mutex

	lastTime      uint64
	clockSequence uint16
	hardwareAddr  [6]byte
}

func newDefaultGenerator() Generator {
	return &generator{}
}

// 新生一个单调递增的 UUID
func (g *generator) NewIncUUID(name string) UUID {
	u := UUID{}
	
	if (len(name)>0 && (len(name) != 8)) {
		panic("UUID length != 8")
		return u
	}
	
 
	timeNow, clockSeq, hardwareAddr := g.getStorage()
	
	//有name且长度为8时，用name替换
	if (len(name)>0 && (len(name) == 8)) {
		md := re.FindStringSubmatch(name)
		if md == nil {
			panic("Invalid UUID string")
			return u
		}
		byteName, _ := hex.DecodeString(name)
		//fmt.Printf("----byteName----- %v\n", byteName)
		var tmpArr [6]byte
		copy(tmpArr[2:], byteName)
		//fmt.Printf("----tmpArr----- %v\n", tmpArr)
		copy(hardwareAddr[:], tmpArr[:])
	}
	// 时间戳高位
	u[0] = byte(uint16(timeNow >> 48))
	// 时间戳中位
	binary.BigEndian.PutUint16(u[1:], uint16(timeNow>>32))
	// 时间戳低位第1~3个字节
	u[3] = byte(uint32(timeNow) >> 24)
	u[4] = byte(uint32(timeNow) >> 16)
	u[5] = byte(uint32(timeNow) >> 8)
	// UUID版本
	u[6] = byte(uint16(timeNow>>48) >> 8)
	// 时间戳低位第4个字节
	u[7] = byte(uint32(timeNow))
	// 时钟序列
	binary.BigEndian.PutUint16(u[8:], clockSeq)
	// MAC地址
	copy(u[10:], hardwareAddr)
 
	// 设置版本号位
	u[6] = (u[6] & 0x0f) | (V1 << 4)
	// 设置变体号位
	u[8] = (u[8]&(0xff>>2) | (0x02 << 6))
 
	return u
}

// NewV1 returns UUID based on current timestamp and MAC address.
func (g *generator) NewV1() UUID {
	u := UUID{}

	timeNow, clockSeq, hardwareAddr := g.getStorage()

	binary.BigEndian.PutUint32(u[0:], uint32(timeNow))
	binary.BigEndian.PutUint16(u[4:], uint16(timeNow>>32))
	binary.BigEndian.PutUint16(u[6:], uint16(timeNow>>48))
	binary.BigEndian.PutUint16(u[8:], clockSeq)

	copy(u[10:], hardwareAddr)

	u.SetVersion(V1)
	u.SetVariant(VariantRFC4122)

	return u
}

// NewV2 returns DCE Security UUID based on POSIX UID/GID.
func (g *generator) NewV2(domain byte) UUID {
	u := UUID{}

	timeNow, clockSeq, hardwareAddr := g.getStorage()

	switch domain {
	case DomainPerson:
		binary.BigEndian.PutUint32(u[0:], posixUID)
	case DomainGroup:
		binary.BigEndian.PutUint32(u[0:], posixGID)
	}

	binary.BigEndian.PutUint16(u[4:], uint16(timeNow>>32))
	binary.BigEndian.PutUint16(u[6:], uint16(timeNow>>48))
	binary.BigEndian.PutUint16(u[8:], clockSeq)
	u[9] = domain

	copy(u[10:], hardwareAddr)

	u.SetVersion(V2)
	u.SetVariant(VariantRFC4122)

	return u
}

// NewV3 returns UUID based on MD5 hash of namespace UUID and name.
func (g *generator) NewV3(ns UUID, name string) UUID {
	u := newFromHash(md5.New(), ns, name)
	u.SetVersion(V3)
	u.SetVariant(VariantRFC4122)

	return u
}

// NewV4 returns random generated UUID.
func (g *generator) NewV4() UUID {
	u := UUID{}
	g.safeRandom(u[:])
	u.SetVersion(V4)
	u.SetVariant(VariantRFC4122)

	return u
}

// NewV5 returns UUID based on SHA-1 hash of namespace UUID and name.
func (g *generator) NewV5(ns UUID, name string) UUID {
	u := newFromHash(sha1.New(), ns, name)
	u.SetVersion(V5)
	u.SetVariant(VariantRFC4122)

	return u
}

func (g *generator) initStorage() {
	g.initClockSequence()
	g.initHardwareAddr()
}

func (g *generator) initClockSequence() {
	buf := make([]byte, 2)
	g.safeRandom(buf)
	g.clockSequence = binary.BigEndian.Uint16(buf)
}

func (g *generator) initHardwareAddr() {
	interfaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range interfaces {
			if len(iface.HardwareAddr) >= 6 {
				copy(g.hardwareAddr[:], iface.HardwareAddr)
				return
			}
		}
	}

	// Initialize hardwareAddr randomly in case
	// of real network interfaces absence
	g.safeRandom(g.hardwareAddr[:])

	// Set multicast bit as recommended in RFC 4122
	g.hardwareAddr[0] |= 0x01
}

func (g *generator) safeRandom(dest []byte) {
	if _, err := rand.Read(dest); err != nil {
		panic(err)
	}
}

// Returns UUID v1/v2 storage state.
// Returns epoch timestamp, clock sequence, and hardware address.
func (g *generator) getStorage() (uint64, uint16, []byte) {
	g.storageOnce.Do(g.initStorage)

	g.storageMutex.Lock()
	defer g.storageMutex.Unlock()

	timeNow := epochFunc()
	// Clock changed backwards since last UUID generation.
	// Should increase clock sequence.
	if timeNow <= g.lastTime {
		g.clockSequence++
	}
	g.lastTime = timeNow

	return timeNow, g.clockSequence, g.hardwareAddr[:]
}

// Returns difference in 100-nanosecond intervals between
// UUID epoch (October 15, 1582) and current time.
// This is default epoch calculation function.
func unixTimeFunc() uint64 {
	return epochStart + uint64(time.Now().UnixNano()/100)
}

// Returns UUID based on hashing of namespace UUID and name.
func newFromHash(h hash.Hash, ns UUID, name string) UUID {
	u := UUID{}
	h.Write(ns[:])
	h.Write([]byte(name))
	copy(u[:], h.Sum(nil))

	return u
}
