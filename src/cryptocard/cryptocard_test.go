package cryptocard

import (
	"fmt"
	"testing"
	"github.com/mutalisk999/go-lib/src/net/buffer_tcp"
)

func Test_L1Request_L2Response(t *testing.T) {
	conn := new(buffer_tcp.BufferTcpConn)
	err := conn.TCPConnect("192.168.1.188", 1818, 1)
	if err != nil {
		fmt.Println("connect error:" + err.Error())
		return
	}

	var l1req L1Request
	l1req.Set('4', 1)
	fmt.Println("l1req size:", l1req.GetSize())
	fmt.Println("l1req:", l1req)
	err = l1req.Pack(conn)
	if err != nil {
		fmt.Println("send error:" + err.Error())
	}

	var l2resp L2Response
	err = l2resp.UnPack(conn)
	if err != nil {
		fmt.Println("recv error:" + err.Error())
	}
	fmt.Println("l2resp:", l2resp)
	fmt.Println("privKeyLen", len(l2resp.PrivKey))
	fmt.Println("pubKeyLen", len(l2resp.PubKey))

	conn.TCPDisConnect()
}

func Test_L7Request_L8Response(t *testing.T) {
	conn := new(buffer_tcp.BufferTcpConn)
	err := conn.TCPConnect("192.168.1.188", 1818, 1)
	if err != nil {
		fmt.Println("connect error:" + err.Error())
		return
	}

	var l7req L7Request
	l7req.Set('2', 1, nil, []byte("test"))
	fmt.Println("l7req size:", l7req.GetSize())
	fmt.Println("l7req:", l7req)
	err = l7req.Pack(conn)
	if err != nil {
		fmt.Println("send error:" + err.Error())
	}

	var l8resp L8Response
	err = l8resp.UnPack(conn)
	if err != nil {
		fmt.Println("recv error:" + err.Error())
	}
	fmt.Println("l8resp:", l8resp)
	fmt.Println("dataSignedLen", len(l8resp.DataSigned))
	fmt.Println("dataSigned", l8resp.DataSigned)

	conn.TCPDisConnect()
}