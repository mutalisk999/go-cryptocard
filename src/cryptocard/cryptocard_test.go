package cryptocard

import (
	"encoding/hex"
	"fmt"
	"github.com/mutalisk999/go-lib/src/net/buffer_tcp"
	"testing"
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

func Test_L5Request_L6Response(t *testing.T) {
	conn := new(buffer_tcp.BufferTcpConn)
	err := conn.TCPConnect("192.168.1.188", 1818, 1)
	if err != nil {
		fmt.Println("connect error:" + err.Error())
		return
	}

	var l5req L5Request
	l5req.Set(100, 1)
	fmt.Println("l5req size:", l5req.GetSize())
	fmt.Println("l5req:", l5req)
	err = l5req.Pack(conn)
	if err != nil {
		fmt.Println("send error:" + err.Error())
	}

	var l6resp L6Response
	err = l6resp.UnPack(conn)
	if err != nil {
		fmt.Println("recv error:" + err.Error())
	}
	fmt.Println("l6resp:", l6resp)
	fmt.Println("privKeyLen", len(l6resp.PrivKey))
	fmt.Println("pubKeyLen", len(l6resp.PubKey))
	fmt.Println("privKeyHex", hex.EncodeToString(l6resp.PrivKey))
	fmt.Println("pubKeyHex", hex.EncodeToString(l6resp.PubKey))

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
	fmt.Println("dataSignedHex", hex.EncodeToString(l8resp.DataSigned))

	conn.TCPDisConnect()
}

func Test_L4Request_L5Response(t *testing.T) {
	conn := new(buffer_tcp.BufferTcpConn)
	err := conn.TCPConnect("192.168.1.188", 1818, 1)
	if err != nil {
		fmt.Println("connect error:" + err.Error())
		return
	}

	var l4req L4Request
	dataSigned, _ := hex.DecodeString("3046022100eee55a6c3d6770262c3cc6782fc4ac4941c8e2f2cc0a40ff2b5ddb4bb9c089450221009894e946ff859acce0e7353fb3ffd5a8ef8dd4a760df5ab9aea651f3e19c8a99")
	l4req.Set('2', 1, nil, nil, []byte("test"), dataSigned)
	fmt.Println("l4req size:", l4req.GetSize())
	fmt.Println("l4req:", l4req)
	err = l4req.Pack(conn)
	if err != nil {
		fmt.Println("send error:" + err.Error())
	}

	var l5resp L5Response
	err = l5resp.UnPack(conn)
	if err != nil {
		fmt.Println("recv error:" + err.Error())
	}
	fmt.Println("l5resp:", l5resp)
	fmt.Println("l5resp errcode", l5resp.ErrCode)

	conn.TCPDisConnect()
}

func Test_L8Request_L9Response(t *testing.T) {
	conn := new(buffer_tcp.BufferTcpConn)
	err := conn.TCPConnect("192.168.1.188", 1818, 1)
	if err != nil {
		fmt.Println("connect error:" + err.Error())
		return
	}

	var l8req L8Request
	privKey, _ := hex.DecodeString("c7ffac95f626af074b62d4ef875640671837fe0c69136bfe722d0a3b5f6216cb3142bf3e22d216c2b2ca90a6652e01f97c31cdbe181cc3d794a9d50a64f1f82680ba622bba08dd651bd5bc8936603d2e38efcf2027ed8506a535813029c614e0318ece3becd350daca0819bf9346ff3fb855ed6a635722a294bbc802c647929b")
	l8req.Set(9999, privKey)
	fmt.Println("l8req size:", l8req.GetSize())
	fmt.Println("l8req:", l8req)
	err = l8req.Pack(conn)
	if err != nil {
		fmt.Println("send error:" + err.Error())
	}

	var l9resp L9Response
	err = l9resp.UnPack(conn)
	if err != nil {
		fmt.Println("recv error:" + err.Error())
	}
	fmt.Println("l9resp:", l9resp)
	fmt.Println("pubKeyLen", len(l9resp.PubKey))
	fmt.Println("pubKeyHex", hex.EncodeToString(l9resp.PubKey))

	conn.TCPDisConnect()
}
