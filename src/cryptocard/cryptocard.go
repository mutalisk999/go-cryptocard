package cryptocard

import (
	"fmt"
	"github.com/kataras/iris/core/errors"
	"github.com/mutalisk999/go-lib/src/net/buffer_tcp"
	"strconv"
)

type L1Request struct {
	MsgHeader [8]byte
	ReqCode   [2]byte
	KeySize   byte
	KeyIndex  [4]byte
}

func (l *L1Request) Set(keySize byte, keyIndex uint16) error {
	l.MsgHeader = [8]byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}
	l.ReqCode = [2]byte{'L', '1'}
	if keySize < '1' || keySize > '4' {
		return errors.New("invalid key size")
	}
	l.KeySize = keySize
	if keyIndex == 0 || (keyIndex > 1024 && keyIndex < 9999) || keyIndex > 9999 {
		return errors.New("invalid key index")
	}
	keyIndexStr := fmt.Sprintf("%04d", keyIndex)
	copy(l.KeyIndex[0:], keyIndexStr)
	return nil
}

func (l L1Request) GetSize() uint16 {
	return uint16(8 + 2 + 1 + 4)
}

func (l L1Request) Pack(conn *buffer_tcp.BufferTcpConn) error {
	var hb, lb byte
	hb = byte((l.GetSize() & 0xFF00) >> 8)
	lb = byte(l.GetSize() & 0xFF)
	msgReq := make([]byte, 0, 2+l.GetSize())
	msgReq = append(msgReq, hb, lb)
	msgReq = append(msgReq, l.MsgHeader[:]...)
	msgReq = append(msgReq, l.ReqCode[:]...)
	msgReq = append(msgReq, l.KeySize)
	msgReq = append(msgReq, l.KeyIndex[:]...)
	err := conn.TCPWrite(msgReq)
	if err != nil {
		return err
	}
	err = conn.TCPFlush()
	if err != nil {
		return err
	}
	return nil
}

type L2Response struct {
	MsgSize    uint16
	MsgHeader  [8]byte
	RespCode   [2]byte
	ErrCode    [2]byte
	PrivKeyLen [4]byte
	PrivKey    []byte
	PubKey     []byte
}

func (l *L2Response) UnPack(conn *buffer_tcp.BufferTcpConn) error {
	bytesMsgSize, count, _, err := conn.TCPRead(2)
	if err != nil {
		return err
	}
	if count != 2 {
		return errors.New("read bytesMsgSize, can not get enough bytes")
	}
	l.MsgSize = uint16(uint16(bytesMsgSize[0])*uint16(16) + uint16(bytesMsgSize[1]))
	bytesMsg, count, _, err := conn.TCPRead(uint32(l.MsgSize))
	if err != nil {
		return err
	}
	if uint16(count) != l.MsgSize {
		return errors.New("read L2 payload, can not get enough bytes")
	}
	copy(l.MsgHeader[:], bytesMsg[0:8])
	copy(l.RespCode[:], bytesMsg[8:10])
	if l.RespCode[0] != 'L' || l.RespCode[1] != '2' {
		return errors.New("error response, RespCode:" + string(l.RespCode[:]))
	}
	copy(l.ErrCode[:], bytesMsg[10:12])
	if l.ErrCode[0] != '0' || l.ErrCode[1] != '0' {
		return errors.New("error response, ErrCode: " + string(l.ErrCode[:]))
	}
	copy(l.PrivKeyLen[:], bytesMsg[12:16])
	privLen, err := strconv.Atoi(string(l.PrivKeyLen[:]))
	if err != nil {
		return err
	}
	l.PrivKey = bytesMsg[16 : 16+privLen]
	l.PubKey = bytesMsg[16+privLen:]
	return nil
}

type L7Request struct {
	MsgHeader [8]byte
	ReqCode   [2]byte
	SigType   byte
	KeyIndex  [4]byte
	PrivKeyOutSide []byte
	DataSource  []byte
}

func (l *L7Request) Set(sigType byte, keyIndex uint16, privKeyOutSide []byte, dataSource []byte) error {
	l.MsgHeader = [8]byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}
	l.ReqCode = [2]byte{'L', '7'}
	l.SigType = sigType
	if keyIndex == 0 || (keyIndex > 1024 && keyIndex < 9999) || keyIndex > 9999 {
		return errors.New("invalid key index")
	}
	keyIndexStr := fmt.Sprintf("%04d", keyIndex)
	copy(l.KeyIndex[0:], keyIndexStr)
	if keyIndex == 9999 {
		if len(privKeyOutSide) == 0 {
			return errors.New("lack of privKeyOutSide")
		} else {
			l.PrivKeyOutSide = privKeyOutSide
		}
	} else {
		if len(privKeyOutSide) != 0 {
			return errors.New("should not set privKeyOutSide")
		}
	}
	l.DataSource = dataSource
	return nil
}

func (l L7Request) GetSize() uint16 {
	if string(l.KeyIndex[:]) != "9999" {
		return uint16(8 + 2 + 1 + 4 + 4 + len(l.DataSource))
	}
	return uint16(8 + 2 + 1 + 4 + 4 + len(l.PrivKeyOutSide) + 4 + len(l.DataSource))
}

func (l L7Request) Pack(conn *buffer_tcp.BufferTcpConn) error {
	var hb, lb byte
	hb = byte((l.GetSize() & 0xFF00) >> 8)
	lb = byte(l.GetSize() & 0xFF)
	msgReq := make([]byte, 0, 2+l.GetSize())
	msgReq = append(msgReq, hb, lb)
	msgReq = append(msgReq, l.MsgHeader[:]...)
	msgReq = append(msgReq, l.ReqCode[:]...)
	msgReq = append(msgReq, l.SigType)
	msgReq = append(msgReq, l.KeyIndex[:]...)
	if string(l.KeyIndex[:]) == "9999" {
		privKeyOutSideLenStr := fmt.Sprintf("%04d", len(l.PrivKeyOutSide))
		msgReq = append(msgReq, []byte(privKeyOutSideLenStr)...)
		msgReq = append(msgReq, l.PrivKeyOutSide...)
	}
	dataSourceLenStr := fmt.Sprintf("%04d", len(l.DataSource))
	msgReq = append(msgReq, []byte(dataSourceLenStr)...)
	msgReq = append(msgReq, l.DataSource...)
	err := conn.TCPWrite(msgReq)
	if err != nil {
		return err
	}
	err = conn.TCPFlush()
	if err != nil {
		return err
	}
	return nil
}

type L8Response struct {
	MsgSize    uint16
	MsgHeader  [8]byte
	RespCode   [2]byte
	ErrCode    [2]byte
	DataSignedLen [4]byte
	DataSigned   []byte
}

func (l *L8Response) UnPack(conn *buffer_tcp.BufferTcpConn) error {
	bytesMsgSize, count, _, err := conn.TCPRead(2)
	if err != nil {
		return err
	}
	if count != 2 {
		return errors.New("read bytesMsgSize, can not get enough bytes")
	}
	l.MsgSize = uint16(uint16(bytesMsgSize[0])*uint16(16) + uint16(bytesMsgSize[1]))
	bytesMsg, count, _, err := conn.TCPRead(uint32(l.MsgSize))
	if err != nil {
		return err
	}
	if uint16(count) != l.MsgSize {
		return errors.New("read L8 payload, can not get enough bytes")
	}
	copy(l.MsgHeader[:], bytesMsg[0:8])
	copy(l.RespCode[:], bytesMsg[8:10])
	if l.RespCode[0] != 'L' || l.RespCode[1] != '8' {
		return errors.New("error response, RespCode:" + string(l.RespCode[:]))
	}
	copy(l.ErrCode[:], bytesMsg[10:12])
	if l.ErrCode[0] != '0' || l.ErrCode[1] != '0' {
		return errors.New("error response, ErrCode: " + string(l.ErrCode[:]))
	}
	copy(l.DataSignedLen[:], bytesMsg[12:16])
	dataSignedLen, err := strconv.Atoi(string(l.DataSignedLen[:]))
	if err != nil {
		return err
	}
	l.DataSigned = bytesMsg[16:]
	if len(l.DataSigned) != dataSignedLen {
		return errors.New("error response, invalid dataSignedLen or dataSigned")
	}
	return nil
}

