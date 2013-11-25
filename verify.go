package yuuup

import "bytes"
import "errors"
import "crypto/aes"
import "encoding/hex"
import "encoding/binary"
import "fmt"

type OtpStatus int
const (
	OTP_OK OtpStatus = iota
	BAD_OTP
	REPLAYED_OTP
	DELAYED_OTP
	NO_CLIENT
)

type KeyStore interface {
	Lookup(userId []byte) (*StoredKey, error)
	Update(userId []byte, values *YubiKeyValues) error
}

type YubiKeyValues struct {
	Counter int
	Low int
	High int
	Use int
}

type StoredKey struct {
	AesKey []byte
	InternalId []byte
	Val YubiKeyValues
}

func (self *YubiKeyValues) CountersGreaterThan(other *YubiKeyValues) bool {
	if self.Counter == other.Counter {
		return self.Use >= other.Use
	}

	return self.Counter > other.Counter
}

func (self *YubiKeyValues) CountersEqual(other *YubiKeyValues) bool {
	return self.Use == other.Use && self.Counter == other.Counter
}

func loadModHex(modStr []byte) ([]byte, error) {
	const HEX string = "0123456789abcdef"
	const MODHEX string = "cbdefghijklnrtuv"

	hexStr := make([]byte, len(modStr))
	for i, b := range modStr {
		idx := bytes.IndexByte([]byte(MODHEX), b)
		if idx == -1 {
			return nil, errors.New("Invalid modhex string")
		}

		hexStr[i] = HEX[idx]
	}

	bytes := make([]byte, hex.DecodedLen(len(hexStr)))
	if _, err := hex.Decode(bytes, hexStr); err != nil {
		return nil, err
	}

	return bytes, nil
}

func yubikeyCRC(crcBuffer []byte) (uint32, error) {
	crc := uint32(0xffff)

	for _, b := range crcBuffer {
		crc = crc ^ (uint32(b) & 0xff)
		for j := 0; j < 8; j += 1 {
			n := crc & 1
			crc = crc >> 1
			if n != 0 {
				crc = crc ^ 0x8408
			}
		}
	}

	if crc != 0xf0b8 {
		return crc, errors.New("CRC mismatch (expected 0xf0b8)")
	}

	return crc, nil
}

func decryptYubikeyOtp(aesKey, uid, text []byte) (*YubiKeyValues, error) {
	type yubikeyMemory struct {
		Uid [6]byte
		UsageCounter uint16
		TimestampLo uint16
		TimestampHi uint8
		SessionCounter uint8
		Random uint16
		Crc uint16
	}

	otp := &yubikeyMemory{}

	cipher, _ := aes.NewCipher(aesKey)
	cipher.Decrypt(text, text)

	_, err := yubikeyCRC(text)
	if err != nil {
		return nil, errors.New("Checksum check failed for OTP")
	}

	buf := bytes.NewBuffer(text)
	err = binary.Read(buf, binary.LittleEndian, otp)
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(otp.Uid[:], uid) {
		return nil, errors.New("Private ID mismatch")
	}

	return &YubiKeyValues{
		int(otp.UsageCounter & 0x7fff),
		int(otp.TimestampLo),
		int(otp.TimestampHi),
		int(otp.SessionCounter)}, nil
}

func ValidateYubikeyOTP(store KeyStore, otp []byte) OtpStatus {
	otpLen := len(otp)

	if otpLen <= 32 || otpLen > 48 {
		return BAD_OTP
	}

	userId := otp[:otpLen - 32]
	token, err := loadModHex(otp[otpLen - 32:])

	if err != nil {
		fmt.Printf("Failed to decode otp: %s", err)
		return BAD_OTP
	}

	sk, err := store.Lookup(userId)
	if err != nil {
		return BAD_OTP
	}

	values, err := decryptYubikeyOtp(sk.AesKey, sk.InternalId, token)
	if err != nil {
		return BAD_OTP
	}

	fmt.Printf("Loaded OTP: %+v\n", values)

	if sk.Val.CountersGreaterThan(values) {
		return REPLAYED_OTP
	}

	if store.Update(userId, values) != nil {
		return BAD_OTP
	}

	return OTP_OK
}
