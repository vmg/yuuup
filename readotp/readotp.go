package main

import "os"
import "fmt"
import "bufio"
import "github.com/vmg/yuuup"

func main() {
	bio := bufio.NewReader(os.Stdin)
	store := yuuup.NewMemoryKeyStore()

	store.Insert("brjbbhekhugr",
		[]byte{
			0x4c, 0xe4, 0xc7, 0x74,
			0x46, 0x4d, 0xb7, 0xfe,
			0x68, 0x5e, 0x31, 0x5c,
			0x0c, 0xeb, 0xf3, 0xe7},
		[]byte{
			0x13, 0x31, 0x8b, 0x9a,
			0xae, 0x77})

	for {
		fmt.Printf("YubiKey: ")
		line, _, err := bio.ReadLine()
		if err != nil {
			return
		}

		switch yuuup.ValidateYubikeyOTP(store, line) {
		case yuuup.OTP_OK:
			fmt.Printf("...OK\n")
		case yuuup.BAD_OTP:
			fmt.Printf("Bad OTP\n")
		case yuuup.REPLAYED_OTP:
			fmt.Printf("Replayed OTP!\n")
		}
	}
}
