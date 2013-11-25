package yuuup

import "testing"

/*
	Public ID:		br jb bh ek hu gr
	Private ID:		13 31 8b 9a ae 77
	AES key:		4c e4 c7 74 46 4d b7 fe 68 5e 31 5c 0c eb f3 e7

	Examples:

	brjbbhekhugrrhkttvggkjujitjgguudukntnevhreju
	brjbbhekhugrcbuufehnbibhklgvfvjrjfbdfvfiurbj
	brjbbhekhugrffjkvbcghdevtrrhfhfjghbcbkkvdrki
	brjbbhekhugrvcugvtbbkcdhvnlnnekfdrcgedhvnuui
	brjbbhekhugrgedheebbkjvucrcvheiicrnificgfhec
*/

func TestSimpleOtp(t *testing.T) {
	store := NewMemoryKeyStore()
	store.Insert("brjbbhekhugr",
		[]byte{
			0x4c, 0xe4, 0xc7, 0x74,
			0x46, 0x4d, 0xb7, 0xfe,
			0x68, 0x5e, 0x31, 0x5c,
			0x0c, 0xeb, 0xf3, 0xe7},
		[]byte{
			0x13, 0x31, 0x8b, 0x9a,
			0xae, 0x77})

	testData := [...]string{
		"brjbbhekhugrrhkttvggkjujitjgguudukntnevhreju",
		"brjbbhekhugrcbuufehnbibhklgvfvjrjfbdfvfiurbj",
		"brjbbhekhugrffjkvbcghdevtrrhfhfjghbcbkkvdrki",
		"brjbbhekhugrvcugvtbbkcdhvnlnnekfdrcgedhvnuui",
		"brjbbhekhugrgedheebbkjvucrcvheiicrnificgfhec"}

	for _, token := range testData {
		if ValidateYubikeyOTP(store, []byte(token)) != OTP_OK {
			t.Errorf("Token %s failed validation", token)
		}
	}

	for _, token := range testData {
		if ValidateYubikeyOTP(store, []byte(token)) != REPLAYED_OTP {
			t.Errorf("Token %s was successfully replayed", token)
		}
	}
}
