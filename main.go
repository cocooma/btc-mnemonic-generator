package main

import (
	"flag"
	"fmt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/skip2/go-qrcode"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
	"os"
	"strings"
)

var mnemonic, folderName, password, networkName, firstWords  string
var derivationPath string
var dices string
var network chaincfg.Params
var entropy []byte
var private bool

func init() {
  flag.StringVar(&mnemonic,   "mnemonic",  "",                        "Mnemonic words")
  flag.StringVar(&folderName, "folder",    "generated_keys_qr_codes", "Folder name default: 'generated_keys_qr_codes'")
  flag.StringVar(&password,   "password",  "",                        "Password")
  flag.StringVar(&dices,      "dices",     "",                        "Dices")
  flag.StringVar(&firstWords, "firstWords","",                        "Insert the first 23 Words. It'll generate the 24th")
  flag.BoolVar(&private,      "private",   false,                     "Display private data" )
  flag.Parse()
}

func main(){
	
	pubkeyBytesToUse := [4]byte{0x02, 0xaa, 0x7e, 0xd3}  // Zpub
	network = chaincfg.MainNetParams
	networkName = "mainnet"
	derivationPath = "m/48'/0'/0'/2'"

	if firstWords != "" {
		seedNumber := SeedCount(firstWords)
		if 23 < seedNumber ||  23 > seedNumber {
			fmt.Printf("Incorect number of seed words, it should be 23 but it is: %d\n", seedNumber)
			os.Exit(1)
		}
		fmt.Println("Please see the seed picker 24th checksum words:")
		word, _ := FindAllChecksumWords(firstWords)
		fmt.Println(word)
		os.Exit(0)
	}else if mnemonic != "" && dices != "" {
		fmt.Println("Mnemonic and dices are both set please only set one at a time!")
		os.Exit(1)
	} else if mnemonic == "" && dices == "" {
		fmt.Println("Mnemonic and dices are not set auto generating entropy!")
		entropy, _ = bip39.NewEntropy(256)
		mnemonic, _ = bip39.NewMnemonic(entropy)
	} else if dices != "" {
		entropy = ConvertDiceToHash(dices)
		mnemonic, _ = bip39.NewMnemonic(entropy)
	}

	seed := bip39.NewSeed(mnemonic, password)
	network = chaincfg.MainNetParams
	masterKey, _ := bip32.NewMasterKey(seed)
	masterXpub := masterKey.PublicKey()
	masterXpriv, err := hdkeychain.NewMaster(seed, &network)

	if err != nil {
		fmt.Println("Couldn't create seed", err)
		os.Exit(1)
	}

	childXpriv, err := DeriveChildKeyFromPath(masterXpriv, derivationPath)
	if err != nil {
		fmt.Println("Error deriving child private key", err)
		os.Exit(1)
	}

	childXpub, err := childXpriv.Neuter()
	if err != nil {
		fmt.Println("Error deriving child public key", err)
		os.Exit(1)
	}

	childZpub, err := Slip132Encode(childXpub, pubkeyBytesToUse)
	if err != nil {
		fmt.Println("Error encoding SLIP132 version bytes on public key")
		os.Exit(1)
	}

	derivationPathSpecter := strings.Replace(strings.ReplaceAll(derivationPath, "'", "h"), "m/", "", 1, )

	xfp, err := RootXPrivToFingerprint(masterXpriv)
	if err != nil {
		fmt.Println("Error calculating fingerpint", err)
		os.Exit(1)
	}

	//Write File
	WriteFiles("mnemonic.txt", folderName, mnemonic + "\n")
	WriteFiles("xpriv.txt", folderName, masterXpriv.String() + "\n")
	WriteFiles("xpub.txt", folderName, masterXpub.String() + "\n")
	WriteFiles("Zpub.txt", folderName, fmt.Sprintf("[%s/%s]%s\n", xfp, derivationPathSpecter, childZpub))

	//Write QR Codes
	_ = qrcode.WriteFile(mnemonic, qrcode.High, 512, folderName + "/mnemonic.png")
	_ = qrcode.WriteFile(masterXpriv.String(), qrcode.High, 512, folderName + "/xpriv.png")
	_ = qrcode.WriteFile(masterXpub.String(), qrcode.High, 512, folderName + "/xpub.png")
	_ = qrcode.WriteFile(childZpub.String(), qrcode.High, 512, folderName + "/Zpub.png")


	//Generate zip password
	ent, _ := bip39.NewEntropy(256)
	zipPass, _ := bip39.NewMnemonic(ent)
    zipPassNoSpaces := strings.Replace(zipPass, " ", "", -1)

	//Zip up the the generated files
	WriteFiles("ZipPassword.txt", folderName, "The zip arch password is the following:\n" + zipPassNoSpaces + "\n")
	ZipEncryptFiles([]string{"mnemonic.txt", "mnemonic.png", "xpriv.txt", "xpriv.png", "xpub.txt", "xpub.png", "Zpub.txt", "Zpub.png"}, folderName, zipPassNoSpaces)


	// Display mnemonic and keys
	if private {
		fmt.Println("Mnemonic: ", mnemonic)
		fmt.Println("Master X private key: ", masterXpriv)
	    fmt.Println("Entropy: ", entropy)
	}
	fmt.Println("Master X public key: ", masterXpub)
	fmt.Println("Master Z public key: ", childZpub)
	fmt.Println("Specter-Desktop Input Format:")
	fmt.Printf("  [%s/%s]%s\n", xfp, derivationPathSpecter, childZpub)
}
