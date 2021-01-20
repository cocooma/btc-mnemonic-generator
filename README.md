# btc-mnemonic-generator

# THIS REPOSITORY COMES WITH ZERO GUARANTEES! USE AT YOUR OWN RISK!

#### Always perform sensitive operations on an airgapped computer and securely wipe it after.

## Quickstart:


CLI Options:

```bigquery
# go run *.go -h
    -dices string
        Dices
    -firstWords string
        Insert the first 23 Words. It'll generate the 24th
    -folder string
        Folder name default: 'generated_keys_qr_codes' (default "generated_keys_qr_codes")
    -mnemonic string
        Mnemonic words
    -password string
        Password
    -private
        Display private data

```

Basic:
```
Mnemonic and dices are not set auto generating entropy!
Master X public key:  xpub661MyMwAqRbcGpu1HGCMwrsqf38qwp9wkbu1GkcohNcsVF7Hk17GD4eVf6n6Bu54A4P8G3hpyN2ZH1Wo2QmVzekmijf8QUeuAFm4Zkm8j2d
Master Z public key:  Zpub74rMnmL6ULUF95W2XjLwFch9MVxqFfqiPUfyAsBJUVQQJWo66WANMak87GStMv6i7TiEfWcssxDfcwJcuLdV1UgwToQLKiRHVmDSpChjEuA
Specter-Desktop Input Format:
[fc0faa24/48h/0h/0h/2h]Zpub74rMnmL6ULUF95W2XjLwFch9MVxqFfqiPUfyAsBJUVQQJWo66WANMak87GStMv6i7TiEfWcssxDfcwJcuLdV1UgwToQLKiRHVmDSpChjEuA
```
The tools is based on: <br>
	https://github.com/tyler-smith/go-bip39 <br>
	https://github.com/yeka/zip <br>
	https://github.com/mflaxman/human-rng-golan

