package main

import (
	"fmt"
	"crypto/aes"
	"net/http"
	"io/ioutil"
	"strings"
	"encoding/base64"
	"math/rand"
	"time"
)

// Sequentially xor chars against each char in the key,
// which is assumed to be no larger in length than the chars
// given. The key is repeated if its length is reached.
func xor(chars, key []byte) []byte {
	j := 0
	keySize := len(key)
	result := []byte{}
	for i := range chars {
		result = append(result, chars[i] ^ key[j])
		j += 1
		if j == keySize {
			j = 0
		}
	}
	return result
}

// Helper for grabbing the text of a raw gist on GitHub.
func httpGet(url string) string {
	response, _ := http.Get(url)
	body, _ := ioutil.ReadAll(response.Body)
	return strings.TrimSpace(string(body))
}

func padPKCS7(chars []byte, size int) []byte {
	charSize := len(chars)
	minus := charSize
	if size < charSize {
		minus %= size
	}
	padSize := size - minus
	padByte := byte(padSize)
	for i := 0; i < padSize; i++ {
		chars = append(chars, padByte)
	}
	return chars
}

func encryptECB(input, key []byte) []byte {
	keySize := len(key)
	inputSize := len(input)
	cipher, _ := aes.NewCipher(key)
	output := make([]byte, inputSize)
	for i := 0; i < inputSize; i += keySize {
		cipher.Encrypt(output[i:i+keySize], input[i:i+keySize])
	}
	return output
}

func decryptECB(input, key []byte) []byte {
	keySize := len(key)
	inputSize := len(input)
	cipher, _ := aes.NewCipher(key)
	output := make([]byte, inputSize)
	for i := 0; i < inputSize; i += keySize {
		cipher.Decrypt(output[i:i+keySize], input[i:i+keySize])
	}
	return output
}

func encryptCBC(input, key, iv []byte) []byte {
	keySize := len(key)
	inputSize := len(input)
	cipher, _ := aes.NewCipher(key)
	output := make([]byte, inputSize)
	for i := 0; i < inputSize; i += keySize {
		cipher.Encrypt(output[i:i+keySize], xor(input[i:i+keySize], iv))
		iv = output[i:i+keySize]
	}
	return output
}

func decryptCBC(input, key, iv []byte) []byte {
	keySize := len(key)
	inputSize := len(input)
	cipher, _ := aes.NewCipher(key)
	temp := make([]byte, inputSize)
	output := []byte{}
	for i := 0; i < inputSize; i += keySize {
		cipher.Decrypt(temp[i:i+keySize], input[i:])
		output = append(output, xor(temp[i:i+keySize], iv)...)
		iv = input[i:i+keySize]
	}
	return output
}

func task9(s string, size int) string {
	return fmt.Sprintf("%q", padPKCS7([]byte(s), size))
}

func task10(url, key string, iv []byte) string {
	encoded := strings.Replace(httpGet(url), "\n", "", -1)
	encrypted, _ := base64.StdEncoding.DecodeString(encoded)
	decrypted := decryptCBC(encrypted, []byte(key), iv)
	check := base64.StdEncoding.EncodeToString(encryptCBC(decrypted, []byte(key), iv))
	if check != encoded {
		return check
	}
	return string(decrypted)
}

func oracle(input []byte) []byte {
	input = padPKCS7(input, 16)
	key := []byte{}
	rand.Seed(time.Now().UnixNano())
	for i := 0; i < 16; i++ {
		key = append(key, byte(rand.Intn(256)))
	}
	return encryptECB(input, key)
}

func task11(input string) string {
	paddedInput :=

	[]byte(input)
	return base64.StdEncoding.EncodeToString(oracle())
}

func main() {
	// println("09: ", task9("YELLOW SUBMARINE", 20))
	// println("10: ", task10("https://gist.github.com/tqbf/3132976/raw/" +
	//                        "f0802a5bc9ffa2a69cd92c981438399d4ce1b8e4/" +
	//                        "gistfile1.txt", "YELLOW SUBMARINE",
	//                        make([]byte, 16)))
	println("11: ", task11("hello"))
}
