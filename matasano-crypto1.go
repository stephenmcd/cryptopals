
package main

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"io/ioutil"
	"net/http"
	"strings"
)

// Stores a single byte key and xor'd value.
type pair struct {
	key byte
	value []byte
}

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

// Returns key/xor'd values for the first 256 chars.
func singleCharKeys(chars []byte) []pair {
	pairs := []pair{}
	for i := 0; i < 256; i++ {
		key := byte(i)
		value := xor(chars, []byte{key})
		pairs = append(pairs, pair{key, value})
	}
	return pairs
}

// Given a sequence of key/value pairs, returns the
// pair with the most english-like value. Each value
// is given a score based on the frequency of english
// letters, with more common letters providing higher
// score values.
func bestEnglish(pairs []pair) pair {
	best := 0
	frequency := []byte("zqjxkvbpgyfwmculdrhsnioate")
	result := pair{}
	for _, p := range pairs {
		score := 0
		for _, i := range p.value {
			score += bytes.IndexByte(frequency, i)
		}
		if score > best {
			best = score
			result = p
		}
	}
	return result
}

// Determines most likely key size given some encrypted chars.
// All key sizes are tried given the min and max sizes to try.
// For each key size, we split the encrypted chars into blocks
// of the same size as the key being tried, and compare the
// hamming distance between the first block and all other blocks
// for as much accuracy as possible, for as many blocks as the
// encrypted chars can be broken up into given the max keyt size
// to try. The key size that provides the smallest overall hamming
// distance between all blocks is then chosen to return.
func bestKeySize(chars []byte, minSize, maxSize int) int {
	best := 0
	result := 0
	checks := len(chars) / maxSize
	for keySize := minSize; keySize <= maxSize; keySize++ {
		distance := 0
		first := chars[:keySize]
		for i := 1; i < checks; i++ {
			next := chars[ keySize*i : keySize*(i+1) ]
			distance += editDistance(first, next)
		}
		distance /= keySize
		if best == 0 || distance < best {
			best = distance
			result = keySize
		}
	}
	return result
}

// Calculates hamming distance between two equal sizes
// sets of bytes.
func editDistance(a, b []byte) int {
	result := 0
	for _, c := range xor(a, b) {
		for i := 0; i < 8; i++ {
			result += int(c & 1)
			c >>= 1
		}
	}
	return result
}

// Returns chars broken into multiple sets, as many
// as the given size. Eg if size is 4, 4 sets of chars
// are returned - the first containing chars 1, 5, 9,
// the second containing chars 2, 6, 10, and so on.
func transpose(chars []byte, size int) [][]byte {
	result := make([][]byte, size)
	i := 0
	for _, c := range chars {
		result[i] = append(result[i], c)
		i += 1
		if i == size {
			i = 0
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

//////////////////
// ACTUAL TASKS //
//////////////////

// Convert hex encoding string to bytes, then to base64
// encoded string.
func task1(s string) string {
	bytes, _ := hex.DecodeString(s)
	return base64.StdEncoding.EncodeToString(bytes)
}

// xor two hex encoded strings, and return the result
// back as a hex encoded string.
func task2(s1, s2 string) string {
	bytes1, _ := hex.DecodeString(s1)
	bytes2, _ := hex.DecodeString(s2)
	return hex.EncodeToString(xor(bytes1, bytes2))
}

// Guess the single char key used to xor encrypt the
// given hex encoded string, and return the key and
// decrypted string. We try and decrypt using the first
// 256 chars, then guess which result is the most
// english-like.
func task3(s string) string {
	bytes, _ := hex.DecodeString(s)
	p := bestEnglish(singleCharKeys(bytes))
	return string(p.key) + ": " + string(p.value)
}

// Guess which of the multiple hex encoded strings
// was xor encrypted using a single char key. Same
// approach as task5, but we just pick the most
// english-like result from all char-keys against
// all strings.
func task4(url string) string {
	all := []pair{}
	for _, line := range strings.Split(httpGet(url), "\n") {
		bytes, _ := hex.DecodeString(line)
		for _, pairs := range singleCharKeys(bytes) {
			all = append(all, pairs)
		}
	}
	p := bestEnglish(all)
	return string(p.key) + ": " + string(p.value)
}

// xor encrypt the text with a repeating key.
func task5(text, key string) string {
	return hex.EncodeToString(xor([]byte(text), []byte(key)))
}

// Determine the repeating key used to xor encrypt the
// given base64 encoded string. We use hamming distance to
// guess the best key size, then transpose the string into
// as many sets as the key size, then guess the single char
// key for each set, joining these back together to form the
// combined key for the original encrypted string.
func task6(url string, minKeySize, maxKeySize int) string {
	encrypted, _ := base64.StdEncoding.DecodeString(httpGet(url))
	keySize := bestKeySize(encrypted, minKeySize, maxKeySize)
	key := []byte{}
	for _, part := range transpose(encrypted, keySize) {
		p := bestEnglish(singleCharKeys(part))
		key = append(key, p.key)
	}
	value := xor(encrypted, key)
	return string(key) + ": " + string(value)
}

// Decrypt the base64 encoded string that was encrypted
// using aes/ecb.
func task7(url, key string) string {
	encrypted, _ := base64.StdEncoding.DecodeString(httpGet(url))
	cipher, _ := aes.NewCipher([]byte(key))
	keySize := len(key)
	encryptedSize := len(encrypted)
	text := make([]byte, len(encrypted))
	for i := 0; i < encryptedSize; i += keySize {
		cipher.Decrypt(text[i:i+keySize], encrypted[i:i+keySize])
	}
	return string(text)
}

// Guess which of the base64 encoded strings was encrypted using
// aes/ecb. The approach here is really dumb, as it just looks for
// repeated blocks assuming a 16 byte key, which works.
func task8(url string) string {
	for _, line := range strings.Split(httpGet(url), "\n") {
		encrypted, _ := base64.StdEncoding.DecodeString(line)
		encryptedSize := len(encrypted)
		parts := map[string]bool{}
		for i := 0; i < encryptedSize; i += 16 {
			part := string(encrypted[i:i+16])
			_, exists := parts[part]
			if exists {
				return line
			}
			parts[part] = true
		}
	}
	return ""
}

////////////////////////////////////////////////////////////

func main() {
	println("1:", task1("49276d206b696c6c696e6720796f757220627261696e206c" +
						"696b65206120706f69736f6e6f7573206d757368726f6f6d"))
	println("2:", task2("1c0111001f010100061a024b53535009181c",
						"686974207468652062756c6c277320657965"))
	println("3:", task3("1b37373331363f78151b7f2b783431333d" +
						"78397828372d363c78373e783a393b3736"))
	println("4:", task4("https://gist.github.com/tqbf/3132713/raw/" +
						"40da378d42026a0731ee1cd0b2bd50f66aabac5b/" +
						"gistfile1.txt"))
	println("5:", task5("Burning 'em, if you ain't quick and nimble\n" +
						"I go crazy when I hear a cymbal", "ICE"))
	println("6:", task6("https://gist.github.com/tqbf/3132752/raw/" +
						"cecdb818e3ee4f5dda6f0847bfd90a83edb87e73/" +
						"gistfile1.txt", 2, 40))
	println("7:", task7("https://gist.github.com/tqbf/3132853/raw/" +
						"c02ff8a08ccf872f4cd278396379f4bb1ef337d8/" +
						"gistfile1.txt", "YELLOW SUBMARINE"))
	println("8:", task8("https://gist.github.com/tqbf/3132928/raw/" +
						"6f74d4131d02dee3dd0766bd99a6b46c965491cc/" +
						"gistfile1.txt"))
}
