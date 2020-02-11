package mlsag

import (
	"crypto/sha256"
	"fmt"

	"github.com/incognitochain/incognito-chain/common"

	C25519 "github.com/incognitochain/incognito-chain/privacy/curve25519"
)

func GenerateFakePublicKey() C25519.Key {
	privateKey := C25519.RandomScalar()
	publicKey := C25519.ScalarmultBase(privateKey)
	return publicKey.ToBytes()
}

func digestMessages(messages []string) (result [][sha256.Size]byte) {
	for i := 0; i < len(messages); i += 1 {
		digest := sha256.Sum256([]byte(messages[i]))
		result = append(result, digest)
	}
	return
}

func hashToPoint(b []byte) C25519.Key {
	keyHash := C25519.Key(C25519.Keccak256(b))
	keyPoint := keyHash.HashToPoint()
	return *keyPoint
}

func hashToNum(b []byte) [sha256.Size]byte {
	return sha256.Sum256(b)
}

func calculatePublicKey(privateKey C25519.Key) [C25519.KeyLength]byte {
	publicKey := *C25519.ScalarmultBase(&privateKey)
	return publicKey.ToBytes()
}

func calculateKeyImages(privateKey []C25519.Key) (result []C25519.Key) {
	for i := 0; i < len(privateKey); i += 1 {
		publicKey := calculatePublicKey(privateKey[i])
		hashPoint := hashToPoint(publicKey[:])
		image := *C25519.ScalarMultKey(&privateKey[i], &hashPoint)
		result = append(result, image)
	}
	return
}

func createRingKeys(privateKeys []C25519.Key, numFake int) (Ks [][]C25519.Key, Pi []int) {
	for i := 0; i < len(privateKeys); i += 1 {
		// Generate fake keys where real key is at 0-th index
		var curGroup []C25519.Key
		curGroup = append(curGroup, calculatePublicKey(privateKeys[i]))
		for j := 0; j < numFake-1; j += 1 {
			fakePub := GenerateFakePublicKey()
			curGroup = append(curGroup, fakePub)
		}

		// Swap the real key to random index within the key group
		r := common.RandInt() % numFake
		Pi = append(Pi, r)
		curGroup[0], curGroup[r] = curGroup[r], curGroup[0]

		Ks = append(Ks, curGroup)
	}
	return
}

func debugRing(privateKeys []C25519.Key, Ks [][]C25519.Key, Pi []int) {
	fmt.Println("================")
	fmt.Println("Here comes Private Keys")
	fmt.Println(privateKeys)

	fmt.Println("================")
	fmt.Println("Here comes Public Keys")
	fmt.Println(calculatePublicKey(privateKeys[0]))

	fmt.Println("================")
	fmt.Println("Here comes Ring Keys")
	fmt.Println(Ks)

	fmt.Println("================")
	for i := 0; i < len(privateKeys); i += 1 {
		fmt.Printf("Checking Ring[%d]\n", i)
		fmt.Println(Ks[i][Pi[i]].ToBytes())
		fmt.Println(calculatePublicKey(privateKeys[i]))
		fmt.Println(calculatePublicKey(privateKeys[i]) == Ks[i][Pi[i]].ToBytes())
	}

	fmt.Println("================")
	fmt.Println("Here comes Pi")
	fmt.Println(Pi)
}

func createRandomChallenges() {
	
}

// SignCore will use MLSAG algorithm to sign on message.
func SignCore(privateKeys []C25519.Key, message string, numFake int) (result []byte) {
	Ks, Pi := createRingKeys(privateKeys, numFake)

	// Steps in paper
	keyImages := calculateKeyImages(privateKeys) // 1st step
	alpha, Rs, := createRandomChallenges()		 // 2nd step

	return
}
