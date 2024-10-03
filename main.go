package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum/common"
	circuits "github.com/iden3/go-circuits/v2"
	auth "github.com/iden3/go-iden3-auth/v2"
	"github.com/iden3/go-iden3-auth/v2/pubsignals"
	"github.com/iden3/go-iden3-auth/v2/state"
	"github.com/iden3/iden3comm/v2/protocol"

	//shell "github.com/ipfs/go-ipfs-api"
	"github.com/skip2/go-qrcode"
    //"github.com/joho/godotenv"
)

const VerificationKeyPath = "verification_key.json"

type KeyLoader struct {
    Dir string
}

// Load keys from embedded FS
func (m KeyLoader) Load(id circuits.CircuitID) ([]byte, error) {
    return os.ReadFile(fmt.Sprintf("%s/%v/%s", m.Dir, id, VerificationKeyPath))
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Verifier is running!"))
}

func main() {
    

    http.HandleFunc("/api/sign-in", GetAuthRequest)
    http.HandleFunc("/api/callback", Callback)
	http.HandleFunc("/", homeHandler)
    log.Println("Starting server at port 8080")
    if err := http.ListenAndServe(":8080", nil); err != nil {
        log.Fatal(err)
    }
}

// Create a map to store the auth requests and their session IDs
var requestMap = make(map[string]interface{})


func GetAuthRequest(w http.ResponseWriter, r *http.Request) {

	// Audience is verifier id
	rURL := "https://5cbb-91-244-54-213.ngrok-free.app"
	sessionID := 1
	CallbackURL := "/api/callback"
	Audience := "did:polygonid:polygon:amoy:2qQ68JkRcf3xrHPQPWZei3YeVzHPP58wYNxx2mEouR"
	
	uri := fmt.Sprintf("%s%s?sessionId=%s", rURL, CallbackURL, strconv.Itoa(sessionID))
	
	// Generate request for basic authentication
	var request protocol.AuthorizationRequestMessage = auth.CreateAuthorizationRequest("test flow", Audience, uri)
	
	
	// Add request for a specific proof
	var mtpProofRequest protocol.ZeroKnowledgeProofRequest
	mtpProofRequest.ID = 1
	mtpProofRequest.CircuitID = string(circuits.AtomicQuerySigV2CircuitID)
	mtpProofRequest.Query = map[string]interface{}{
		"allowedIssuers": []string{"*"},
		"credentialSubject": map[string]interface{}{
			"birthday": map[string]interface{}{
				"$lt": 20000101,
			},
		},
		"context": "ipfs://QmcNPpnDNtPjSCcAJH9UFnBm8oSx2jN27LnoywEmXsuVkZ",
		"type":    "KYCAgeCredential",
	}
	request.Body.Scope = append(request.Body.Scope, mtpProofRequest)
	
	// Store auth request in map associated with session ID
	requestMap[strconv.Itoa(sessionID)] = request
	
	// print request
	fmt.Println(request)
	
	msgBytes, _ := json.Marshal(request)

	err := qrcode.WriteFile(string(msgBytes), qrcode.Medium, 256, "qr.png")
	if err != nil {
		log.Printf("Eror...Don't creare QR Code!")
	}
	
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(msgBytes)
		return
	}

	// Callback works with sign-in callbacks
func Callback(w http.ResponseWriter, r *http.Request) {
    fmt.Println("callback")
    // Get session ID from request
    sessionID := r.URL.Query().Get("sessionId")

    // get JWZ token params from the post request
    tokenBytes, err := io.ReadAll(r.Body)
    if err != nil {
        log.Println(err)
        return
    }

    //keyApi := os.Getenv("KEY_API_INFURA")

    // Add Polygon AMOY RPC node endpoint - needed to read on-chain state
    ethURL := "https://polygon-amoy.infura.io/v3/a1e81bcaca104bf9ad54f4e88b4c3554"

    fmt.Println(ethURL)

    // Add IPFS url - needed to load schemas from IPFS
    //ipfsURL := "ipfs://QmcNPpnDNtPjSCcAJH9UFnBm8oSx2jN27LnoywEmXsuVkZ"

    //ipfsURL := "https://ipfs.io"


    // Add identity state contract address
    contractAddress := "0x1a4cC30f2aA0377b0c3bc9848766D90cb4404124"

    resolverPrefix := "polygon:amoy"

    // Locate the directory that contains circuit's verification keys
    keyDIR := "../keys"

    // fetch authRequest from sessionID
    authRequest := requestMap[sessionID]

    // print authRequest
    log.Println(authRequest)

    // load the verifcation key
    var verificationKeyLoader = &KeyLoader{Dir: keyDIR}
    resolver := state.ETHResolver{
        RPCUrl:          ethURL,
        ContractAddress: common.HexToAddress(contractAddress),
    }

    resolvers := map[string]pubsignals.StateResolver{
        resolverPrefix: resolver,
    }

    // EXECUTE VERIFICATION
    verifier, err := auth.NewVerifier(verificationKeyLoader, resolvers, auth.WithIPFSGateway("https://ipfs.io"))
    if err != nil {
        log.Println(err.Error())
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }    
    authResponse, err := verifier.FullVerify(
        r.Context(),
        string(tokenBytes),
        authRequest.(protocol.AuthorizationRequestMessage),
        pubsignals.WithAcceptedStateTransitionDelay(time.Minute*5))
    if err != nil {
        log.Println(err.Error())
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    //marshal auth resp
    messageBytes, err := json.Marshal(authResponse)
    if err != nil {
        log.Println(err.Error())
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    w.WriteHeader(http.StatusOK)
    w.Header().Set("Content-Type", "application/json")
    w.Write(messageBytes)
    log.Println("verification passed")
}