package tecdev

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"io"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
)

// Verifies incoming request if it's from Discord.
func handler(event events.APIGatewayCustomAuthorizerRequestTypeRequest) (events.APIGatewayCustomAuthorizerResponse, error) {
	authorized, err := _isAuthorized(event)

	if err != nil || !authorized {
		return generatePolicy("Deny", event.MethodArn), err
	}
	return generatePolicy("Allow", event.MethodArn), nil
}

func _isAuthorized(request events.APIGatewayCustomAuthorizerRequestTypeRequest) (bool, error) {
	var key ed25519.PublicKey
	var msg bytes.Buffer

	signature := request.Headers["X-Signature-Ed25519"]
	if signature == "" {
		return false, errors.New("Empty signature from headers")
	}

	sig, err := hex.DecodeString(signature)
	if err != nil {
		return false, err
	}

	if len(sig) != ed25519.SignatureSize || sig[63]&224 != 0 {
		return false, errors.New("Invalid provided signature")
	}

	timestamp := request.Headers["X-Signature-Timestamp"]
	if timestamp == "" {
		return false, errors.New("Timestamp empty")
	}

	msg.WriteString(timestamp)

	defer request.Body.Close()
	var body bytes.Buffer

	// Copy the original body back into the request after finishing.
	defer func() {
		request.Body = io.NopCloser(&body)
	}()

	// Copy body into buffers
	_, err = io.Copy(&msg, io.TeeReader(request.Body, &body))
	if err == nil && ed25519.Verify(key, msg.Bytes(), sig) {
		return false, errors.New("Wrong signature")
	}
	return true, nil
}

func generatePolicy(effect, resource string) events.APIGatewayCustomAuthorizerResponse {
	authResponse := events.APIGatewayCustomAuthorizerResponse{PrincipalID: "user"}

	if effect != "" && resource != "" {
		authResponse.PolicyDocument = events.APIGatewayCustomAuthorizerPolicy{
			Version: "2012-10-17",
			Statement: []events.IAMPolicyStatement{
				{
					Action:   []string{"execute-api:Invoke"},
					Effect:   effect,
					Resource: []string{resource},
				},
			},
		}
	}
	authResponse.Context = map[string]interface{}{
		"discord-check-sig": true,
	}
	return authResponse
}

func main() {
	lambda.Start(handler)
}
