package main

import (
	"encoding/json"
	"fmt"

	"github.com/buzzdan/maskify"
)

func main() {
	data := map[string]interface{}{
		"name":     "John Doe",
		"email":    "john@doe.com",
		"password": "password123",
		"aws-settings": map[string]interface{}{
			"access_key_id":     "AKIA123456789",
			"secret_access_key": "1234567890ABCDERGHIJK",
			"default_token":     "123456",
		},
	}

	fieldsToMask := &maskify.MaskedFields{
		maskify.PasswordMaskedField("password"),
		maskify.TokenMaskedField("access_key_id"),
		maskify.TokenMaskedField("secret_access_key"),
		maskify.TokenMaskedField("default_token"),
	}

	fieldsToMask.Mask(data)

	// convert to json or yaml
	bytes, err := json.Marshal(data)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(bytes))
}
