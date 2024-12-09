# maskify

Maskify is a robust Go library designed to enhance data security by automatically masking sensitive fields in a map. It supports two types of masking:

Token Masking: Reveals a few characters of the token while masking the rest.

Password Masking: Completely masks the password to ensure maximum security.

With Maskify, you can easily protect sensitive information in your applications, making it an essential tool for any Go developer concerned with data privacy and security.

## Installation

```
go get github.com/buzzdan/maskify
```

## Usage

```go
import (
    "fmt"
    "github.com/buzzdan/maskify"
)

func main() {
    data := map[string]interface{}{
        "name": "John Doe",
        "email": "john@doe.com",
        "password": "password123",
        "aws-settings": map[string]interface{}{
            "access_key_id": "AKIA123456789",
            "secret_access_key": "1234567890ABCDERGHIJK",
            "default_token": "123456",
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
```
result:
```json
{
  "aws-settings": {
    "access_key_id": "*********6789",
    "default_token": "****56",
    "secret_access_key": "*****************HIJK"
  },
  "email": "john@doe.com",
  "name": "John Doe",
  "password": "***********"
}
```