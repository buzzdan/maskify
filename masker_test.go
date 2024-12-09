package maskify

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPasswordMaskedField(t *testing.T) {
	field := PasswordMaskedField("password")
	expected := MaskedField{Name: "password", mask: PasswordMask{}}
	assert.Equal(t, expected, field, "PasswordMaskedField failed")
}

func TestTokenMaskedField(t *testing.T) {
	field := TokenMaskedField("token")
	expected := MaskedField{Name: "token", mask: TokenMask{}}
	assert.Equal(t, expected, field, "TokenMaskedField failed")
}

func TestMaskFields(t *testing.T) {
	obj := map[string]interface{}{
		"my-password": "secretpassword",
		"my-token":    "1234567890abcdef",
	}
	expected := map[string]interface{}{
		"my-password": "**************",
		"my-token":    "************cdef",
	}

	mask := MaskedFields{
		PasswordMaskedField("my-password"),
		TokenMaskedField("my-token"),
	}

	mask.Mask(obj)

	assert.Equal(t, expected, obj, "MaskFields failed")
}

func TestMaskFieldsNested(t *testing.T) {
	obj := map[string]interface{}{
		"my-password": "secretpassword",
		"my-token":    "1234567890abcdef",
		"nested": map[string]interface{}{
			"my-password": "nestedpassword",
			"my-token":    "nestedtoken",
		},
	}

	mask := MaskedFields{
		PasswordMaskedField("my-password"),
		TokenMaskedField("my-token"),
	}

	mask.Mask(obj)

	assert.Equal(t, "**************", obj["my-password"], "MaskFields failed on my-password")
	assert.Equal(t, "************cdef", obj["my-token"], "MaskFields failed on my-token")

	nested, ok := obj["nested"].(map[string]interface{})
	require.True(t, ok, "nested field is not a map")
	assert.Equal(t, "**************", nested["my-password"], "MaskFields failed on nested my-password")
	assert.Equal(t, "*********en", nested["my-token"], "MaskFields failed on nested my-token")
}

func TestMaskFieldsDeepNested(t *testing.T) {
	obj := map[string]interface{}{
		"sinks": map[string]interface{}{
			"sink-s3": map[string]interface{}{
				"auth": map[string]interface{}{
					"access_key_id":     "secretpassword",
					"secret_access_key": "1234567890abcdef",
				},
			},
		},
	}

	mask := MaskedFields{
		PasswordMaskedField("access_key_id"),
		TokenMaskedField("secret_access_key"),
	}

	mask.Mask(obj)
	auth, ok := obj["sinks"].(map[string]interface{})["sink-s3"].(map[string]interface{})["auth"].(map[string]interface{})
	require.True(t, ok, "auth field is not a map")
	assert.Equal(t, "**************", auth["access_key_id"], "MaskFields failed on access_key_id")
	assert.Equal(t, "************cdef", auth["secret_access_key"], "MaskFields failed on secret_access_key")
}

func TestMaskFieldsArray(t *testing.T) {
	obj := []interface{}{
		map[string]interface{}{
			"my-password": "secretpassword",
			"my-token":    "1234567890abcdef",
		},
		map[string]interface{}{
			"my-password": "anotherpassword",
			"my-token":    "another1234567890abcdef",
		},
	}

	mask := MaskedFields{
		PasswordMaskedField("my-password"),
		TokenMaskedField("my-token"),
	}

	mask.Mask(obj)

	obj1, ok := obj[0].(map[string]interface{})
	require.True(t, ok, "first object is not a map")

	obj2, ok := obj[1].(map[string]interface{})
	require.True(t, ok, "second object is not a map")

	assert.Equal(t, "**************", obj1["my-password"], "MaskFields failed on my-password in the first object")
	assert.Equal(t, "************cdef", obj1["my-token"], "MaskFields failed on my-token in the first object")

	assert.Equal(t, "***************", obj2["my-password"], "MaskFields failed on my-password in the second object")
	assert.Equal(t, "*******************cdef", obj2["my-token"], "MaskFields failed on my-token in the second object")
}

func TestTokenMask_MaskValue(t *testing.T) {
	tests := []struct {
		value    string
		expected string
	}{
		{value: "1234567890abcdef", expected: "************cdef"},
		{value: "1234567890", expected: "********90"},
		{value: "12345678", expected: "******78"},
		{value: "1234567", expected: "*****67"},
		{value: "123456", expected: "****56"},
		{value: "12345", expected: "*****"},
		{value: "1234", expected: "****"},
		{value: "123", expected: "***"},
		{value: "12", expected: "**"},
		{value: "1", expected: "*"},
		{value: "", expected: ""},
	}

	mask := TokenMask{}
	for _, test := range tests {
		actual := mask.MaskValue(test.value)
		assert.Equal(t, test.expected, actual, fmt.Sprintf("Token masking failed for value: %s, length: %d", test.value, len(test.value)))
	}
}

func TestPasswordMask_MaskValue(t *testing.T) {
	tests := []struct {
		value    string
		expected string
	}{
		{value: "secretpassword", expected: "**************"},
		{value: "password", expected: "********"},
		{value: "pass", expected: "****"},
		{value: "pa", expected: "**"},
		{value: "p", expected: "*"},
		{value: "", expected: ""},
	}

	mask := PasswordMask{}
	for _, test := range tests {
		actual := mask.MaskValue(test.value)
		assert.Equal(t, test.expected, actual, "Password masking failed for value: "+test.value)
	}
}

func TestMaskFieldsEnvVar(t *testing.T) {
	obj := map[string]interface{}{
		"my-password": "secretpassword",
		"my-token":    "${AWS_ACCESS_KEY_ID}",
	}
	expected := map[string]interface{}{
		"my-password": "**************",
		"my-token":    "${AWS_ACCESS_KEY_ID}",
	}
	mask := MaskedFields{
		PasswordMaskedField("my-password"),
		TokenMaskedField("my-token"),
	}
	mask.Mask(obj)
	assert.Equal(t, expected, obj, "MaskFields failed")
}
