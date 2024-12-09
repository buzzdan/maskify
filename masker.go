package maskify

import "strings"

const (
	longTokenLength   = 12
	shortTokenLength  = 6
	longRevealLength  = 4
	shortRevealLength = 2
)

// MaskedField is holds a field to be masked
type MaskedField struct {
	Name string
	mask masker
}

// MaskValue masks the value of the field
func (f MaskedField) MaskValue(value string) string {
	return f.mask.MaskValue(value)
}

// MaskedFields is a list of MaskedField
type MaskedFields []MaskedField

// Masker is the interface for masking values
type masker interface {
	MaskValue(value string) string
}

// TokenMask masks token values
// Tokens are usually long and should reveal only the last few characters (depending on the length)
type TokenMask struct{}

func (t TokenMask) MaskValue(value string) string {
	strLen := len(value)
	var starsCount int
	switch {
	case strLen >= longTokenLength:
		starsCount = strLen - longRevealLength
	case strLen >= shortTokenLength:
		starsCount = strLen - shortRevealLength
	default:
		starsCount = strLen
	}
	return strings.Repeat("*", starsCount) + value[starsCount:]
}

// PasswordMask masks password values
// Passwords should be completely masked
type PasswordMask struct{}

// MaskValue masks the password value
func (p PasswordMask) MaskValue(value string) string {
	return strings.Repeat("*", len(value))
}

// PasswordMaskedField creates a MaskedField for password values
func PasswordMaskedField(fieldName string) MaskedField {
	return MaskedField{Name: fieldName, mask: PasswordMask{}}
}

// TokenMaskedField creates a MaskedField for token values
func TokenMaskedField(fieldName string) MaskedField {
	return MaskedField{Name: fieldName, mask: TokenMask{}}
}

// Mask masks the fields in the object
func (f MaskedField) Mask(obj map[string]interface{}) {
	value, ok := obj[f.Name].(string)
	if ok && !IsEnvVar(value) {
		obj[f.Name] = f.mask.MaskValue(value)
	}
}

// Mask masks the fields in the object
func (m MaskedFields) Mask(obj interface{}) {
	switch obj := obj.(type) {
	case map[string]interface{}:

		// see if masked field keys exists in the obj map top level
		for _, field := range m {
			field.Mask(obj)
		}

		// recurse into nested maps
		for _, v := range obj {
			m.Mask(v)
		}

	case []interface{}:
		for _, v := range obj {
			m.Mask(v)
		}
	case string:
		for _, field := range m {
			obj = field.MaskValue(obj)
		}
	}
}

// MaskValue masks the value of the field
func (m MaskedFields) MaskValue(fieldName, value string) string {
	for _, field := range m {
		if fieldName == field.Name {
			return field.MaskValue(value)
		}
	}
	return value
}

// IsEnvVar checks if the value is an environment variable. e.g. ${VAR}
func IsEnvVar(value string) bool {
	return strings.HasPrefix(value, "${") && strings.HasSuffix(value, "}")
}
