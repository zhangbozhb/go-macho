package macho

import "strings"

func (s Symbol) FunctionName() string {
	if strings.HasPrefix(s.Name, "_") {
		return s.Name[1:]
	}
	return s.Name
}
