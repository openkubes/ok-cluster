package main

// Command aliases only rewrite the command prefix. Flags, input identity,
// execution mode and approval/evidence requirements are never inferred.
func canonicalProductArguments(arguments []string) []string {
	offset := 0
	if len(arguments) > 0 && arguments[0] == "help" {
		offset = 1
	}
	if len(arguments) <= offset {
		return arguments
	}
	var command []string
	consumed := 1
	switch {
	case arguments[offset] == "up":
		command = []string{"cluster", "create"}
	case len(arguments) > offset+1 && arguments[offset] == "destroy" && arguments[offset+1] == "cluster":
		command = []string{"cluster", "destroy"}
		consumed = 2
	default:
		return arguments
	}
	normalized := append([]string{}, arguments[:offset]...)
	normalized = append(normalized, command...)
	return append(normalized, arguments[offset+consumed:]...)
}
