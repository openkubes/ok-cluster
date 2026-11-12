package main

// Keep legacy up/create compatibility except when the user explicitly chooses
// the new operator mode. No legacy command may silently gain Make privileges.
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
	case arguments[offset] == "up" && hasExplicitUpMode(arguments[offset+1:]):
		return arguments // the new operator dispatcher validates exact allowed mode
	case arguments[offset] == "up" && (len(arguments) == offset+1 ||
		(len(arguments) == offset+2 && isHelpArgument(arguments[offset+1]))):
		return arguments // show the new up operator help, no execution
	case arguments[offset] == "up":
		command = []string{"cluster", "create"} // preserve existing runner semantics
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

// Any explicit --mode or --mode=... is reserved for the new operator router;
// malformed/unsupported modes fail closed there instead of falling back to Runner.
func hasExplicitUpMode(args []string) bool {
	for _, arg := range args {
		if arg == "--mode" || len(arg) > len("--mode=") && arg[:len("--mode=")] == "--mode=" {
			return true
		}
	}
	return false
}
