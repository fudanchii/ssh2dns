package log

import (
	"fmt"
	"os"
)

func Err(msg string) {
	fmt.Fprintf(os.Stderr, "[!] %s\n", msg)
}

func Fatal(msg string) {
	Err(msg)
	os.Exit(134)
}

func Info(msg string) {
	fmt.Printf("[-] %s\n", msg)
}

func Raw(label string, msg interface{}) {
	fmt.Fprintf(os.Stderr, "[*] <%s> %q\n", label, msg)
}
