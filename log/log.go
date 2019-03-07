package log

import (
	"fmt"
	"os"
)

func Err(msg string) {
	fmt.Fprintf(os.Stderr, "[!] %s\n", msg)
}
func Info(msg string) {
	fmt.Printf("[-] %s\n", msg)
}

func Raw(label string, msg interface{}) {
	fmt.Fprintf(os.Stderr, "[*] <%s> %q\n", label, msg)
}
