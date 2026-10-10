// Команда aisec-cli образца: не серверный компонент, os/exec разрешён.
package main

import "os/exec" // clean:depguard

func main() { _ = exec.Command }
