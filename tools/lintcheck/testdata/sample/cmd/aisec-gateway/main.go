// Команда aisec-gateway образца: os/exec в серверном компоненте запрещён.
package main

import "os/exec" // want:depguard

func main() { _ = exec.Command }
