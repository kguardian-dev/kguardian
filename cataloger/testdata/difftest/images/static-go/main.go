// The static-go fixture's program, built by its Dockerfile (testdata is
// outside the cataloger module's packages).
package main

import (
	"fmt"

	"golang.org/x/text/language"
)

func main() { fmt.Println(language.English) }
