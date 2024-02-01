package main

import (
	"crypto/sha1"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"strconv"
)

func isIPAddress(s string) bool {
    parts := strings.Split(s, ".")
    if len(parts) != 4 {
        return false
    }
    for _, part := range parts {
        num, err := strconv.Atoi(part)
        if err != nil || num < 0 || num > 255 {
            return false
        }
    }
    return true
}

func containsLetters(s string) bool {
	for _, r := range s {
		if ('a' <= r && r <= 'z') || ('A' <= r && r <= 'Z') {
			return true
		}
	}
	return false
}

func getIPAddress() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			return "", err
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if ok && !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
				return ipNet.IP.String(), nil
			}
		}
	}

	return "", fmt.Errorf("Error: IP not found")
}

func calculateSHA1(input string) string {
	hash := sha1.New()
	hash.Write([]byte(input))
	return fmt.Sprintf("%x", hash.Sum(nil))
}

func createFormData(ip, sha1Hash, domain string) url.Values {
	data := url.Values{}
	data.Set("CSRF1079979480303398", "network100222513")
	data.Set("CSRF1029583167602236", "phishing108631868")
	data.Set("lol-stop-reverse-engineering-my-source-and-buy-an-api-key46204", ip)
	data.Set("CSRF1011566160955414", "CSRF100241554")
	data.Set("CSRF1006529950390228", "malware109473266")
	data.Set("CSRF1035726183550395", "firewall105356042")
	data.Set("CSRF1044416736350566", "subnet100668039")
	data.Set("lol-stop-reverse-engineering-my-source-and-buy-an-api-key38185", ip)
	data.Set("CSRF1013981810156556", "bot110684546")
	data.Set("CSRF1036262826081024", "security109518995")
	data.Set("lol-stop-reverse-engineering-my-source-and-buy-an-api-key49363", ip)
	data.Set("CSRF1038982738414625", "firewall107047201")
	data.Set("CSRF1012341660705000", "intrusion107709157")
	data.Set("CSRF1053516321016340", "burglar104230239")
	data.Set("CSRF1109975951516376", "CSRF100271026")
	data.Set("CSRF1085601106611743", "cyberspace102093975")
	data.Set("lol-stop-reverse-engineering-my-source-and-buy-an-api-key55411", ip)
	data.Set("CSRF1004083549254001", "CSRF102912265")
	data.Set("CSRF1057674747818471", "burglar109540372")
	data.Set("CSRF1103987355931856", "malware110575873")
	data.Set("CSRF1009263175628124", "hacking110589097")
	data.Set("CSRF1100068933681356", "honeypot103704874")
	data.Set("lol-stop-reverse-engineering-my-source-and-buy-an-api-key52614", ip)
	data.Set("CSRF1014814466707184", "intrusion105031644")
	data.Set("CSRF1064652583997549", "subnet105807340")
	data.Set("CSRF1020379274940689", "bot110906622")
	data.Set("CSRF1080693901848420", "cyberwar110804733")
	data.Set("lol-stop-reverse-engineering-my-source-and-buy-an-api-key13379", ip)
	data.Set("CSRF1104000408654857", "spy104068797")
	data.Set("CSRF1067653399989757", "subnet106709650")
	data.Set("CSRF1066015974439422", "subnet_ip110024912")
	data.Set("lol-stop-reverse-engineering-my-source-and-buy-an-api-key90895", ip)
	data.Set("CSRF1085860113788394", "subnet103141462")
	data.Set("lol-stop-reverse-engineering-my-source-and-buy-an-api-key69970", ip)
	data.Set("CSRF1004779928040548", "tenant104236720")
	data.Set("lol-stop-reverse-engineering-my-source-and-buy-an-api-key92604", ip)
	data.Set("CSRF1071940523507460", "counterfeiter107985863")
	data.Set("CSRF1032053364145764", "CSRF101868681")
	data.Set("CSRF1069785491669216", "drudge110656682")
	data.Set("CSRF1047608050923298", "cracker105806575")
	data.Set("CSRF1014895113379121", "programmer100585258")
	data.Set("CSRF1085033674236718", "Trojan104939427")
	data.Set("CSRF1037210598786089", "cyberspace105422840")
	data.Set("CSRF1021719844439195", "techie110756427")
	data.Set("CSRF1082015735858918", "subnet110913638")
	data.Set("CSRF1048628681707732", "tenant104852707")
	data.Set("CSRF1048713127708762", "burglar109361826")
	data.Set("lol-stop-reverse-engineering-my-source-and-buy-an-api-key32777", ip)
	data.Set("CSRF1059493558983334", "cyberspace100297303")
	data.Set("CSRF1044696079734830", "cybercrime108357927")
	data.Set("CSRF1016595905994364", "bogey102106430")
	data.Set("lol-stop-reverse-engineering-my-source-and-buy-an-api-key55622", ip)
	data.Set("CSRF1072700114830679", "firewall105872367")
	data.Set("lol-stop-reverse-engineering-my-source-and-buy-an-api-key87814", ip)
	data.Set("CSRF1063610394222642", "bogey106057518")
	data.Set("CSRF1104950425798693", "thief102643393")
	data.Set("CSRF1075463026525919", "malware103715154")
	data.Set("CSRF1020144742256741", "tenant102367155")
	data.Set("CSRF1101536167007890", "drudge101537078")
	data.Set("CSRF1088342748312662", "CSRF104054073")
	data.Set("lol-stop-reverse-engineering-my-source-and-buy-an-api-key87213", ip)
	data.Set("CSRF1058785720263885", "scammer100142892")
	data.Set("CSRF1008654000842802", "prankster107360847")
	data.Set("CSRF1086796776227431", "prankster104763350")
	data.Set("lol-stop-reverse-engineering-my-source-and-buy-an-api-key36123", ip)
	data.Set("CSRF1049038741376620", "addict109113416")
	data.Set("CSRF1078416421209966", "bot106011089")
	data.Set("CSRF1106496136909290", "car103878210")
	data.Set("CSRF1034064043991869", "CSRF102103028")
	data.Set("CSRF1004078614367613", "cyber110965274")
	data.Set("CSRF1067768081222665", "firewall105943805")
	data.Set("CSRF1096716844961506", "car107267553")
	data.Set("lol-stop-reverse-engineering-my-source-and-buy-an-api-key45213", ip)
	data.Set("CSRF1088671413026451", "bogey110239612")
	data.Set("CSRF1077064633775349", "honeypot102278625")
	data.Set("CSRF1051159640091732", "mask108460994")
	data.Set("CSRF1083896545107217", "espionage106205964")
	data.Set("CSRF1080353652408776", "CSRF107864470")
	data.Set("CSRF1042949396372479", "identitytheft102484037")
	data.Set("CSRF1083980158176928", "pirate103692558")
	data.Set("CSRF1021445569997524", "computer106850755")
	data.Set("CSRF1061681046811092", "addict109790120")
	data.Set("CSRF984341238797932", "espionage104141104")
	data.Set("node", "207.85.125.52")
	data.Set("is_admin", "false")
	data.Set("jn", "JS aan, T aangeroepen, CSRF aangepast")
	data.Set("domain", domain)
	data.Set("lol-stop-reverse-engineering-my-source-and-buy-an-api-key", sha1Hash)
	data.Set("scan_subdomains", "")

	return data
}

func sendRequest(url string, data url.Values, headers map[string]string) (string, error) {
	body := strings.NewReader(data.Encode())

	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return "", err
	}

	for key, value := range headers {
		req.Header.Add(key, value)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	responseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(responseBody), nil
}

func extractSubdomains(htmlContent string) []string {
	subdomainPattern := regexp.MustCompile(`'>([^<]+)</a>`)

	matches := subdomainPattern.FindAllStringSubmatch(htmlContent, -1)

	subdomains := make([]string, 0)
	for _, match := range matches {
		if len(match) > 1 {
			subdomain := strings.TrimSpace(match[1])
			if subdomain != "" && subdomain != "none" {
				subdomains = append(subdomains, subdomain)
			}
		}
	}

	return subdomains
}

var onlyDomains bool
var onlyIPs bool
var needHelp bool

func init() {
	flag.BoolVar(&onlyDomains, "od", false, "Only display subdomains")
	flag.BoolVar(&onlyIPs, "oi", false, "Only display IP addresses")
	flag.BoolVar(&needHelp, "h", false, "Display help message")
}

func main() {
	var d string

	flag.StringVar(&d, "d", "", "Specify the domain for the form data")
	flag.Parse()

	if d == "" {
		fmt.Println("Usage: c99find -d <domain>")
		os.Exit(1)
	}

	if needHelp {
		fmt.Println("Usage: c99find -d <domain> [-oi | -od]")
		fmt.Println("Options:")
		fmt.Println("  -oi  Display only IP addresses")
		fmt.Println("  -od  Display only subdomains")
		fmt.Println("  If no filter is specified, both subdomains and IP addresses will be displayed.")
		fmt.Println("Example: c99find -d visma.com -od | anew subdomains")
		os.Exit(1)
	}

	url := "https://subdomainfinder.c99.nl/index.php"

	ip, err := getIPAddress()
	if err != nil {
		log.Fatal(err)
	}

	sha1Hash := calculateSHA1(ip)

	data := createFormData(ip, sha1Hash, d)

	headers := map[string]string{
		"Host":                   "subdomainfinder.c99.nl",
		"Cache-Control":          "max-age=0",
		"Sec-Ch-Ua":              "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\"",
		"Origin":                 "https://subdomainfinder.c99.nl",
		"Sec-Ch-Ua-Mobile":       "?0",
		"Upgrade-Insecure-Requests": "1",
		"User-Agent":             "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.216 Safari/537.36",
		"Content-Type":           "application/x-www-form-urlencoded",
		"Accept":                 "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
		"Sec-Ch-Ua-Platform":     "\"macOS\"",
		"Sec-Fetch-Site":         "same-origin",
		"Sec-Fetch-Mode":         "navigate",
		"Sec-Fetch-Dest":         "empty",
		"Referer":                "https://subdomainfinder.c99.nl",
		 "Accept-Language":        "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
		"Priority":               "u=0, i",
	}

	response, err := sendRequest(url, data, headers)
	if err != nil {
		log.Fatal(err)
	}

	subdomains := extractSubdomains(response)

	for _, subdomain := range subdomains {
		if onlyDomains {
			if isIPAddress(subdomain) {
				continue
			}
			fmt.Println(subdomain)
		} else if onlyIPs && !containsLetters(subdomain) {
			fmt.Println(subdomain)
		} else {
			fmt.Println(subdomain)
		}
	}	
}
