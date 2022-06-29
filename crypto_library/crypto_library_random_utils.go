package cryptolib

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"time"
)

func addLocalEntropyToRandomPool() {
	writeToEntropyPool(getInstanceDataEntropy())
	entropy, err := getAWSInstanceMetadataEntropy()
	if err != nil {
		writeToEntropyPool(entropy)
	}

}

//reason for writing some static data is so that 2 equal instances don't start with the same random pool
func writeToEntropyPool(data []byte) error {
	errRandom := ioutil.WriteFile("/dev/random", data, 0644)
	errUrandom := ioutil.WriteFile("/dev/urandom", data, 0644)

	if errRandom == nil || errUrandom == nil {
		return nil
	}

	return errors.New("Could not write to /dev/random and /dev/urandom")
}

func getAWSInstanceMetadataEntropy() ([]byte, error) {

	metadataURLs := []string{
		"http://169.254.169.254/latest/meta-data/iam/info",
		"http://169.254.169.254/latest/meta-data/local-hostname",
		"http://169.254.169.254/latest/meta-data/reservation-id",
		"http://169.254.169.254/latest/dynamic/instance-identity/document",
		"http://169.254.169.254/latest/dynamic/instance-identity/signature",
		"http://169.254.169.254/latest/dynamic/instance-identity/pkcs7",
		"http://169.254.169.254/latest/dynamic/instance-identity/rsa2048",
		"http://169.254.169.254/latest/meta-data/network/interfaces/macs/",
		"http://169.254.169.254/latest/meta-data/iam/security-credentials/",
	}

	timeout := time.Duration(5 * time.Millisecond)
	client := http.Client{
		Timeout: timeout,
	}
	entropy := ""
	var body []byte
	for _, metadataURL := range metadataURLs {
		resp, err := client.Get(metadataURL)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		body, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		entropy += string(body)
	}

	resp, err := client.Get("http://169.254.169.254/latest/meta-data/iam/security-credentials/" + string(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	sha512 := sha512.New()
	sha512.Write([]byte(entropy))
	return sha512.Sum(nil), nil

}

func getEntropyFromKMS() ([]byte, error) {
	return nil, errors.New("getEntropyFromKMS Not implemented")
	//https://docs.aws.amazon.com/kms/latest/APIReference/API_GenerateRandom.html
	//https://github.com/aws/aws-sdk-go/blob/master/service/kms/api.go#L1855
	//need to make sure to query the correct region
}

func getEntropyFromUbuntuPollinate() ([]byte, error) {
	client := &http.Client{}

	req, err := http.NewRequest("POST", "https://entropy.ubuntu.com/", nil)
	if err != nil {
		return nil, errors.New("cryptolib failed new request")
	}

	req.Header.Set("User-Agent", "curl/7.47.0-1ubuntu2.9 pollinate/4.33-0ubuntu1~16.04.1 cloud-init/ Ubuntu/16.04.3/LTS GNU/Linux/4.10.0-28-generic/x86_64 Intel(R)/Core(TM)/i7-6660U/CPU/@/2.40GHz uptime/25472.19/20375.82 virt/oracle")

	//challenge is required but not used, that's why it's static, the server is expecting a random, it's not a secret.
	resp, err := client.PostForm("https://entropy.ubuntu.com/",
		url.Values{"challenge": {"2001dee208ffefdc7051675c7f0dac63cad6aa85f6c57d31a75c879ce6f2e8ca63b16acded5ac16f0b53046f03f104f4dc33bc62542a5a561db631c807ad5ca4"}})
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	entropy, err := hex.DecodeString(string(body)[129:257]) //first 128 characters with newline are not entropy, hence not needed.
	if err != nil {
		return nil, err
	}
	return entropy, nil
}

func getEntropyFromRandomService() ([]byte, error) {
	resp, err := http.Get("https://www.random.org/strings/?num=1&len=20&digits=on&upperalpha=on&loweralpha=on&unique=on&format=plain&rnd=new")
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("cryptolib: getEntropyFromRandomService: Entropy pool depleted or service malfunction. Status Code: %d", resp.StatusCode)
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	if len(body) != 21 { //end of line adds 1 more character to the 20 requested.
		return nil, fmt.Errorf("cryptolib: getEntropyFromRandomService: Received an invalid random: %s", body)
	}
	return body, nil
}

//getInstanceData
func getInstanceDataEntropy() []byte {
	uniqueData := ""
	uniqueData += getHostNetworkInformation()
	uniqueData += getHostName()
	uniqueData += strconv.FormatInt(time.Now().UnixNano(), 10) //doesn't seem to have nanosec resolution in OSX
	out, err := exec.Command("nstat").Output()
	if err != nil {
		uniqueData += string(out)
	}

	sha512 := sha512.New()
	sha512.Write([]byte(uniqueData))
	return sha512.Sum(nil)
	//date +%s%N works in linux AWS AMI and Ubuntu
}

func getHostName() string {
	name, err := os.Hostname()
	if err != nil {
		return ""
	}
	return name
}

//Gets all IPs v4,v6 and loopbacks (that are not actually needed)
func getHostNetworkInformation() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	var networkData string
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			return ""
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			networkData += ip.String()
		}
		if i.Flags&net.FlagUp != 0 && bytes.Compare(i.HardwareAddr, nil) != 0 {
			networkData += i.HardwareAddr.String()
		}
	}
	return networkData
}
