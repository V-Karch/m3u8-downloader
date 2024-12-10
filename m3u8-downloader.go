// @author:llychao<lychao_vip@163.com>
// @contributor: Junyi<me@junyi.pw>
// @date:2020-02-18
// @功能:golang m3u8 video Downloader
package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/levigross/grequests"
)

const (
	// HEAD_TIMEOUT request header timeout
	HEAD_TIMEOUT = 5 * time.Second
	// PROGRESS_WIDTH progress bar length
	PROGRESS_WIDTH = 20
	// TS_NAME_TEMPLATE ts video clip naming rules
	TS_NAME_TEMPLATE = "%05d.ts"
)

var (
	//Command line parameters
	urlFlag = flag.String("u", "", "m3u8 download address (http(s)://url/xx/xx/index.m3u8)")
	nFlag   = flag.Int("n", 24, "num: number of download threads (default 24)")
	htFlag  = flag.String("ht", "v1", "hostType: How to set getHost (v1: `http(s):// + url.Host + filepath.Dir(url.Path)`; v2: ` http(s)://+ u.Host`")
	oFlag   = flag.String("o", "movie", "movieName: custom file name (default is movie) without suffix")
	cFlag   = flag.String("c", "", "cookie:custom request cookie")
	rFlag   = flag.Bool("r", true, "autoClear: Whether to automatically clear ts files")
	sFlag   = flag.Int("s", 0, "InsecureSkipVerify: Whether to allow insecure requests (default 0)")
	spFlag  = flag.String("sp", "", "savePath: the absolute path where the file is saved (the default is the current path, the default value is recommended)")

	logger *log.Logger
	ro     = &grequests.RequestOptions{
		UserAgent:      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36",
		RequestTimeout: HEAD_TIMEOUT,
		Headers: map[string]string{
			"Connection":      "keep-alive",
			"Accept":          "*/*",
			"Accept-Encoding": "*",
			"Accept-Language": "zh-CN,zh;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5",
		},
	}
)

// TsInfo is used to save the download address and file name of the ts file
type TsInfo struct {
	Name string
	Url  string
}

func init() {
	logger = log.New(os.Stdout, "", log.Ldate|log.Ltime|log.Lshortfile)
}

func main() {
	Run()
}

func Run() {
	msgTpl := "[Function]: Multi-threaded download of live streaming m3u8 video\n[Reminder]: Download failed, please use -ht=v2 \n[Reminder]: Download failed, m3u8 address may be nested\n[Reminder]: Progress bar halfway Download failed, can be repeated"
	fmt.Println(msgTpl)
	runtime.GOMAXPROCS(runtime.NumCPU())
	now := time.Now()

	// 1、Parse command line parameters
	flag.Parse()
	m3u8Url := *urlFlag
	maxGoroutines := *nFlag
	hostType := *htFlag
	movieName := *oFlag
	autoClearFlag := *rFlag
	cookie := *cFlag
	insecure := *sFlag
	savePath := *spFlag

	ro.Headers["Referer"] = getHost(m3u8Url, "v2")
	if insecure != 0 {
		ro.InsecureSkipVerify = true
	}
	// http custom cookies
	if cookie != "" {
		ro.Headers["Cookie"] = cookie
	}
	if !strings.HasPrefix(m3u8Url, "http") || m3u8Url == "" {
		flag.Usage()
		return
	}
	var download_dir string
	pwd, _ := os.Getwd()
	if savePath != "" {
		pwd = savePath
	}
	// Initialize the directory for downloading ts, and all subsequent ts files will be saved here.
	download_dir = filepath.Join(pwd, movieName)
	if isExist, _ := pathExists(download_dir); !isExist {
		os.MkdirAll(download_dir, os.ModePerm)
	}

	// 2、Parsing m3u8
	m3u8Host := getHost(m3u8Url, hostType)
	m3u8Body := getM3u8Body(m3u8Url)
	//m3u8Body := getFromFile()
	ts_key := getM3u8Key(m3u8Host, m3u8Body)
	if ts_key != "" {
		fmt.Printf("ts file to be decrypted key: %s \n", ts_key)
	}
	ts_list := getTsList(m3u8Host, m3u8Body)
	fmt.Println("Number of ts files to be downloaded:", len(ts_list))

	// 3. Download the ts file to download_dir
	downloader(ts_list, maxGoroutines, download_dir, ts_key)
	if ok := checkTsDownDir(download_dir); !ok {
		fmt.Printf("\n[Failed] Please check the validity of the url address \n")
		return
	}

	// 4. Merge ts cut files into mp4 files
	mv := mergeTs(download_dir)
	if autoClearFlag {
		// Automatically clear the ts file directory
		os.RemoveAll(download_dir)
	}

	// 5. Output download video information
	DrawProgressBar("Merging", float32(1), PROGRESS_WIDTH, mv)
	fmt.Printf("\n[Success] Download and save path: %s | Total time taken: %6.2fs\n", mv, time.Now().Sub(now).Seconds())
}

// Get the host of m3u8 address
func getHost(Url, ht string) (host string) {
	u, err := url.Parse(Url)
	checkErr(err)
	switch ht {
	case "v1":
		host = u.Scheme + "://" + u.Host + filepath.Dir(u.EscapedPath())
	case "v2":
		host = u.Scheme + "://" + u.Host
	}
	return
}

// Get the content body of m3u8 address
func getM3u8Body(Url string) string {
	r, err := grequests.Get(Url, ro)
	checkErr(err)
	return r.String()
}

// Get m3u8 encrypted key
func getM3u8Key(host, html string) (key string) {
	lines := strings.Split(html, "\n")
	key = ""
	for _, line := range lines {
		if strings.Contains(line, "#EXT-X-KEY") {
			if !strings.Contains(line, "URI") {
				continue
			}
			fmt.Println("[debug] line_key:", line)
			uri_pos := strings.Index(line, "URI")
			quotation_mark_pos := strings.LastIndex(line, "\"")
			key_url := strings.Split(line[uri_pos:quotation_mark_pos], "\"")[1]
			if !strings.Contains(line, "http") {
				key_url = fmt.Sprintf("%s/%s", host, key_url)
			}
			res, err := grequests.Get(key_url, ro)
			checkErr(err)
			if res.StatusCode == 200 {
				key = res.String()
				break
			}
		}
	}
	fmt.Println("[debug] m3u8Host:", host, "m3u8Key:", key)
	return
}

func getTsList(host, body string) (tsList []TsInfo) {
	lines := strings.Split(body, "\n")
	index := 0
	var ts TsInfo
	for _, line := range lines {
		if !strings.HasPrefix(line, "#") && line != "" {
			// There may be m3u8 in the second-level nested format, please convert it yourself!
			index++
			if strings.HasPrefix(line, "http") {
				ts = TsInfo{
					Name: fmt.Sprintf(TS_NAME_TEMPLATE, index),
					Url:  line,
				}
				tsList = append(tsList, ts)
			} else {
				line = strings.TrimPrefix(line, "/")
				ts = TsInfo{
					Name: fmt.Sprintf(TS_NAME_TEMPLATE, index),
					Url:  fmt.Sprintf("%s/%s", host, line),
				}
				tsList = append(tsList, ts)
			}
		}
	}
	return
}

func getFromFile() string {
	data, _ := os.ReadFile("./ts.txt")
	return string(data)
}

// Download ts file
// @modify: 2020-08-13 Fixed the problem that ts format SyncByte merge cannot be played
func downloadTsFile(ts TsInfo, download_dir, key string, retries int) {
	if retries <= 0 {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			// fmt.Println("The network is unstable, downloading at breakpoint is ongoing")
			downloadTsFile(ts, download_dir, key, retries-1)
		}
	}()
	curr_path_file := fmt.Sprintf("%s/%s", download_dir, ts.Name)
	if isExist, _ := pathExists(curr_path_file); isExist {
		// logger.Println("[warn] File: " + ts.Name + "already exist")
		return
	}
	res, err := grequests.Get(ts.Url, ro)
	if err != nil || !res.Ok {
		if retries > 0 {
			downloadTsFile(ts, download_dir, key, retries-1)
			return
		} else {
			// logger.Printf("[warn] File :%s", ts.Url)
			return
		}
	}
	// Check whether the length is legal
	var origData []byte
	origData = res.Bytes()
	contentLen := 0
	contentLenStr := res.Header.Get("Content-Length")
	if contentLenStr != "" {
		contentLen, _ = strconv.Atoi(contentLenStr)
	}
	if len(origData) == 0 || (contentLen > 0 && len(origData) < contentLen) || res.Error != nil {
		// logger.Println("[warn] File: " + ts.Name + "res origData invalid or err：", res.Error)
		downloadTsFile(ts, download_dir, key, retries-1)
		return
	}
	// Decrypt the video ts source file
	if key != "" {
		// Decrypt ts file, algorithm: aes 128 cbc pack5
		origData, err = AesDecrypt(origData, []byte(key))
		if err != nil {
			downloadTsFile(ts, download_dir, key, retries-1)
			return
		}
	}
	// https://en.wikipedia.org/wiki/MPEG_transport_stream
	// Some TS files do not start with SyncByte 0x47, they can not be played after merging,
	// Need to remove the bytes before the SyncByte 0x47(71).
	syncByte := uint8(71) //0x47
	bLen := len(origData)
	for j := 0; j < bLen; j++ {
		if origData[j] == syncByte {
			origData = origData[j:]
			break
		}
	}
	os.WriteFile(curr_path_file, origData, 0666)
}

// downloader m3u8 Downloader
func downloader(tsList []TsInfo, maxGoroutines int, downloadDir string, key string) {
	retry := 5 // Number of retries for a single ts download
	var wg sync.WaitGroup
	limiter := make(chan struct{}, maxGoroutines) // chan struct memory occupied 0 bool occupied 1
	tsLen := len(tsList)
	downloadCount := 0
	for _, ts := range tsList {
		wg.Add(1)
		limiter <- struct{}{}
		go func(ts TsInfo, downloadDir, key string, retryies int) {
			defer func() {
				wg.Done()
				<-limiter
			}()
			downloadTsFile(ts, downloadDir, key, retryies)
			downloadCount++
			DrawProgressBar("Downloading", float32(downloadCount)/float32(tsLen), PROGRESS_WIDTH, ts.Name)
			return
		}(ts, downloadDir, key, retry)
	}
	wg.Wait()
}

func checkTsDownDir(dir string) bool {
	if isExist, _ := pathExists(filepath.Join(dir, fmt.Sprintf(TS_NAME_TEMPLATE, 0))); !isExist {
		return true
	}
	return false
}

// Merge ts files
func mergeTs(downloadDir string) string {
	mvName := downloadDir + ".mp4"
	outMv, _ := os.Create(mvName)
	defer outMv.Close()
	writer := bufio.NewWriter(outMv)
	err := filepath.Walk(downloadDir, func(path string, f os.FileInfo, err error) error {
		if f == nil {
			return err
		}
		if f.IsDir() || filepath.Ext(path) != ".ts" {
			return nil
		}
		bytes, _ := os.ReadFile(path)
		_, err = writer.Write(bytes)
		return err
	})
	checkErr(err)
	_ = writer.Flush()
	return mvName
}

// progress bar
func DrawProgressBar(prefix string, proportion float32, width int, suffix ...string) {
	pos := int(proportion * float32(width))
	s := fmt.Sprintf("[%s] %s%*s %6.2f%% \t%s",
		prefix, strings.Repeat("■", pos), width-pos, "", proportion*100, strings.Join(suffix, ""))
	fmt.Print("\r" + s)
}

// ============================== Shell related ==============================
// Determine whether the file exists
func pathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

// Execute shell
func execUnixShell(s string) {
	cmd := exec.Command("bash", "-c", s)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s", out.String())
}

func execWinShell(s string) error {
	cmd := exec.Command("cmd", "/C", s)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return err
	}
	fmt.Printf("%s", out.String())
	return nil
}

// windows merge files
func win_merge_file(path string) {
	pwd, _ := os.Getwd()
	os.Chdir(path)
	execWinShell("copy /b *.ts merge.tmp")
	execWinShell("del /Q *.ts")
	os.Rename("merge.tmp", "merge.mp4")
	os.Chdir(pwd)
}

// unix Merge files
func unix_merge_file(path string) {
	pwd, _ := os.Getwd()
	os.Chdir(path)
	//cmd := `ls  *.ts |sort -t "\." -k 1 -n |awk '{print $0}' |xargs -n 1 -I {} bash -c "cat {} >> new.tmp"`
	cmd := `cat *.ts >> merge.tmp`
	execUnixShell(cmd)
	execUnixShell("rm -rf *.ts")
	os.Rename("merge.tmp", "merge.mp4")
	os.Chdir(pwd)
}

// ============================= Encryption and decryption related ==============================

func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func AesEncrypt(origData, key []byte, ivs ...[]byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	var iv []byte
	if len(ivs) == 0 {
		iv = key
	} else {
		iv = ivs[0]
	}
	origData = PKCS7Padding(origData, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, iv[:blockSize])
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	return crypted, nil
}

func AesDecrypt(crypted, key []byte, ivs ...[]byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	var iv []byte
	if len(ivs) == 0 {
		iv = key
	} else {
		iv = ivs[0]
	}
	blockMode := cipher.NewCBCDecrypter(block, iv[:blockSize])
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	origData = PKCS7UnPadding(origData)
	return origData, nil
}

func checkErr(e error) {
	if e != nil {
		logger.Panic(e)
	}
}
