# m3u8-downloader

Golang multi-threaded download of live stream m3u8 format video, cross-platform. You only need to specify the necessary flags (`u`, `o`, `n`, `ht`) to run, and the tool will automatically parse the M3U8 file for you and download the TS fragments and merge them into one file.


## Function introduction

1. Download and parse M3U8
2. Retry when downloading TS fails (encrypted and synchronized decryption)
3. Merge TS fragments

>You can download small movies from island countries
>You can download small movies from island countries
>You can download small movies from island countries
> Say important things three times...

## Effect display
![demo](./demo.gif)

## Parameter description:

```
- u m3u8 download address (http(s)://url/xx/xx/index.m3u8)
- o movieName: Custom file name (default is movie) without suffix (default "movie")
- n num: number of download threads (default 24)
- ht hostType: How to set getHost (v1: http(s):// + url.Host + filepath.Dir(url.Path); v2: `http(s)://+ u.Host` (default " v1")
- c cookie: Custom request cookie (for example: key1=v1; key2=v2)
- r autoClear: Whether to automatically clear ts files (default true)
-s InsecureSkipVerify: Whether to allow insecure requests (default 0)
- sp savePath: The absolute path where the file is saved (default is the current path, default value is recommended) (for example: unix:/Users/xxxx; windows:C:\Documents)
```

By default, only the `u` parameter needs to be passed, and other parameters can be kept as default. Some links may limit the request frequency, and the value of the `n` parameter can be adjusted according to the actual situation.

## download

The compiled platforms include: [Click to download](https://github.com/llychao/m3u8-downloader/releases)

- m3u8-darwin-amd64
- m3u8-darwin-arm64
- m3u8-linux-386
- m3u8-linux-amd64
- m3u8-linux-arm64
- m3u8-windows-386.exe
- m3u8-windows-amd64.exe
- m3u8-windows-arm64.exe

## Usage

### Source code method

```bash
Compile yourself: go build -o m3u8-downloader
Simple use: ./m3u8-downloader -u=http://example.com/index.m3u8
Complete use: ./m3u8-downloader -u=http://example.com/index.m3u8 -o=example -n=16 -ht=v1 -c="key1=v1; key2=v2"
```

### Binary mode:

Linux and MacOS and Windows PowerShell

```
Simple to use:
./m3u8-linux-amd64 -u=http://example.com/index.m3u8
./m3u8-darwin-amd64 -u=http://example.com/index.m3u8
.\m3u8-windows-amd64.exe -u=http://example.com/index.m3u8

Full use:
./m3u8-linux-amd64 -u=http://example.com/index.m3u8 -o=example -n=16 -ht=v1 -c="key1=v1; key2=v2"
./m3u8-darwin-amd64 -u=http://example.com/index.m3u8 -o=example -n=16 -ht=v1 -c="key1=v1; key2=v2"
.\m3u8-windows-amd64.exe -u=http://example.com/index.m3u8 -o=example -n=16 -ht=v1 -c="key1=v1; key2=v2"
```

## Problem description

1. On Linux or Mac platform, if it shows that there is no running permission, please use the chmod command to add permissions.
```bash
 # Linux amd64 platform
 chmod 0755 m3u8-linux-amd64
 # Mac darwin amd64 platform
 chmod 0755 m3u8-darwin-amd64
 ```
2. If the download fails, please set -ht="v1" or -ht="v2" (default is v1)
```golang
func get_host(Url string, ht string) string {
    u, err := url.Parse(Url)
    var host string
    checkErr(err)
    switch ht {
    case "v1":
        host = u.Scheme + "://" + u.Host + path.Dir(u.Path)
    case "v2":
        host = u.Scheme + "://" + u.Host
    }
    return host
}
```
