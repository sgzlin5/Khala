# Khala
Khala Connect everything!


Based on n2n, we add UDP punching process make it is possible to make a UDP hole between NAT3 <-> NAT4 or NAT4 <-> NAT4.


We would not have any plan for further development and support, good luck :)

## Build

Required following libraries:
- libjson-c
- libcurl

These libraries should be installed before start compiling, compile commands as following:
```
sudo apt-get install libcurl4-openssl-dev -y
sudo apt-get install libjson-c-dev -y
cmake ./
make
```

## Host Setup

Parameters introduction (参数介绍):
- `-f`: supernode run in foreground (如果开启这个选项SN将会运行在前台) 
- `-v`: make more verbose (调整LOG等级，每多一个v，LOG等级提高1级)
- `-s`: specified url used to verify community and password from edge（默认不配置即可）
- `-p`: specified local port, default is 7654 (指定SN的端口，默认端口是7654)

Example:
```
sudo supernode -p 7654
```

## Edge Setup

Parameters introduction (参数介绍):
- `-c`: community name edge belongs to (节点要加入/创建的community名称)
- `-k`: encryption key (密码)
- `-a`: interface address and optional CIDR subnet (ip地址 eg. static:10.110.0.1)
- `-f`: edge run in foreground (如果开启这个选项edge将会运行在前台) 
- `-l`: supernode ip address or name, and port (指定SN的地址与端口 eg. supernode.net:7654)
- `-r`: enable packet forwarding through community (允许报文通过community转发)
- `-d`: TAP device name (创建的设备名)
- `-A`: choose a cipher for payload encryption (加密算法选择使用ChaCha20 -A4)

Example:
```
sudo edge -c mycmn -k mypaswd -a 10.110.10.1 -l supernode.net:7654 -r -d edge0 -A4
```

## Related Projects
 - Original N2N: [n2n](https://github.com/ntop/n2n)
 - Android N2N: [hin2n](https://github.com/switch-iot/hin2n)
 - Khala App: [khala-app](git@github.com:sgzlin5/khala-app.git)