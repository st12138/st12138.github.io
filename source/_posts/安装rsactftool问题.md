---
title: 安装RsaCtfTool问题
date: 2019-08-12 16:01:47
tags: [tool,ctf]
categories: 
- 问题
---
## 安装RsaCtfTool遇到的问题
### 1.没有安装mpfr和mpc

```
错误
fatal error: mpfr.h
fatal error: mpc.h
```

---------------------------------------------

```
解决
ftp://ftp.gnu.org/gnu/mpfr
tar mpfr-v.tar.gz   
cd mpfr-v
./configure
make
make check
make install

ftp://gcc.gnu.org/pub/gcc/infrastructure
tar -xzvf  mpc-v.tar.gz
cd mpc-1.0.3
./configure
make
make check
make install
```

安装配置mpfr和mpc  

### 2.网络

```
错误
Could not find a version that satisfies the requirement skimage (from versions: )      
Collecting distribute
Exception:
Traceback (most recent call last):
```

--------------------------------------------------


```
解决
pip install -r requirements.txt -i http://pypi.douban.com/simple/ --trusted-host pypi.douban.com
```

换豆瓣的镜像源