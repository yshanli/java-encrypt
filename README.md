# java-encrypt
使用java加解密的示例代码，openssl操作命令放在test.txt文件


PKCS ： Public Key Cryptography Standards
PEM:  Private Enhanced Mail
密钥的描述是用ASN.1定义的，而对ASN.1描述语言可以用多种编码形式，比如BER（Basic Encode Rules）, DER(Distinguished Encode Rules)

PKCS#1 : 是 RSA Cryptography Specifications，即 RSA 密码学规范, 定义了RAS密钥文件格式和编码方式，以及加解密，签名，填充的基础算法
OpenSSL 命令示例
$ openssl genrsa -out prikey.p1 1024
$ openssl rsa -in prikey.p1 -pubout -RSAPublicKey_out > pubkey.p1
导出的文件就是PKCS#1格式的，用文本编辑器打开可以看到 以 
-----BEGIN RSA PUBLIC KEY-----
-----END RSA PUBLIC KEY-----
-----BEGIN RSA PRIVATE KEY-----
-----END RSA PRIVATE KEY-----
如果key带有密码，则上述字符串里会带有 ENCRYPTED字眼

PKCS#8： 是 Private-Key Information Syntax Standard，即私钥格式相关的标准，它不像 PKCS#1 只支持 RSA，而是支持各种类型的私钥。PKCS#8 私钥文件格式中首尾并未说明私钥算法类型，算法类型在数据中标识。PKCS#8 中的私钥也支持加密
可以使用 openssl 将 PKCS#1 格式的私钥 prikey.p1 转换成 PKCS#8 格式的 prikey.p8，如下：
$ openssl pkcs8 -in prikey.p1 -topk8 -out prikey.p8 -nocrypt
这里生成的密钥文件都是二进制形式，直接用文本编辑器打开会是乱码，所以key一般都会经过base64编码，方便传输和阅读，即openssl的命令导出密钥的时候使用PEM格式输出，DER格式则是输出二进制格式
以上是密钥的格式的一般知识，证书则是包含了一个或者多个公私秘钥信息的文件。
目前总的来说有三种常用的证书编码格式：X.509证书、PKCS#12证书和PKCS#7证书：
X.509证书是最经常使用的证书，它仅包含了公钥信息而没有私钥信息，是可以公开进行发布的，所以X.509证书对象一般都不需要加密。
X.509证书的格式通常如下:
                 ……相关的可读解释信息（省略）……
                 ---BEGIN CERTIFICATE---
                 ……PEM编码的X.509证书内容(省略)……
                 ---END CERTIFICATE---
PKCS#12证书: 不同于X.509证书，它可以包含一个或多个证书，并且还可以包含证书对应的私钥。PKCS#12的私钥是经过加密的，密钥由用户提供的口令产生。所以，无论在使用PKCS#12证书的时候一般会要用用户输入密钥口令。PKCS#12证书文件在Windwos平台和Mozzila中支持的后缀名是p12或者pfx。






