import encrypt.RSAKeyUtils;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class main {
    public static final String PUBLIC_KEY = "./public.key";
    public static final String PRIVATE_KEY = "./private.key";
    public static final String TEST_FILE = "./test.txt";

    public static final String OPENSSL_PUBLIC_KEY = "./openssl_public.pem";
    public static final String OPENSSL_PRIVATE_KEY = "./openssl_private.pem";

    public static void main(String[] args) throws Exception {
        RSAKeyUtils.setPublicKeyPath(PUBLIC_KEY);
        RSAKeyUtils.setPrivatePath(PRIVATE_KEY);

        RSAKeyUtils.init(PUBLIC_KEY, PRIVATE_KEY);

        encryptSting();

        readOpenSSLPrivateKeyAndVerifySignature();
    }

    static void encryptSting() {
        String text = "e5195a5ddc9c792cb86c42111ca24f4e69b4a4c7cfae168f47bcb6fbcffb69ec";
        System.out.println("原始数据:" + text);
        String enc = RSAKeyUtils.encByPrivateKey(text);
        System.out.println("加密数据:" + enc);
        System.out.println("解密数据:" + RSAKeyUtils.decByPublicKey(enc));
        String sign=RSAKeyUtils.doSignPrivateKey(text);
        System.out.println("签名:"+sign);
        System.out.println("验签结果:"+RSAKeyUtils.doVerifyPublicKey(text, sign));
    }

    static void readOpenSSLPrivateKeyAndVerifySignature() throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException, IOException {
        try (PemReader pemReader = new PemReader(new FileReader(OPENSSL_PRIVATE_KEY))) {
            byte[] code =  Files.readAllBytes(Paths.get(TEST_FILE));

            PemObject pemObject = pemReader.readPemObject();
            byte[] pemContent = pemObject.getContent();

            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pemContent);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = kf.generatePrivate(keySpec);

            Signature privateSignature = Signature.getInstance("SHA256withRSA");
            privateSignature.initSign(privateKey);
            privateSignature.update(code);

            String result = Base64.getEncoder().encodeToString(privateSignature.sign());
            System.out.println("OpenSSL PEM 对文件 " + TEST_FILE + " 的签名:" + result);
        }
    }
}
