package encrypt;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;

import java.io.File;
import java.io.IOException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class RSAKeyUtils {
    private static String RAS_PUBLICKEY_PATH = "";
    private static String RSA_PRIVATEKEY_PATH = "";

    public static void init(String RAS_PUBLICKEY_PATH,
                               String RSA_PRIVATEKEY_PATH) {
        try {
            FileUtils.forceMkdir(new File(new File(RAS_PUBLICKEY_PATH)
                    .getParent()));
            Map<String, Object> keyPair = new HashMap<>();
            RSAHelper.generateKeyPair(keyPair);
            RSAHelper.saveKeyPair(keyPair, RAS_PUBLICKEY_PATH,
                    RSA_PRIVATEKEY_PATH);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void setPublicKeyPath(String keyPath) {
        RAS_PUBLICKEY_PATH = keyPath;
    }

    public static void setPrivatePath(String crtPath) {
        RSA_PRIVATEKEY_PATH = crtPath;
    }

    public static String encByPublicKey(String data) {
        String dataBack = "";
        try {
            if (!StringUtils.isEmpty(data)) {
                byte[] Bytes = RSAHelper.encryptWithPublicKey(data.getBytes(),
                        0, data.getBytes().length,
                        RSAHelper.getKey(RAS_PUBLICKEY_PATH));
                dataBack = new String(Base64.getEncoder().encode(Bytes));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return dataBack;
    }

    public static String encByPrivateKey(String data) {
        String dataBack = "";
        try {
            if (!StringUtils.isEmpty(data)) {
                byte[] Bytes = RSAHelper.encryptWithPrivateKey(data.getBytes(),
                        0, data.getBytes().length,
                        RSAHelper.getKey(RSA_PRIVATEKEY_PATH));
                dataBack = new String(Base64.getEncoder().encode(Bytes));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return dataBack;
    }

    public static String decByPublicKey(String data) {
        String dataBack = "";
        try {
            if (!StringUtils.isEmpty(data)) {
                dataBack = decByPublicKey(data, RSAHelper.getKey(RAS_PUBLICKEY_PATH));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return dataBack;
    }

    public static String decByPublicKey(String data, byte[] key) {
        String dataBack = "";
        try {
            if (!StringUtils.isEmpty(data)) {
                byte[] Bytes = RSAHelper.decryptWithPublicKey(
                        Base64.getDecoder().decode(data), 0,
                        Base64.getDecoder().decode(data).length,
                        key);
                dataBack = new String(Bytes);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return dataBack;
    }

    public static String decByPrivateKey(String data) {
        String dataBack = "";
        try {
            if (!StringUtils.isEmpty(data)) {
                byte[] Bytes = RSAHelper.decryptWithPrivateKey(
                        Base64.getDecoder().decode(data), 0,
                        Base64.getDecoder().decode(data).length,
                        RSAHelper.getKey(RSA_PRIVATEKEY_PATH));
                dataBack = new String(Bytes);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return dataBack;
    }

    public static String doSignPrivateKey(String data) {
        String dataBack = "";
        try {
            if (!StringUtils.isEmpty(data)) {
                byte[] Bytes = RSAHelper.sign(data.getBytes(), 0,
                        data.getBytes().length,
                        RSAHelper.getKey(RSA_PRIVATEKEY_PATH));
                dataBack = new String(Base64.getEncoder().encode(Bytes));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return dataBack;
    }

    public static boolean doVerifyPublicKey(String data, String sign) {
        Boolean returnFlag = Boolean.FALSE;
        if ((StringUtils.isEmpty(data)) || (StringUtils.isEmpty(sign))) {
            return false;
        }
        try {
            returnFlag = RSAHelper.verify(data.getBytes(), 0,
                    data.getBytes().length,
                    RSAHelper.getKey(RAS_PUBLICKEY_PATH),
                    Base64.getDecoder().decode(sign));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return returnFlag;
    }

}

