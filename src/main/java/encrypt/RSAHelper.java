package encrypt;

import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

public class RSAHelper {
    public static final String KEY_ALGORITHM = "RSA";
    private static final int KEY_LENGTH = 1024;
    public static final String PUBLIC_KEY = "PublicKey";
    public static final String PRIVATE_KEY = "PrivateKey";
    private static final int MAX_ENCRYPT_BLOCK = 117;
    private static final int MAX_DECRYPT_BLOCK = 128;
    private static final String SIGNATURE_ALGORITHM = "MD5withRSA";

    public RSAHelper() {
    }

    public static void generateKeyPair(Map<String, Object> keyMap) {
        boolean result = false;

        KeyPairGenerator keyPairGenerator = null;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            result = true;
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(RSAHelper.class.getName()).log(Level.SEVERE, null,
                    ex);
        }

        if (result) {
            SecureRandom secureRandom = new SecureRandom();

            String currentDateTime = new SimpleDateFormat("yyyyMMddHHmmssSSS")
                    .format(new Date());
            secureRandom.setSeed(currentDateTime.getBytes());

            keyPairGenerator.initialize(1024, secureRandom);

            KeyPair keyPair = keyPairGenerator.genKeyPair();

            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();

            keyMap.put("PublicKey", publicKey.getEncoded());
            keyMap.put("PrivateKey", privateKey.getEncoded());
        }
    }

    public static void saveKeyPair(Map<String, Object> keyPair,
                                   String publicKeyFileName, String privateKeyFileName) {
        try {
            FileOutputStream fileOutputStream = new FileOutputStream(
                    publicKeyFileName);
            byte[] publicKey = (byte[]) keyPair.get("PublicKey");
            fileOutputStream.write(publicKey);
            fileOutputStream.close();
        } catch (FileNotFoundException ex) {
            Logger.getLogger(RSAHelper.class.getName()).log(Level.SEVERE, null,
                    ex);
        } catch (IOException ex) {
            Logger.getLogger(RSAHelper.class.getName()).log(Level.SEVERE, null,
                    ex);
        }

        try {
            FileOutputStream fileOutputStream = new FileOutputStream(
                    privateKeyFileName);
            byte[] privateKey = (byte[]) keyPair.get("PrivateKey");
            fileOutputStream.write(privateKey);
            fileOutputStream.close();
        } catch (FileNotFoundException ex) {
            Logger.getLogger(RSAHelper.class.getName()).log(Level.SEVERE, null,
                    ex);
        } catch (IOException ex) {
            Logger.getLogger(RSAHelper.class.getName()).log(Level.SEVERE, null,
                    ex);
        }
    }

    public static byte[] getKey(String keyFileName) {
        byte[] keyBytes = null;
        try {
            File file = new File(keyFileName);
            FileInputStream fileInputStream = new FileInputStream(file);
            DataInputStream dataInputStream = new DataInputStream(
                    fileInputStream);

            keyBytes = new byte[(int) file.length()];

            dataInputStream.readFully(keyBytes);

            dataInputStream.close();
            fileInputStream.close();
        } catch (FileNotFoundException ex) {
            Logger.getLogger(RSAHelper.class.getName()).log(Level.SEVERE, null,
                    ex);
        } catch (IOException ex) {
            Logger.getLogger(RSAHelper.class.getName()).log(Level.SEVERE, null,
                    ex);
        }

        return keyBytes;
    }

    public static byte[] encryptWithPublicKey(byte[] data, int offSet,
                                              int length, byte[] keyBytes) throws Exception {
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        Key publicK = keyFactory.generatePublic(x509KeySpec);

        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(1, publicK);
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        int i = 0;

        while (length - offSet > 0) {
            byte[] cache;
            if (length - offSet > 117) {
                cache = cipher.doFinal(data, offSet, 117);
            } else {
                cache = cipher.doFinal(data, offSet, length - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * 117;
        }
        byte[] encryptedData = out.toByteArray();
        out.close();
        return encryptedData;
    }

    public static byte[] encryptWithPrivateKey(byte[] data, int offSet,
                                               int length, byte[] keyBytes) throws Exception {
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        Key privateK = keyFactory.generatePrivate(pkcs8KeySpec);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(1, privateK);
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        int i = 0;

        while (length - offSet > 0) {
            byte[] cache;
            if (length - offSet > 117) {
                cache = cipher.doFinal(data, offSet, 117);
            } else {
                cache = cipher.doFinal(data, offSet, length - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * 117;
        }
        byte[] encryptedData = out.toByteArray();
        out.close();
        return encryptedData;
    }

    public static byte[] decryptWithPublicKey(byte[] data, int offSet,
                                              int length, byte[] keyBytes) throws Exception {
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        Key publicK = keyFactory.generatePublic(x509KeySpec);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(2, publicK);
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        int i = 0;

        while (length - offSet > 0) {
            byte[] cache;
            if (length - offSet > 128) {
                cache = cipher.doFinal(data, offSet, 128);
            } else {
                cache = cipher.doFinal(data, offSet, length - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * 128;
        }
        byte[] decryptedData = out.toByteArray();
        out.close();
        return decryptedData;
    }

    public static byte[] decryptWithPrivateKey(byte[] data, int offSet,
                                               int length, byte[] keyBytes) throws Exception {
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        Key privateK = keyFactory.generatePrivate(pkcs8KeySpec);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(2, privateK);
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        int i = 0;

        while (length - offSet > 0) {
            byte[] cache;
            if (length - offSet > 128) {
                cache = cipher.doFinal(data, offSet, 128);
            } else {
                cache = cipher.doFinal(data, offSet, length - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * 128;
        }
        byte[] decryptedData = out.toByteArray();
        out.close();
        return decryptedData;
    }

    public static byte[] sign(byte[] data, int offset, int length,
                              byte[] privateKeyBytes) {
        byte[] signedData = null;
        try {
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
                    privateKeyBytes);

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            PrivateKey privateKey = keyFactory
                    .generatePrivate(pkcs8EncodedKeySpec);

            Signature signature = Signature.getInstance("MD5withRSA");

            signature.initSign(privateKey);

            signature.update(data, offset, length);

            signedData = signature.sign();
        } catch (Exception ex) {
            Logger.getLogger(RSAHelper.class.getName()).log(Level.SEVERE, null,
                    ex);
        }

        return signedData;
    }

    public static boolean verify(byte[] data, int offset, int length,
                                 byte[] publicKeyBytes, byte[] dataSignature) {
        boolean result = false;
        try {
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(
                    publicKeyBytes);

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);

            Signature signature = Signature.getInstance("MD5withRSA");

            signature.initVerify(publicKey);

            signature.update(data, offset, length);

            result = signature.verify(dataSignature);
        } catch (Exception ex) {
            Logger.getLogger(RSAHelper.class.getName()).log(Level.SEVERE, null,
                    ex);
        }

        return result;
    }
}

