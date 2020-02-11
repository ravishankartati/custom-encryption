package com.ravi.customencyptplugin;

import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CallbackContext;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Random;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Hex;

/**
 * This class echoes a string called from JavaScript.
 */
public class CustomEncryptPlugin extends CordovaPlugin {

    private static final String ENCRYPT = "encrypt";
    private static final String DECRYPT = "decrypt";
    private static final String GENERATE_SECURE_KEY = "generateSecureKey";
    private static final String GENERATE_SECURE_IV = "generateSecureIV";

    private static final String CIPHER_TRANSFORMATION = "AES/CBC/PKCS5PADDING";
    private static final int PBKDF2_ITERATION_COUNT = 1001;
    private static final int PBKDF2_KEY_LENGTH = 256;
    private static final int SECURE_IV_LENGTH = 64;
    private static final int SECURE_KEY_LENGTH = 128;
    private static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA1";
    private static final String PBKDF2_SALT = "hY0wTq6xwc6ni01G";
    private static final Random RANDOM = new SecureRandom();

    @Override
    public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException {
        if (action.equals("ENCRYPT")) {
            String secureKey = args.getString(0);
            String iv = args.getString(1);
            String value = args.getString(2);
            callbackContext.success(encrypt(secureKey, value, iv));
        }
        return false;
    }

    /**
     * To perform the AES256 encryption
     *
     * @param secureKey A 32 bytes string, which will used as input key for AES256
     *                  encryption
     * @param fileURL   Path to the file which will be encrypted.
     * @param iv        A 16 bytes string, which will used as initial vector for
     *                  AES256 encryption
     * @return AES Encrypted file URL
     * @throws Exception
     */
    private String encrypt(String secureKey, String fileURL, String iv) throws Exception {
        byte[] pbkdf2SecuredKey = generatePBKDF2(secureKey.toCharArray(), PBKDF2_SALT.getBytes("UTF-8"),
                PBKDF2_ITERATION_COUNT, PBKDF2_KEY_LENGTH);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes("UTF-8"));
        SecretKeySpec secretKeySpec = new SecretKeySpec(pbkdf2SecuredKey, "AES");
        return encryptUsingFileStream(secretKeySpec, ivParameterSpec, fileURL);

    }

    /**
     * To perform the AES256 encryption using FileStream
     *
     * @param secureKey A 32 bytes string, which will used as input key for AES256
     *                  encryption
     * @param fileURL   Path to the file which will be encrypted.
     * @param iv        A 16 bytes string, which will used as initial vector for
     *                  AES256 encryption
     * @return File path of encrypted file.
     * @throws Exception
     */

    private String encryptUsingFileStream(SecretKeySpec secretKeySpec, IvParameterSpec ivParameterSpec,
            String fileURL) {
        int read;
        File inputFile = new File(fileUrl); // file to encrypted.
        File encryptedFile = new File("file:///storage/emulated/0/Download/" + inputFile.getName()); // write encrypted
                                                                                                     // data to this
                                                                                                     // file.
        if (!encryptedFile.exists())
            encryptedFile.createNewFile();
        FileInputStream fileInpStream = new FileInputStream(inputFile);
        FileOutputStream fileOpStream = new FileOutputStream(encryptedFile);
        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        CipherInputStream cipherInpStream = new CipherInputStream(fileInpStream, cipher);
        while ((read = cipherInpStream.read()) != -1) {
            fileOpStream.write((char) read);
            fileOpStream.flush();
        }
        fileOpStream.close();
        return encryptedFile.getAbsolutePath();
    }

    /**
     * @param password       The password
     * @param salt           The salt
     * @param iterationCount The iteration count
     * @param keyLength      The length of the derived key.
     * @return PBKDF2 secured key
     * @throws Exception https://docs.oracle.com/javase/8/docs/api/javax/crypto/spec/PBEKeySpec
     */
    private static byte[] generatePBKDF2(char[] password, byte[] salt, int iterationCount, int keyLength)
            throws Exception {
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
        KeySpec keySpec = new PBEKeySpec(password, salt, iterationCount, keyLength);
        SecretKey secretKey = secretKeyFactory.generateSecret(keySpec);
        return secretKey.getEncoded();
    }

    /**
     * This method used to generate the secure key based on the PBKDF2 algorithm
     *
     * @param password The password
     * @return SecureKey
     * @throws Exception
     */
    private static String generateSecureKey(String password) throws Exception {
        byte[] secureKeyInBytes = generatePBKDF2(password.toCharArray(), generateRandomSalt(), PBKDF2_ITERATION_COUNT,
                SECURE_KEY_LENGTH);
        return Hex.encodeHexString(secureKeyInBytes);
    }

    /**
     * This method used to generate the secure IV based on the PBKDF2 algorithm
     *
     * @param password The password
     * @return SecureIV
     * @throws Exception
     */
    private static String generateSecureIV(String password) throws Exception {
        byte[] secureIVInBytes = generatePBKDF2(password.toCharArray(), generateRandomSalt(), PBKDF2_ITERATION_COUNT,
                SECURE_IV_LENGTH);
        return Hex.encodeHexString(secureIVInBytes);
    }

    /**
     * This method used to generate the random salt
     *
     * @return salt
     */
    private static byte[] generateRandomSalt() {
        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);
        return salt;
    }
}
