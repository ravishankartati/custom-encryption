package com.ravi.customencyptplugin;

import android.content.Context;
import android.os.Environment;
import android.Manifest;
import android.util.Log;
import android.content.pm.PackageManager;

import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CallbackContext;
import org.apache.cordova.PermissionHelper;
import org.apache.cordova.PluginResult;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Random;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * This class echoes a string called from JavaScript.
 */
public class CustomEncryptPlugin extends CordovaPlugin {

    private static final String LOG_TAG = "Encryption";
    private static final String ENCRYPT = "encrypt";
    private static final String DECRYPT = "decrypt";
    private static final String GENERATE_SECURE_KEY = "generateSecureKey";
    private static final String GENERATE_SECURE_IV = "generateSecureIV";

    public static final int ENC_REQ_CODE = 0;
    public static final int DEC_REQ_CODE = 1;
    public static final int PERMISSION_DENIED_ERROR = 2;
    public static final String WRITE = Manifest.permission.WRITE_EXTERNAL_STORAGE;

    private static final String CIPHER_TRANSFORMATION = "AES/CBC/PKCS5PADDING";
    private static final int PBKDF2_ITERATION_COUNT = 1001;
    private static final int PBKDF2_KEY_LENGTH = 256;
    private static final int SECURE_IV_LENGTH = 64;
    private static final int SECURE_KEY_LENGTH = 128;

    private static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA1";
    private static final String PBKDF2_SALT = "hY0wTq6xwc6ni01G";
    private static final Random RANDOM = new SecureRandom();

    private CallbackContext callbackContext;
    private String secureKey;
    private String iv;
    private String value;

    @Override
    public boolean execute(String action, JSONArray args, CallbackContext cb) throws JSONException {
        this.callbackContext = cb;
        this.secureKey = args.getString(0);
        this.iv = args.getString(1);
        this.value = args.getString(2);
        if (action.equals("ENCRYPT")) {
            cordova.getThreadPool().execute(new Runnable() {
                @Override
                public void run() {
                    android.os.Process.setThreadPriority(android.os.Process.THREAD_PRIORITY_BACKGROUND);
                    try {
                        callbackContext.success(encryptUsingFileStream(secureKey, value, iv));
                    } catch (Exception e) {
                        Log.d(LOG_TAG, action + e.getMessage());
                        callbackContext.error(action + e.getMessage());
                    }
                }
            });
            return true;
        } else if (action.equals("DECRYPT")) {
            cordova.getThreadPool().execute(new Runnable() {
                @Override
                public void run() {
                    android.os.Process.setThreadPriority(android.os.Process.THREAD_PRIORITY_BACKGROUND);
                    try {
                        callbackContext.success(decryptUsingFileStream(secureKey, value, iv));
                    } catch (Exception e) {
                        Log.d(LOG_TAG, action + e.getMessage());
                        callbackContext.error("F error ");
                    }
                }
            });
            return true;
        }
        return false;
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

    private String encryptUsingFileStream(String secureKey, String fileURL, String iv) {
        try {
            if (!hasWritePermission())
                getWritePermission(ENC_REQ_CODE);
            byte[] pbkdf2SecuredKey = generatePBKDF2(secureKey.toCharArray(), PBKDF2_SALT.getBytes("UTF-8"),
                    PBKDF2_ITERATION_COUNT, PBKDF2_KEY_LENGTH);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes("UTF-8"));
            SecretKeySpec secretKeySpec = new SecretKeySpec(pbkdf2SecuredKey, "AES");
            int read;
            File dirPath = Environment.getExternalStoragePublicDirectory("Download");
            File inputFile = new File(dirPath, fileURL); // file to encrypted.
            File encryptedFile = new File(dirPath, "enc" + fileURL); // write encrypted
            if (!encryptedFile.exists() && hasWritePermission())
                encryptedFile.createNewFile();
            FileInputStream fileInpStream = new FileInputStream(inputFile.getPath());
            FileOutputStream fileOpStream = new FileOutputStream(encryptedFile);
            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
            CipherInputStream cipherInpStream = new CipherInputStream(fileInpStream, cipher);
            while ((read = cipherInpStream.read()) != -1) {
                fileOpStream.write((char) read);
                fileOpStream.flush();
            }
            fileOpStream.close();
            Log.d(LOG_TAG, encryptedFile.getAbsolutePath());
            return encryptedFile.getAbsolutePath();

        } catch (Exception e) {
            Log.d(LOG_TAG, e.getMessage());
            return e.getMessage();
        }
    }

    /**
     * To perform the AES256 decryption using FileStream
     *
     * @param secureKey A 32 bytes string, which will used as input key for AES256
     *                  encryption
     * @param fileURL   Path to the file which will be encrypted.
     * @param iv        A 16 bytes string, which will used as initial vector for
     *                  AES256 encryption
     * @return File path of decrypted file.
     * @throws Exception
     */

    private String decryptUsingFileStream(String secureKey, String fileURL, String iv) {
        try {
            if (!hasWritePermission())
                getWritePermission(DEC_REQ_CODE);
            byte[] pbkdf2SecuredKey = generatePBKDF2(secureKey.toCharArray(), PBKDF2_SALT.getBytes("UTF-8"),
                    PBKDF2_ITERATION_COUNT, PBKDF2_KEY_LENGTH);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv.getBytes("UTF-8"));
            SecretKeySpec secretKeySpec = new SecretKeySpec(pbkdf2SecuredKey, "AES");
            int read;
            File dirPath = Environment.getExternalStoragePublicDirectory("Download");
            File encryptedFile = new File(dirPath, fileURL);
            File decryptedFile = new File(dirPath, "dec" + fileURL);
            if (!decryptedFile.exists() && hasWritePermission())
                decryptedFile.createNewFile();
            FileInputStream encryptedFileStream = new FileInputStream(encryptedFile.getPath());
            FileOutputStream outputFileStream = new FileOutputStream(decryptedFile);
            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
            CipherOutputStream cipherOpStream = new CipherOutputStream(outputFileStream, cipher);
            while ((read = encryptedFileStream.read()) != -1) {
                cipherOpStream.write((char) read);
                cipherOpStream.flush();
            }
            cipherOpStream.close();
            return decryptedFile.getAbsolutePath();

        } catch (Exception e) {
            Log.d(LOG_TAG, e.getMessage());
            return e.getMessage();
        }
    }

    private boolean hasWritePermission() {
        return cordova.hasPermission(WRITE);
    }

    private void getWritePermission(int requestCode) {
        cordova.requestPermission(this, requestCode, WRITE);
    }

    @Override
    public void onRequestPermissionResult(int requestCode, String[] permissions, int[] grantResults)
            throws JSONException {
        for (int r : grantResults) {
            if (r == PackageManager.PERMISSION_DENIED) {
                callbackContext.sendPluginResult(new PluginResult(PluginResult.Status.ERROR, PERMISSION_DENIED_ERROR));
                return;
            }
        }
        switch (requestCode) {
            case ENC_REQ_CODE:
                encryptUsingFileStream(secureKey, value, iv);
                break;
            case DEC_REQ_CODE:
                decryptUsingFileStream(secureKey, value, iv);
                break;
            default:
                Log.e(LOG_TAG, "request code not found");
        }
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
        return bytesToHexString(secureKeyInBytes);
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
        return bytesToHexString(secureIVInBytes);
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

    public static String bytesToHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }
}
