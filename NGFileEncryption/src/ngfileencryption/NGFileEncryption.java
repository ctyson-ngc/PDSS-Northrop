/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package ngfileencryption;

import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Clint-PC
 */
public class NGFileEncryption {
    
    private static final File DESKTOP =
                                        new File(System.getProperty("user.home") + "/Desktop");
    private static final File BASE_PDF = new File(DESKTOP, "TESTPDF.pdf");
    private static String IV = "IV_VALUE_16_BYTE"; 
    private static String PASSWORD = "PASSWORD_VALUE"; 
    private static String SALT = "SALT_VALUE";
    
    public static byte[] encryptAndEncode(byte[] raw) {
        try {
            Cipher c = getCipher(Cipher.ENCRYPT_MODE);           
            byte[] encryptedVal = c.doFinal(raw);            
            byte[] s = Base64.getEncoder().encode(encryptedVal);            
            return s;
        } catch (Throwable t) {
            throw new RuntimeException(t);
        }
    }
    
    public static byte[] decodeAndDecrypt(byte[] encrypted) throws Exception {
        byte[] decodedValue = Base64.getDecoder().decode(encrypted);
        int length = decodedValue.length;
        Cipher c = getCipher(Cipher.DECRYPT_MODE);
        byte[] decValue = c.doFinal(decodedValue);
        return decValue;
    }
    
    private static String getString(byte[] bytes) throws UnsupportedEncodingException {
        return new String(bytes, "UTF-8");
    }
    
    private static byte[] getBytes(String str) throws UnsupportedEncodingException {
        return str.getBytes("UTF-8");
    }
    
    private static Cipher getCipher(int mode) throws Exception {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] iv = new byte[c.getBlockSize()];
                //getBytes(IV);
        c.init(mode, generateKey(), new IvParameterSpec(iv));
        return c;
    }
    
    private static Key generateKey() throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        char[] password = PASSWORD.toCharArray();
        byte[] salt = getBytes(SALT);
 
        KeySpec spec = new PBEKeySpec(password, salt, 65536, 128);
        SecretKey tmp = factory.generateSecret(spec);
        byte[] encoded = tmp.getEncoded();
        return new SecretKeySpec(encoded, "AES");
    }
    private static byte[] readFile(File file) {
            byte[] content = null;
            InputStream is;
            try {
                    is = new FileInputStream(file);
                    BufferedInputStream vf = new BufferedInputStream(is);
                    content = new byte[(file.length() <= Integer.MAX_VALUE)
                                                    ? (int) file.length() : Integer.MAX_VALUE];
//			content = new byte[is.available()];

                    System.out.printf("file.length() : %d\nis.available() : %d",
                                                    file.length(), is.available());

                    vf.read(content);
                    is.close();
            } catch (FileNotFoundException ex) {
                    Logger.getLogger(NGFileEncryption.class.getName()).log(Level.SEVERE, null, ex);
            } catch (IOException ex) {
                    Logger.getLogger(NGFileEncryption.class.getName()).log(Level.SEVERE, null, ex);
            }
            return content;
    }
    
    public static void saveFile(byte[] bytes, File file) throws IOException {
            BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(file));
            bos.write(bytes);
            bos.flush();
            bos.close();
    }
    

    
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws Exception {
//        NGFileEncryption ngclass = new NGFileEncryption();
//        String encrypted = ngclass.encryptAndEncode("First test works during furlough. Yay!");
//        System.out.println(encrypted);
//        String decrypted = ngclass.decodeAndDecrypt(encrypted);
//        System.out.println(decrypted);
         byte[] content = readFile(BASE_PDF);
         System.out.println("ORIGINAL: " + new String(content).substring(0, 8));
         byte[] encrypted = encryptAndEncode(content);
         System.out.println("ENCRYPTED: " + new String(encrypted).substring(0, 8));
         File encryptedFile = new File(DESKTOP, "EncryptedPDF.pdf");
         saveFile(encrypted, encryptedFile);
         content = readFile(encryptedFile);
         
          byte[] decrypted = decodeAndDecrypt(content);
          System.out.println("DECRYPTED: " + new String(decrypted).substring(0, 8));
          File decryptedFile = new File(DESKTOP, "DecryptedPDF.pdf");
          saveFile(decrypted, decryptedFile);
         
        // TODO code application logic here
    }
    
   
    
}
