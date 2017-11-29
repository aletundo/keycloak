package org.keycloak.credential.hash;

import org.keycloak.credential.CredentialModel;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.UserCredentialModel;
import java.security.SecureRandom;
import java.security.MessageDigest;

public class MediaWikiBTypePasswordHashProvider implements PasswordHashProvider {

    private final String providerId;

    public MediaWikiBTypePasswordHashProvider(String providerId) {
        this.providerId = providerId;
    }
	
   
    @Override
    public void encode(String rawPassword, int iterations, CredentialModel credential) {
    
        byte[] salt = getSalt();
        String stringSalt = bytesToHexString(salt).substring(0, 8);
        String delimiter = getDelimiter();
        String encodedPassword = encode(rawPassword, delimiter, stringSalt);
        
        credential.setAlgorithm(providerId);
        credential.setType(UserCredentialModel.PASSWORD);
        credential.setValue(encodedPassword);
    }

    @Override
    public boolean verify(String rawPassword, CredentialModel credential) {
        String salt = extractSalt(credential.getValue());
        return encode(rawPassword, getDelimiter(), salt).equals(credential.getValue());
    }
    
     @Override
    public boolean policyCheck(PasswordPolicy policy, CredentialModel credential) {
        return providerId.equals(credential.getAlgorithm());
    }

    public void close() {
    }
    
    private String encode(String rawPassword, String delimiter, String salt) {
    	/*
    	 *  The B type password is composed by:
    	 *  - a colon and the capital letter B, followed by
    	 *  - a colon and a pseudo-random eight-digit hex salt, followed by
    	 *  - a colon and the md5 hash of a concatenation of:
    	 *  	- the eight-digit hex salt,
    	 *	- a dash ("-"), and
    	 *	- the md5 hash of the password
    	 *
    	 *	For example, if a user's password is "password,"
    	 *	the md5 hash of it is 5f4dcc3b5aa765d61d8327deb882cf99. 
    	 *	Let's say that the pseudo-random eight-digit hex salt generated 
    	 *	when the password column is created is 838c83e1.
    	 *	The value stored in the password column is:
    	 *	":B:838c83e1:" + md5("838c83e1-" + md5("password")) =
    	 *	":B:838c83e1:" + md5("838c83e1-5f4dcc3b5aa765d61d8327deb882cf99") =
    	 *	":B:838c83e1:e4ab7024509eef084cdabd03d8b2972c"

    	 */
        try {
            MessageDigest md5 = MessageDigest.getInstance("MD5");

            md5.update(rawPassword.getBytes());
            byte bytePwd[] = md5.digest();
            String hashedPwd = bytesToHexString(bytePwd);

            String saltDashHashedPwd = salt + "-" + hashedPwd;
            md5.update(saltDashHashedPwd.getBytes());
            byte[] byteSaltDashHashedPwd = md5.digest();
            
            String encodedPwd = delimiter + "B" + delimiter + salt + delimiter + bytesToHexString(byteSaltDashHashedPwd);
            
            if(encodedPwd.length() < 32){
            	throw new RuntimeException("Credential could not be encoded");
            }
            
            return encodedPwd;
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }
    
    private byte[] getSalt() {
        byte[] buffer = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(buffer);
        return buffer;
    }
    
    private String extractSalt(String value) {
        String[] valueItems = value.split(getDelimiter());
        return valueItems[2];
    }
    
    
    private String getDelimiter() {
    	return ":";
    }

    private static String bytesToHexString(byte[] bytes){
        StringBuilder sb = new StringBuilder();
        for(byte b : bytes){
            sb.append(String.format("%02x", b&0xff));
        }
        return sb.toString();
    }  

}
