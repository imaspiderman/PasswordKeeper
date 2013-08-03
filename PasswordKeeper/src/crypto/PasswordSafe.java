package crypto;

import java.security.SecureRandom;
import java.util.Set;

import javax.crypto.*;

import javax.crypto.spec.*;

public class PasswordSafe {

	private Cipher cipher;
	private SecretKeySpec encryptionKey;
	private String _version = "1.0";
	private String sDataFile = "data.dat";
	private String sKeyFile = "key.dat";
	private boolean bKeyFileSet = false;
	private String sAlgorithm = "AES/CBC/PKCS5Padding";
	private java.util.HashMap<String, byte[]> hPasswords;
	private String sMasterPassword;
	
	public PasswordSafe() {
	}
	
	private String decryptPassword(byte[] password)throws Exception{
		this.initKey();
		this.cipher = Cipher.getInstance(this.sAlgorithm);
		this.cipher.init(Cipher.DECRYPT_MODE, encryptionKey, new IvParameterSpec(this.sMasterPassword.getBytes()));
		String plaintext = new String(cipher.doFinal(password), "UTF-8");
		
		return plaintext;
	}
	
	private byte[] encryptPassword(String password) throws Exception{
		this.initKey();		
		this.cipher = Cipher.getInstance(this.sAlgorithm);
		this.cipher.init(Cipher.ENCRYPT_MODE, this.encryptionKey, new IvParameterSpec(this.sMasterPassword.getBytes()));
		return cipher.doFinal(password.getBytes("UTF-8"));
	}
	
	private void initKey() throws Exception{
		java.io.FileInputStream f = new java.io.FileInputStream(this.sKeyFile);
		try{
			java.io.ObjectInputStream ois = new java.io.ObjectInputStream(f);
			this.encryptionKey = (SecretKeySpec)ois.readObject();
			ois.close();
		}catch(Exception ex){
			ex.printStackTrace();
		}
	}
	
	private SecretKey generateKey() throws Exception{	
		SecretKeySpec secret = new SecretKeySpec(SecureRandom.getSeed(16),"AES");
		return secret;
	}
	
	private void showMainMenu(){
		System.out.print("\n\n");
		System.out.print("Password Safe v" + _version + "\n");
		System.out.print("Please select an option:\n");
		if(this.bKeyFileSet) System.out.print("  [Key file is set]\n");
		else System.out.print("  [Key file not set]\n");
		System.out.print("  1. Set Key File\n");
		System.out.print("  2. Get Saved Password\n");
		System.out.print("  3. Save New Password\n");
		System.out.print("  4. Show all saved names\n");
		System.out.print("  5. Generate New Secret Key\n");
		System.out.print("  6. Generate Random Password\n");
		System.out.print("  7. Help\n");
		System.out.print("  8. Quit\n\n");
		System.out.print("Selection: ");
		String selection = System.console().readLine();
		selection = selection.replaceAll("[^0-9]", "");
		if(selection.length() > 0)
		{
			doSelection(selection);
		}
	}
	
	private void doSelection(String selection){
		switch(Integer.parseInt(selection)){
		case 1: this.dialogSetKeyFile();
			break;
		case 2: this.dialogGetPassword();
			break;
		case 3: this.dialogSaveNewPassword();
			break;
		case 4: this.dialogShowSavedNames();
			break;
		case 5: this.dialogGenerateKey();
			break;
		case 6: this.dialogGenerateRandomPassword();
			break;
		case 8: return;
		default: this.showMainMenu();
			break;
		}
	}
	
	private void dialogGenerateRandomPassword(){
		this.getPasswordHash();
		System.out.print("\n\nEnter the Name of the Key: ");
		String sName = System.console().readLine();
		if(this.hPasswords.containsKey(sName)){
			this.hPasswords.remove(sName);
		}
		try{
			this.hPasswords.put(sName, this.encryptPassword(this.generateRandomPassword()));
		}catch(Exception ex){
			ex.printStackTrace();
		}
		this.showMainMenu();
	}
	
	private String generateRandomPassword(){
		java.util.Random r = new java.util.Random();
		char[] aPass = new char[16];
		for(int i=0; i<16; i++){
			aPass[i] = (char)(r.nextInt(94) + 32);
		}
		
		return new String(aPass);
	}
	
	private void dialogShowSavedNames(){
		this.getPasswordHash();
		Set<String> s = this.hPasswords.keySet();
		java.util.Iterator<String> i = s.iterator();
		int iCount = 0;
		while(i.hasNext()){
			String sName = i.next();
			System.out.print("\n" + sName);
			iCount++;
			if(iCount == 20){
				iCount = 0;
				System.out.print("\n\nPress Enter to continue");
				System.console().readLine();
			}
		}
		System.out.print("\n");
		System.console().readLine();
		this.showMainMenu();
	}
	
	public void dialogGetMasterPassword(){		
		this.sMasterPassword = new String(System.console().readPassword("\n\nPlease Enter Master Password: "));
		if(this.sMasterPassword.length() < 16) while(this.sMasterPassword.length() < 16){this.sMasterPassword += "9";}
		if(this.sMasterPassword.length() > 16) this.sMasterPassword = this.sMasterPassword.substring(0,15);
		this.showMainMenu();
	}
	
	private void dialogGetPassword(){
		System.out.print("\n\nEnter password to get: ");
		String sName = System.console().readLine();
		this.getPasswordHash();
		if(this.hPasswords.containsKey(sName)){
			try{
				System.out.print("\n\nPassword is:" + this.decryptPassword(this.hPasswords.get(sName)));
				System.console().readLine();
			}catch(Exception ex){
				System.out.print("Unable to retrieve password");
			}
		}
		this.showMainMenu();
	}
	
	@SuppressWarnings("unchecked")
	private void getPasswordHash(){
		java.io.File f = new java.io.File(this.sDataFile);
		if(this.hPasswords == null){			
			if(!f.exists()) this.hPasswords = new java.util.HashMap<String, byte[]>();
			else {
				try{
					java.io.ObjectInputStream ois = new java.io.ObjectInputStream(new java.io.FileInputStream(f));
					this.hPasswords = (java.util.HashMap<String, byte[]>)ois.readObject();
					ois.close();
				}catch(Exception ex){
					ex.printStackTrace();
				}
			}			
		}
	}
	
	private void dialogSaveNewPassword(){
		System.out.print("\n\nEnter a name for this password: ");
		String sName = System.console().readLine();
		System.out.print("\nEnter the password: ");
		String sPassword = System.console().readLine();
		java.io.File f = new java.io.File(this.sDataFile);
		this.getPasswordHash();
		try{
			this.hPasswords.put(sName, this.encryptPassword(sPassword));
			java.io.ObjectOutputStream oos = new java.io.ObjectOutputStream(new java.io.FileOutputStream(f));
			oos.writeObject(this.hPasswords);
			oos.flush();
			oos.close();
		}catch(Exception ex){
			ex.printStackTrace();
		}
		this.showMainMenu();
	}
	
	private void dialogSetKeyFile(){
		System.out.print("\n\nEnter Key File Path and Name: ");
		this.sKeyFile = System.console().readLine();
		java.io.File f = new java.io.File(this.sKeyFile);
		if(f.exists()) this.bKeyFileSet = true;
		this.showMainMenu();
	}
	
	private void dialogGenerateKey(){
		System.out.print("\n\nGenerating new key...");
		SecretKey s;
		try{
			s = generateKey();
			System.out.print("Key generation complete\n\n");
			java.io.FileOutputStream fos = new java.io.FileOutputStream(this.sKeyFile);
			java.io.ObjectOutputStream oos = new java.io.ObjectOutputStream(fos);
			oos.writeObject(s);
			oos.flush();
			oos.close();
			System.console().readLine();
			this.showMainMenu();
		}catch(Exception ex){
			ex.printStackTrace();
		}
	}

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		PasswordSafe s = new PasswordSafe();
		s.dialogGetMasterPassword();
	}

}
