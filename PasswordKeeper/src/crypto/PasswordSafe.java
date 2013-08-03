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

	/**
	 * Returns the decryptedPassword
	 * @param password Saved encrypted password to decrypt
	 * @return
	 * @throws Exception
	 */
	private String decryptPassword(byte[] password) throws Exception {
		this.initKey();
		this.cipher = Cipher.getInstance(this.sAlgorithm);
		this.cipher.init(Cipher.DECRYPT_MODE, encryptionKey,
				new IvParameterSpec(this.sMasterPassword.getBytes()));
		String plaintext = new String(cipher.doFinal(password), "UTF-8");

		return plaintext;
	}

	/**
	 * Handles the selection choices from the menu
	 * @param selection
	 */
	private void doSelection(String selection) {
		switch (Integer.parseInt(selection)) {
		case 1:
			this.dialogSetKeyFile();
			break;
		case 2:
			this.dialogGetPassword();
			break;
		case 3:
			this.dialogSaveNewPassword();
			break;
		case 4:
			this.dialogShowSavedNames();
			break;
		case 5:
			this.dialogGenerateKey();
			break;
		case 6:
			this.dialogGenerateRandomPassword();
			break;
		case 7:
			this.dialogHelp();
			break;
		case 8:
			return;
		case 99:
			this.dialogDeletePassword();
			break;
		default:
			this.showMainMenu();
			break;
		}
	}

	/**
	 * Encrypts a password
	 * @param password The password to encrypt
	 * @return
	 * @throws Exception
	 */
	private byte[] encryptPassword(String password) throws Exception {
		this.initKey();
		this.cipher = Cipher.getInstance(this.sAlgorithm);
		this.cipher.init(Cipher.ENCRYPT_MODE, this.encryptionKey,
				new IvParameterSpec(this.sMasterPassword.getBytes()));
		return cipher.doFinal(password.getBytes("UTF-8"));
	}

	/**
	 * Generates a random secret key for use with encryption
	 * @return
	 * @throws Exception
	 */
	private SecretKey generateKey() throws Exception {
		SecretKeySpec secret = new SecretKeySpec(SecureRandom.getSeed(16),
				"AES");
		return secret;
	}

	/**
	 * Generates a 16 character random password
	 * @return
	 */
	private String generateRandomPassword() {
		java.util.Random r = new java.util.Random();
		char[] aPass = new char[16];
		for (int i = 0; i < 16; i++) {
			aPass[i] = (char) (r.nextInt(94) + 32);
		}

		return new String(aPass);
	}

	/**
	 * Reads the password hash from the data file
	 */
	@SuppressWarnings("unchecked")
	private void getPasswordHash() {
		java.io.File f = new java.io.File(this.sDataFile);
		if (this.hPasswords == null) {
			if (!f.exists())
				this.hPasswords = new java.util.HashMap<String, byte[]>();
			else {
				try {
					java.io.ObjectInputStream ois = new java.io.ObjectInputStream(
							new java.io.FileInputStream(f));
					this.hPasswords = ((java.util.HashMap<String, byte[]>) ois
							.readObject());
					ois.close();
				} catch (Exception ex) {
					ex.printStackTrace();
				}
			}
		}
	}

	/**
	 * Reads in the encryption key from a file
	 * @throws Exception
	 */
	private void initKey() throws Exception {
		java.io.FileInputStream f = new java.io.FileInputStream(this.sKeyFile);
		try {
			java.io.ObjectInputStream ois = new java.io.ObjectInputStream(f);
			this.encryptionKey = (SecretKeySpec) ois.readObject();
			ois.close();
		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}

	/**
	 * Displays the main selection menu
	 */
	private void showMainMenu() {
		System.out.print("\n\n");
		System.out.print("Password Keeper v" + _version + "\n");
		System.out.print("Please select an option:\n");
		if (this.bKeyFileSet)
			System.out.print("  [Key file is set]\n");
		else
			System.out.print("  [Key file not set]\n");
		System.out.print("  1. Set Key File\n");
		System.out.print("  2. Get Saved Password\n");
		System.out.print("  3. Save New Password\n");
		System.out.print("  4. Show all saved names\n");
		System.out.print("  5. Generate New Secret Key\n");
		System.out.print("  6. Generate Random Password\n");
		System.out.print("  7. Help\n");
		System.out.print("  8. Quit\n");
		System.out.print("  99. Delete Password\n\n");
		System.out.print("Selection: ");
		String selection = System.console().readLine();
		selection = selection.replaceAll("[^0-9]", "");
		if (selection.length() > 0) {
			doSelection(selection);
		}
	}

	/**
	 * Writes the password hashmap to a file
	 */
	private void writePasswordFile() {
		java.io.File f = new java.io.File(this.sDataFile);
		try {
			java.io.ObjectOutputStream oos = new java.io.ObjectOutputStream(
					new java.io.FileOutputStream(f));
			oos.writeObject(this.hPasswords);
			oos.flush();
			oos.close();
		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}

	/**
	 * Deletes a password by its name
	 */
	private void dialogDeletePassword() {
		this.getPasswordHash();
		System.out.print("\n\nEnter Name to Delete: ");
		String sName = System.console().readLine();
		if (this.hPasswords.containsKey(sName)) {
			this.hPasswords.remove(sName);
			this.writePasswordFile();
		}
	}

	/**
	 * Generates and saves a new secret key
	 */
	private void dialogGenerateKey() {
		System.out.print("\n\nGenerating new key...");
		SecretKey s;
		try {
			s = generateKey();
			System.out.print("Key generation complete\n\n");
			java.io.FileOutputStream fos = new java.io.FileOutputStream(
					this.sKeyFile);
			java.io.ObjectOutputStream oos = new java.io.ObjectOutputStream(fos);
			oos.writeObject(s);
			oos.flush();
			oos.close();
			System.console().readLine();
			this.showMainMenu();
		} catch (Exception ex) {
			ex.printStackTrace();
		}
	}

	/**
	 * The dialog used for generating a random password
	 */
	private void dialogGenerateRandomPassword() {
		this.getPasswordHash();
		System.out.print("\n\nEnter the Name of the Key: ");
		String sName = System.console().readLine();
		if (this.hPasswords.containsKey(sName)) {
			this.hPasswords.remove(sName);
		}
		try {
			this.hPasswords.put(sName,
					this.encryptPassword(this.generateRandomPassword()));
			this.writePasswordFile();
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		this.showMainMenu();
	}

	/**
	 * The dialog used for getting a master password
	 */
	public void dialogGetMasterPassword() {
		this.sMasterPassword = new String(System.console().readPassword(
				"\n\nPlease Enter Master Password: "));
		if (this.sMasterPassword.length() < 16)
			while (this.sMasterPassword.length() < 16) {
				this.sMasterPassword += "9";
			}
		if (this.sMasterPassword.length() > 16)
			this.sMasterPassword = this.sMasterPassword.substring(0, 15);
		this.showMainMenu();
	}

	/**
	 * The dialog used to retrieve a saved password
	 */
	private void dialogGetPassword() {
		System.out.print("\n\nEnter password to get: ");
		String sName = System.console().readLine();
		this.getPasswordHash();
		if (this.hPasswords.containsKey(sName)) {
			try {
				System.out.print("\n\nPassword is:"
						+ this.decryptPassword(this.hPasswords.get(sName)));
				System.console().readLine();
			} catch (Exception ex) {
				System.out.print("Unable to retrieve password");
			}
		}
		this.showMainMenu();
	}
	
	/**
	 * This shows the help dialog instructions
	 */
	public void dialogHelp(){
		System.out.print("\n\nThe password keeper uses a combination of a master password and a secret key file.\n");
		System.out.print("To get started you should have already been prompted for a master password. The next\n");
		System.out.print("step is to generate a new key file using option 5. By default the new key file is created\n");
		System.out.print("in the current directory as key.dat. If you leave the key.dat file in the current directory\n");
		System.out.print("the program will pick it up automatically. However to better secure your passwords you should\n");
		System.out.print("rename this file and store it on a separate media. If you have moved the key file then you\n");
		System.out.print("need to perform option 1 and give the program the path to the key file. Once the key file is\n");
		System.out.print("set you can begin saving, generating and retrieving passwords. The passwords are stored in a\n");
		System.out.print("file called data.dat in the local directory. Currently this file needs to reside with the\n");
		System.out.print("program in the same directory.\n");
		System.out.print("A master password and a key file go together. If you so choose you can create multiple key\n");
		System.out.print("files with different master passwords associated with them. All the passwords would still\n");
		System.out.print("reside inside the data.dat file but would could have different encryptions for each password.\n");
		System.out.print("The program would need to be restarted each time a different master password is desired.");
		System.console().readLine();
		this.showMainMenu();
	}

	/**
	 * Dialog used to manually input a new password to save
	 */
	private void dialogSaveNewPassword() {
		System.out.print("\n\nEnter a name for this password: ");
		String sName = System.console().readLine();
		System.out.print("\nEnter the password: ");
		String sPassword = System.console().readLine();
		this.getPasswordHash();
		try {
			this.hPasswords.put(sName, this.encryptPassword(sPassword));
			this.writePasswordFile();
		} catch (Exception ex) {
			ex.printStackTrace();
		}
		this.showMainMenu();
	}

	/**
	 * Shows all the saved names of the passwords in the file
	 */
	private void dialogShowSavedNames() {
		this.getPasswordHash();
		Set<String> s = this.hPasswords.keySet();
		java.util.Iterator<String> i = s.iterator();
		int iCount = 0;
		while (i.hasNext()) {
			String sName = i.next();
			System.out.print("\n" + sName);
			iCount++;
			if (iCount == 20) {
				iCount = 0;
				System.out.print("\n\nPress Enter to continue");
				System.console().readLine();
			}
		}
		System.out.print("\n");
		System.console().readLine();
		this.showMainMenu();
	}

	/**
	 * Associates the secret key file with the program
	 */
	private void dialogSetKeyFile() {
		System.out.print("\n\nEnter Key File Path and Name: ");
		this.sKeyFile = System.console().readLine();
		java.io.File f = new java.io.File(this.sKeyFile);
		if (f.exists())
			this.bKeyFileSet = true;
		this.showMainMenu();
	}

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		PasswordSafe s = new PasswordSafe();
		s.dialogGetMasterPassword();
	}

}
