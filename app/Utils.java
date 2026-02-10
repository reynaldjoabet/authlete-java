
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.Authenticator;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.PasswordAuthentication;
import java.net.Proxy;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Properties;
import java.util.Scanner;
import java.util.Map;
import java.util.TreeMap;
import java.util.UUID;
import java.util.jar.Manifest;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.persistence.EntityManager;
import play.libs.typedmap.TypedKey;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
//import org.apache.commons.io.IOUtils;

public class Utils {

    protected static final TypedKey<Map<String, Object>> PAC4J_REQUEST_ATTRIBUTES = TypedKey.create("pac4jRequestAttributes");
	private static String INPUT = "Unvalidated Input";
	private static String SERVER = "Server Misconfiguration";
	private static String CRYPTO = "Weak Cryptography";
	private static String DATAEX = "Data Exposure";
	private static String ACCESS = "Broken Access Control and Session Management";
	private static String PUBLIC = "Publicly Known Vulnerability";
	private static String OUTDATED = "Outdated Libraries and Components";
	private static String UNKNOWN = "Uncategorized";



	public static String sanitizeMongo(String input) {
		return input.replaceAll("[\"'{}:]", "");
	}

	public static boolean checkEmail(String email) {
		String emailRegex = "[A-Z0-9a-z._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,6}";
		Matcher match = Pattern.compile(emailRegex).matcher(email);
		return match.matches();

	}


	public static String decryptPassword(String password) {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			String secret = System.getenv("FACTION_SECRET_KEY");
			byte[] hash = md.digest(secret.getBytes());
			char[] b64hash = Base64.encodeBase64String(hash).toCharArray();

			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
			KeySpec spec = new PBEKeySpec(b64hash, "f04ce910-bedb-4d8f-a023-4d2441dc0fba".getBytes(), 65536, 256);
			SecretKey tmp = factory.generateSecret(spec);
			SecretKey SecKey = new SecretKeySpec(tmp.getEncoded(), "AES");

			Cipher AesCipher = Cipher.getInstance("AES");
			AesCipher.init(Cipher.DECRYPT_MODE, SecKey);
			byte[] cypherText = Base64.decodeBase64(password);
			byte[] bytePlainText = AesCipher.doFinal(cypherText);
			return new String(bytePlainText);

		} catch (Exception ex) {
			return "";
		}

	}
	public static byte [] decryptBytes(String data) {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			String secret = System.getenv("FACTION_SECRET_KEY");
			byte[] hash = md.digest(secret.getBytes());
			char[] b64hash = Base64.encodeBase64String(hash).toCharArray();

			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
			KeySpec spec = new PBEKeySpec(b64hash, "f04ce910-bedb-4d8f-a023-4d2441dc0fba".getBytes(), 65536, 256);
			SecretKey tmp = factory.generateSecret(spec);
			SecretKey SecKey = new SecretKeySpec(tmp.getEncoded(), "AES");

			Cipher AesCipher = Cipher.getInstance("AES");
			AesCipher.init(Cipher.DECRYPT_MODE, SecKey);
			byte[] cypherText = Base64.decodeBase64(data);
			byte[] bytePlainText = AesCipher.doFinal(cypherText);
			return bytePlainText;

		} catch (Exception ex) {
			System.out.println(ex);
			return null;
		}

	}
	
	public static String md5hash(String data) {
		try {
			MessageDigest md;
			md = MessageDigest.getInstance("md5");
			byte[] hash = md.digest(data.getBytes());
			return Hex.encodeHexString( hash );
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
	}
	public static String md5hash(byte [] data) {
		try {
			MessageDigest md;
			md = MessageDigest.getInstance("md5");
			byte[] hash = md.digest(data);
			return Hex.encodeHexString( hash );
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
	}

	public static String encryptPassword(String password) {
		try {

			MessageDigest md = MessageDigest.getInstance("SHA-256");
			String secret = System.getenv("FACTION_SECRET_KEY");
			byte[] hash = md.digest(secret.getBytes());
			char[] b64hash = Base64.encodeBase64String(hash).toCharArray();

			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
			KeySpec spec = new PBEKeySpec(b64hash, "f04ce910-bedb-4d8f-a023-4d2441dc0fba".getBytes(), 65536, 256);
			SecretKey tmp = factory.generateSecret(spec);
			SecretKey SecKey = new SecretKeySpec(tmp.getEncoded(), "AES");

			Cipher AesCipher = Cipher.getInstance("AES");

			byte[] byteText = password.getBytes();

			AesCipher.init(Cipher.ENCRYPT_MODE, SecKey);
			byte[] byteCipherText = AesCipher.doFinal(byteText);

			return Base64.encodeBase64String(byteCipherText);

		} catch (Exception Ex) {
			Ex.printStackTrace();
			return null;
		}

	}
	public static String encryptBytes(byte [] data) {
		try {

			MessageDigest md = MessageDigest.getInstance("SHA-256");
			String secret = System.getenv("FACTION_SECRET_KEY");
			byte[] hash = md.digest(secret.getBytes());
			char[] b64hash = Base64.encodeBase64String(hash).toCharArray();

			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
			KeySpec spec = new PBEKeySpec(b64hash, "f04ce910-bedb-4d8f-a023-4d2441dc0fba".getBytes(), 65536, 256);
			SecretKey tmp = factory.generateSecret(spec);
			SecretKey SecKey = new SecretKeySpec(tmp.getEncoded(), "AES");

			Cipher AesCipher = Cipher.getInstance("AES");


			AesCipher.init(Cipher.ENCRYPT_MODE, SecKey);
			byte[] byteCipherText = AesCipher.doFinal(data);

			return Base64.encodeBase64String(byteCipherText);

		} catch (Exception Ex) {
			Ex.printStackTrace();
			return null;
		}

	}

	public static String generateICSFile(List<String> sendTo, String sendFrom, String Title, String Body) {
		UUID uid = UUID.randomUUID();
		String ics = "BEGIN:VCALENDAR\r\n";
		ics += "VERSION:2.0\r\n";
		ics += "PRODID:-//FuseSoftLLS/Faction//NONSGML v1.0//EN\r\n";
		ics += "BEGIN:VEVENT\r\n";
		ics += "CLASS:PUBLIC\r\n";
		ics += "UID:" + uid.toString() + "\r\n";
		for (String email : sendTo)
			ics += "ATTENDEE;mailto:" + email + "\r\n";
		ics += "X-ALT-DESC;FMTTYPE=text/html:<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2//EN\">\\n<HTML>\\n"
				+ "<BODY>\\n" + Body.replace("\r", "").replace("\n", "\\\\n") + "</BODY></HTML>\r\n";
		ics += "SUMMARY:" + Title + "\r\n";
		// ics+="DESCRIPTION:" + Body.replace("\r", "").replace("\n", "\\\\n") + "\r\n";
		ics += "BEGIN:VALARM\r\n";
		ics += "TRIGGER:-PT15M\r\n";
		ics += "ACTION:DISPLAY\r\n";
		ics += "DESCRIPTION:Reminder\r\n";
		ics += "END:VALARM\r\n";
		ics += "END:VEVENT\r\n";
		ics += "END:VCALENDAR\r\n";

		return ics;
	}

	
	public static String getEnv(String ENV_VAR) {
		String var = System.getenv(ENV_VAR);
		return var == null ? "" : var;
	}
	
	
	
	public static String addBadge(String title, String color, String icon) {
		return String.format("<small class=\"badge badge-%s\"><i class=\"fa %s\"></i>%s</small>",
				color,
				icon,
				title);
	}

}