package dSik;

import org.junit.*;
import static org.junit.Assert.*;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.util.Random;

import static org.hamcrest.CoreMatchers.*;

public class TestRSA {
	private RSA rsa;

	/** Fixture for GUI testing. */
	@Before
	public void setUp() {
		// Test using 2000-bit RSA
		rsa = new RSA(2000);
	}
	
	@Test
	public void timeHashingOf10KbBigIntegerInBitsPerSecond() {
		System.out.println("\n=============================");
		BigInteger tenKbBigInteger = create10KbBigInteger();
		long startTime = System.nanoTime();
		BigInteger hash = RSA.sha256(tenKbBigInteger);
		long endTime = System.nanoTime();
		// Divide difference by 1000000 to go from ns to ms
		BigDecimal timeUsed = new BigDecimal((endTime - startTime)); 
		System.out.println("Resulting hash: "+hash);
		BigDecimal tenKbInBits = new BigDecimal(10000 * 8);
		BigDecimal timeInNsToHash1Bit = timeUsed.divide(tenKbInBits, 10, RoundingMode.HALF_UP);
		BigDecimal timeInMsToHash1Bit = timeInNsToHash1Bit.divide(new BigDecimal("1000000"), 10, RoundingMode.HALF_UP);
		BigDecimal oneThousand = new BigDecimal(1000);
		BigDecimal bitsPerSecond = oneThousand.divide(timeInMsToHash1Bit, 2, RoundingMode.HALF_UP);
		System.out.println("Bits hashed per second: "+bitsPerSecond);
		System.out.println("It took "+timeUsed+"ns to hash 10kb");
		System.out.println("=============================\n");
		
		// Not really a test, should just time the hash function
		assertThat("Not a test", true, is(true));
	}
	
	@Test
	public void timeCreatingRSASignatureUsing2000BitRSAKey() {
		System.out.println("\n=============================");
		BigInteger a1992BitBigInteger = create1992BitBigInteger();
		long startTime = System.nanoTime();
		BigInteger signedMessage = rsa.sign(a1992BitBigInteger);
		long endTime = System.nanoTime();
		// Divide difference by 1000000 to go from ns to ms
		BigDecimal timeUsed = new BigDecimal((endTime - startTime)); 
		System.out.println("Resulting hash: "+signedMessage);
		BigDecimal a1992Bit = new BigDecimal(1992);
		BigDecimal timeInNsToHashAndSign1Bit = timeUsed.divide(a1992Bit, 10, RoundingMode.HALF_UP);
		BigDecimal timeInMsToHashAndSign1Bit = timeInNsToHashAndSign1Bit.divide(new BigDecimal("1000000"), 10, RoundingMode.HALF_UP);
		BigDecimal oneThousand = new BigDecimal(1000);
		BigDecimal bitsPerSecond = oneThousand.divide(timeInMsToHashAndSign1Bit, 2, RoundingMode.HALF_UP);
		System.out.println("Bits hashed and signed per second: "+bitsPerSecond);
		System.out.println("It took "+timeUsed+"ns to hash and sign 1992 bits");
		System.out.println("=============================\n");
		
		// Not really a test, should just time the hash function
		assertThat("Not a test", true, is(true));
	}
	
	// Not used currently
	@SuppressWarnings("unused")
	private void create10kbFile() {
		try {
			String fileName = "10kbFile.txt";
			String pathToCurrentDirectory = System.getProperty("user.dir")+"/";
			File file = new File(pathToCurrentDirectory+fileName);
			
			// Create the file
			file.createNewFile();
			
			FileWriter fw;
			fw = new FileWriter(file.getAbsoluteFile());
			
			BufferedWriter bw = new BufferedWriter(fw);
			
			int tenThousand = 10000;
			Random random = new Random();
			
			// Write 10000 random numbers to the file = 10kb filesize (1 num = 1 byte)
			for (int i = 0; i < tenThousand; i++) {
				bw.write(""+random.nextInt(10));
			}
			bw.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	private static BigInteger create1992BitBigInteger() {
		String a1992BitStringOfRandomNums = "";
		Random random = new Random();
		// Write 1992/8 random numbers to the string (1 num = 8 bit, 1992/8 nums = 1992 bit)
		for (int i = 0; i < 1992/8; i++) {
			a1992BitStringOfRandomNums += random.nextInt(10);
		}
		System.out.println("Length of 1992 bits of random numbers: "+a1992BitStringOfRandomNums.length());
		return new BigInteger(a1992BitStringOfRandomNums);
	}
	
	private static BigInteger create10KbBigInteger() {
		String tenKbStringOfRandomNumbers = "";
		Random random = new Random();
		// Write 10000 random numbers to the string (1 num = 1 byte, 10K nums = 10k bytes)
		for (int i = 0; i < 10000; i++) {
			tenKbStringOfRandomNumbers += random.nextInt(10);
		}
		System.out.println("Length of 10kb random numbers: "+tenKbStringOfRandomNumbers.length());
		return new BigInteger(tenKbStringOfRandomNumbers);
	}
	
	@Test
	public void using1000BitRSAShouldGenerateModulusOfBitLength1000() {
		rsa = new RSA(1000);
		int bitLengthOfKey = rsa.getBitLengthOfModulus();
		assertThat("Bit length of key is 1000", bitLengthOfKey, is(1000));
	}
	
	@Test
	public void using2000BitRSAShouldGenerateModulusOfBitLength2000() {
		rsa = new RSA(2000);
		int bitLengthOfKey = rsa.getBitLengthOfModulus();
		assertThat("Bit length of key is 2000", bitLengthOfKey, is(2000));
	}
	
	@Test
	public void messageAndEcryptedMessageShouldBeDifferent() {
		BigInteger message = new BigInteger("3141592653589793238462643383279502884197169399375105820974944592307816406286");
		
		// Encrypt the message using RSA
		BigInteger encryptedMessage = rsa.encrypt(message);
		assertThat("The encrypted message differs from the original message", encryptedMessage.equals(message), is(false));
	}
	
	@Test
	public void messageAndEcryptedMessageShouldBeDifferent2() {
		BigInteger message = new BigInteger("112");
		
		// Encrypt the message using RSA
		BigInteger encryptedMessage = rsa.encrypt(message);
		assertThat("The encrypted message differs from the original message", encryptedMessage.equals(message), is(false));
	}
	
	@Test
	public void messageAndEcryptedMessageShouldBeDifferent3() {
		BigInteger message = new BigInteger("2");
		
		// Encrypt the message using RSA
		BigInteger encryptedMessage = rsa.encrypt(message);
		assertThat("The encrypted message differs from the original message", encryptedMessage.equals(message), is(false));
	}
	
	@Test
	public void shouldBeAbleToDecryptAnEncryptedMessage() {
		BigInteger message = new BigInteger("3141592653589793238462643383279502884197169399375105820974944592307816406286");
		
		// Encrypt the message using RSA
		BigInteger encryptedMessage = rsa.encrypt(message);
		
		// Decrypt the encrypted message using RSA
		BigInteger decryptedMessage = rsa.decrypt(encryptedMessage);
		
		// Check if the decrypted message matches the message, as it should
		assertThat("The decrypted message matches the original message", decryptedMessage, is(message));
	}
	
	@Test
	public void shouldBeAbleToDecryptAnEncryptedMessage2() {
		BigInteger message = new BigInteger("112");
		
		// Encrypt the message using RSA
		BigInteger encryptedMessage = rsa.encrypt(message);
		
		// Decrypt the encrypted message using RSA
		BigInteger decryptedMessage = rsa.decrypt(encryptedMessage);
		
		// Check if the decrypted message matches the message, as it should
		assertThat("The decrypted message matches the original message", decryptedMessage, is(message));
	}
	
	@Test
	public void shouldBeAbleToDecryptAnEncryptedMessage3() {
		BigInteger message = new BigInteger("2");
		
		// Encrypt the message using RSA
		BigInteger encryptedMessage = rsa.encrypt(message);
		
		// Decrypt the encrypted message using RSA
		BigInteger decryptedMessage = rsa.decrypt(encryptedMessage);
		
		// Check if the decrypted message matches the message, as it should
		assertThat("The decrypted message matches the original message", decryptedMessage, is(message));
	}
	
	@Test
	public void shouldVerifyACorrectlySignedMessage() {
		BigInteger message = new BigInteger("234234234");
		BigInteger signedMessage = rsa.sign(message);
		boolean verified = rsa.verify(message, signedMessage);
		assertThat("The signed message is verified", verified, is(true));
	}
	
	@Test
	public void shouldVerifyACorrectlySignedMessage2() {
		BigInteger message = new BigInteger("2");
		BigInteger signedMessage = rsa.sign(message);
		boolean verified = rsa.verify(message, signedMessage);
		assertThat("The signed message is verified", verified, is(true));
	}
	
	@Test
	public void shouldVerifyACorrectlySignedMessage3() {
		BigInteger message = new BigInteger("314159265358979323846264338327950288419716939937510582");
		BigInteger signedMessage = rsa.sign(message);
		boolean verified = rsa.verify(message, signedMessage);
		assertThat("The signed message is verified", verified, is(true));
	}
	
	@Test
	public void shouldNotVerifyAWronglySignedMessage() {
		BigInteger message = new BigInteger("314159265358979323846264338327950288419716939937510582");
		BigInteger fakeSignedMessage = rsa.sign(new BigInteger("98798798798787898798798798778696981"));
		boolean verified = rsa.verify(message, fakeSignedMessage);
		assertThat("The signed message is not verified", verified, is(false));
	}
	
	@Test
	public void shouldNotVerifyAWronglySignedMessage2() {
		BigInteger message = new BigInteger("112");
		BigInteger fakeSignedMessage = rsa.sign(new BigInteger("111"));
		boolean verified = rsa.verify(message, fakeSignedMessage);
		assertThat("The signed message is not verified", verified, is(false));
	}
	
	@Test
	public void shouldNotVerifyAWronglySignedMessage3() {
		BigInteger message = new BigInteger("34957329045868923487623984561092837409864435");
		BigInteger fakeSignedMessage = rsa.sign(new BigInteger("111"));
		boolean verified = rsa.verify(message, fakeSignedMessage);
		assertThat("The signed message is not verified", verified, is(false));
	}
	
	@Test
	public void shouldNotVerifyAWronglySignedMessage4() {
		BigInteger message = new BigInteger("111");
		BigInteger fakeSignedMessage = rsa.sign(new BigInteger("34957329045868923487623984561092837409864435"));
		boolean verified = rsa.verify(message, fakeSignedMessage);
		assertThat("The signed message is not verified", verified, is(false));
	}
}