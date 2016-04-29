package dSikMandatoryProgramming;

import java.math.BigInteger;
import java.security.SecureRandom;

public class RSA {
	private static final BigInteger e = new BigInteger("3");
	private static final BigInteger zero = BigInteger.ZERO;
	private static final BigInteger one = BigInteger.ONE;
	private int k = 2000;
	private BigInteger d, n = null;

	public RSA(int bitLength) {
		this.k = bitLength;
		this.keyGen();
	}

	/*
	 * Decrypts the cipher.
	 * Returns c^d mod n.
	 */
	public BigInteger decrypt(BigInteger c) {
		return c.modPow(d, n);
	}

	/*
	 * Encrypts the message.
	 * Returns c = m^e mod n.
	 * Precondition: 0 <= m <= n-1.
	 */
	public BigInteger encrypt(BigInteger m) {
		return m.modPow(e, n);
	}

	/*
	 * First generates n (of bit length k), then calculates d based on the prime factors of n.
	 */
	private void keyGen() {
		// Bitlengths
		int bitLengthOfP = k / 2;
		int bitLengthOfQ = k - bitLengthOfP;
		
		// Variables
		BigInteger q, p, qMinusOne, pMinusOne;
		boolean bitLengthIsTooShort, isNotInvertible;
		
		// Choosing p and q
		do {
			p = rsaPrime(bitLengthOfP);
			q = rsaPrime(bitLengthOfQ);
			pMinusOne = p.subtract(one);
			qMinusOne = q.subtract(one);
			n = p.multiply(q);
			
			// (q-1)(p-1) should not be divisible by e
			isNotInvertible = qMinusOne.multiply(pMinusOne).mod(e).equals(zero);
			
			// bitlength of n should equal k
			bitLengthIsTooShort = n.bitLength() < k;
		} while (bitLengthIsTooShort || isNotInvertible);

		// Calculating d, where d = e^{-1} mod (p-1)(q-1)
		d = e.modInverse(qMinusOne.multiply(pMinusOne));
	}
	
	/*
	 * Generates a random prime p of specified bit length where gcd(p-1, e) = 1.
	 */
	private BigInteger rsaPrime(int bitLength) {
		BigInteger prime;
		SecureRandom random = new SecureRandom();
		do {
			prime = new BigInteger(bitLength, 100, random);
		} while (!(prime.subtract(one)).gcd(e).equals(one));
		return prime;
	}
	
	/*
	 * Automatically 'tests' this RSA-implementation on all strings given as arguments.
	 * Remember: The arguments have to be numbers.
	 */
	public static void main(String[] args) {
		// Only for testing; reads messages as input from program arguments
		RSA rsa = new RSA(2000);
		for (int i = 0; i < args.length; i++) {
			if (i == 0) System.out.println("\n\n\n=== POSTIVE TEST ENCRYPT/DECRYPT ===\n");
			System.out.println("================================");
			BigInteger message = new BigInteger(args[i]);
			BigInteger encryptedMessage = rsa.encrypt(message);
			BigInteger decryptedMessage = rsa.decrypt(encryptedMessage);
			System.out.println("message: " + message);
			System.out.println("encrypted message: " + encryptedMessage);
			System.out.println("decrypted message: " + decryptedMessage);
			if (message.equals(decryptedMessage)) System.out.println("correctly encrypted/decrypted");
			else System.out.println("failure in encryption/decryption");
			System.out.println("================================");
			if (i != args.length - 1) System.out.println("\n");
		}
	}
}