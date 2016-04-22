package com.yenlo.identity.application.authenticator.custom;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Random;
import java.util.concurrent.TimeUnit;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * 
 * @author vitor
 *
 */
public class GoogleAuthenticatorClass {
	
	public static final String RNG_ALGORITHM = "com.warrenstrange.googleauth.rng.algorithm";

    /**
     * The system property to specify the random number generator provider to use.
     *
     * @since 0.5.0
     */
    public static final String RNG_ALGORITHM_PROVIDER = "com.warrenstrange.googleauth.rng.algorithmProvider";

    /**
     * The number of bits of a secret key in binary form. Since the Base32
     * encoding with 8 bit characters introduces an 160% overhead, we just need
     * 80 bits (10 bytes) to generate a 16 bytes Base32-encoded secret key.
     */
    private static final int SECRET_BITS = 80;

    /**
     * Number of scratch codes to generate during the key generation.
     * We are using Google's default of providing 5 scratch codes.
     */
    private static final int SCRATCH_CODES = 5;

    /**
     * Number of digits of a scratch code represented as a decimal integer.
     */
    private static final int SCRATCH_CODE_LENGTH = 8;

    /**
     * Modulus used to truncate the scratch code.
     */
    public static final int SCRATCH_CODE_MODULUS = (int) Math.pow(10, SCRATCH_CODE_LENGTH);

    /**
     * Magic number representing an invalid scratch code.
     */
    private static final int SCRATCH_CODE_INVALID = -1;

    /**
     * Length in bytes of each scratch code. We're using Google's default of
     * using 4 bytes per scratch code.
     */
    private static final int BYTES_PER_SCRATCH_CODE = 4;

    public static String secret = "A7SJOX45QFXTY4UA";
    
	private static final String HMAC_HASH_FUNCTION = "HmacSHA1";
	
	private static int codeDigits = 6;
	
	private static int keyModulus = (int) Math.pow(10, codeDigits);
	
	public String geraSecretKey() throws InvalidKeyException, NoSuchAlgorithmException {
		
		int secretSize = 80;
		int numOfScratchCodes = 5;
		int scratchCodeSie = 4;
		
		// Allocating the buffer
		byte[] buffer =  new byte[secretSize / 8 + numOfScratchCodes * scratchCodeSie];
		
		// Filling the buffer with random numbers.
		// Notice: you want to reuse the same random generator
		// while generating larger random number sequences.
		new Random().nextBytes(buffer);
		
		byte[] secretKey = Arrays.copyOf(buffer, secretSize / 8);
		
		Base32Vitor codec = new Base32Vitor();
		String generatedKey =  codec.encodeToString(secretKey);
		int validationCode = calculateCode(secretKey, 0);
		List<Integer> scratchCodes = calculateScratchCodes(buffer);
		
		return generatedKey;
	}

	
	 private int generateScratchCode() {
	        while (true) {
	            byte[] scratchCodeBuffer = new byte[BYTES_PER_SCRATCH_CODE];
	            new Random().nextBytes(scratchCodeBuffer);

	            int scratchCode = calculateScratchCode(scratchCodeBuffer);

	            if (scratchCode != SCRATCH_CODE_INVALID) {
	                return scratchCode;
	            }
	        }
	    }
	
	  private List<Integer> calculateScratchCodes(byte[] buffer) {
	        List<Integer> scratchCodes = new ArrayList<Integer>();

	        while (scratchCodes.size() < SCRATCH_CODES) {
	            byte[] scratchCodeBuffer = Arrays.copyOfRange(
	                    buffer,
	                    SECRET_BITS / 8 + BYTES_PER_SCRATCH_CODE * scratchCodes.size(),
	                    SECRET_BITS / 8 + BYTES_PER_SCRATCH_CODE * scratchCodes.size() + BYTES_PER_SCRATCH_CODE);

	            int scratchCode = calculateScratchCode(scratchCodeBuffer);

	            if (scratchCode != SCRATCH_CODE_INVALID) {
	                scratchCodes.add(scratchCode);
	            } else {
	                scratchCodes.add(generateScratchCode());
	            }
	        }

	        return scratchCodes;
	    }
	  
	  private int calculateScratchCode(byte[] scratchCodeBuffer) {
	        if (scratchCodeBuffer.length < BYTES_PER_SCRATCH_CODE) {
	            throw new IllegalArgumentException(
	                    String.format(
	                            "The provided random byte buffer is too small: %d.",
	                            scratchCodeBuffer.length));
	        }

	        int scratchCode = 0;

	        for (int i = 0; i < BYTES_PER_SCRATCH_CODE; ++i) {
	            scratchCode = (scratchCode << 8) + (scratchCodeBuffer[i] & 0xff);
	        }

	        scratchCode = (scratchCode & 0x7FFFFFFF) % SCRATCH_CODE_MODULUS;

	        // Accept the scratch code only if it has exactly
	        // SCRATCH_CODE_LENGTH digits.
	        if (validateScratchCode(scratchCode)) {
	            return scratchCode;
	        } else {
	            return SCRATCH_CODE_INVALID;
	        }
	    }
	  
	  
	  public boolean validateScratchCode(int scratchCode) {
	        return (scratchCode >= SCRATCH_CODE_MODULUS / 10);
	    }
	  
   public int calculateCode(byte[] key, long tm) {
        // Allocating an array of bytes to represent the specified instant
        // of time.
        byte[] data = new byte[8];
        long value = tm;

        // Converting the instant of time from the long representation to a
        // big-endian array of bytes (RFC4226, 5.2. Description).
        for (int i = 8; i-- > 0; value >>>= 8) {
            data[i] = (byte) value;
        }

        // Building the secret key specification for the HmacSHA1 algorithm.
        SecretKeySpec signKey = new SecretKeySpec(key, HMAC_HASH_FUNCTION);

        try {
            // Getting an HmacSHA1 algorithm implementation from the JCE.
            Mac mac = Mac.getInstance(HMAC_HASH_FUNCTION);

            // Initializing the MAC algorithm.
            try {
				mac.init(signKey);
			} catch (InvalidKeyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

            // Processing the instant of time and getting the encrypted data.
            byte[] hash = mac.doFinal(data);

            // Building the validation code performing dynamic truncation
            // (RFC4226, 5.3. Generating an HOTP value)
            int offset = hash[hash.length - 1] & 0xF;

            // We are using a long because Java hasn't got an unsigned integer type
            // and we need 32 unsigned bits).
            long truncatedHash = 0;

            for (int i = 0; i < 4; ++i) {
                truncatedHash <<= 8;

                // Java bytes are signed but we need an unsigned integer:
                // cleaning off all but the LSB.
                truncatedHash |= (hash[offset + i] & 0xFF);
            }

            // Clean bits higher than the 32nd (inclusive) and calculate the
            // module with the maximum validation code value.
            truncatedHash &= 0x7FFFFFFF;
            truncatedHash %= keyModulus;

            // Returning the validation code to the caller.
            return (int) truncatedHash;
        } catch (NoSuchAlgorithmException ex) {
            // Logging the exception.
//            log(Level.SEVERE, ex.getMessage(), ex);

            // We're not disclosing internal error details to our clients.
           return (Integer) null;
        }
    }
	
	public String getQRBarcodeURL(String user, String host, String secret) {
		String format = "https://www.google.com/chart?chs=200x200&chld=M%%7C0&cht=qr&chl=otpauth://totp/%s@%s%%3Fsecret%%3D%s";
		return String.format(format, user, host, secret);
	}

	boolean check_code(String secret, long code) throws NoSuchAlgorithmException, InvalidKeyException {
		
		long t = new Date().getTime() / TimeUnit.SECONDS.toMillis(30);
		
		Base32Vitor codec = new Base32Vitor();
		byte[] decodedKey = codec.decode(secret);

		// Window is used to check codes generated in the near past.
		// You can use this value to tune how far you're willing to go.
		int window = 3;
		for (int i = -window; i <= window; ++i) {
			long hash = verify_code(decodedKey, t + i);

			if (hash == code) {
				return true;
			}
		}

		// The validation code is invalid.
		return false;
	}

	private int verify_code(byte[] key, long t)
			throws NoSuchAlgorithmException, InvalidKeyException {
		byte[] data = new byte[8];
		long value = t;
		for (int i = 8; i-- > 0; value >>>= 8) {
			data[i] = (byte) value;
		}

		SecretKeySpec signKey = new SecretKeySpec(key, "HmacSHA1");
		Mac mac = Mac.getInstance("HmacSHA1");
		mac.init(signKey);
		byte[] hash = mac.doFinal(data);

		int offset = hash[20 - 1] & 0xF;

		// We're using a long because Java hasn't got unsigned int.
		long truncatedHash = 0;
		for (int i = 0; i < 4; ++i) {
			truncatedHash <<= 8;
			// We are dealing with signed bytes:
			// we just keep the first byte.
			truncatedHash |= (hash[offset + i] & 0xFF);
		}

		truncatedHash &= 0x7FFFFFFF;
		truncatedHash %= 1000000;

		return (int) truncatedHash;
	}
}
