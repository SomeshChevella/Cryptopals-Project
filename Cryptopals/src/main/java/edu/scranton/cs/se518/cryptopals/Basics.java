package edu.scranton.cs.se518.cryptopals;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.HexFormat;
import java.util.List;

public class Basics {
	static HexFormat h = HexFormat.of();
	static char c;
	static List<String> messagesOfShakespeare= new ArrayList<String>();
	static long[] characters = new long[65536];
	static double[] englishFrequency = new double[65536];

	/**
	 * Converts a String representing hexadecimal values into an array of bytes.
	 * <p>
	 * You will need to implement this functionality first since the units tests for
	 * all other challenges take their input as hexadecimal-encoded strings.
	 *
	 * @param hex A String containing hexadecimal digits.
	 * @return A byte array containing binary data decoded from the supplied String.
	 * @throws IllegalArgumentException if the input is not valid hexadecimal.
	 */
	public static byte[] decodeHex(String hex) {
		byte[] x = h.parseHex(hex);
		return x;
	}

	/**
	 * Convert hexadecimal-encoded data to Base64-encoded data. You can use any
	 * classes built into the Java runtime itself but do MUST NOT add any further
	 * dependencies to accomplish this task.
	 * <p>
	 * Set 1, <a href="https://cryptopals.com/sets/1/challenges/1">Challenge 1</a>
	 * of The Cryptopals Crypto Challenges
	 *
	 * @param hex A String containing hexadecimal digits.
	 * @return A String containing base64 data decoded from the supplied String.
	 */
	public static String hexToBase64(String hex) {
		return Base64.getEncoder().encodeToString(decodeHex(hex));
	}

	/**
	 * Takes two equal-length buffers and produces their XOR combination.
	 * <p>
	 * Set 1, <a href="https://cryptopals.com/sets/1/challenges/2">Challenge 2</a>
	 * of The Cryptopals Crypto Challenges
	 *
	 * @param first  A byte array to include in the XOR.
	 * @param second A byte array to include in the XOR.
	 * @return A byte array containing the fixed XOR of the two inputs.
	 */
	public static byte[] fixedXOR(byte[] first, byte[] second) {
		int length = first.length;
		byte[] xorByte = new byte[length];
		for (int i = 0; i < first.length; i++) {
			xorByte[i] = (byte) (first[i] ^ second[i]);
		}
		return xorByte;
	}

	/**
	 * Decrypts a message using the single-byte XOR cipher and the provided key.
	 * <p>
	 * Set 1, <a href="https://cryptopals.com/sets/1/challenges/3">Challenge 3</a>
	 * of The Cryptopals Crypto Challenges
	 *
	 * @param message A hexadecimal-encoded ciphertext.
	 * @param key     The single byte key to use to decrypt the message.
	 * @return The decrypted messages as a UTF-8 encoded String.
	 * @throws UnsupportedEncodingException 
	 */
	public static String decryptSingleByteXOR(String message, byte key)  {
		byte[] bytes = decodeHex(message);
		byte[] result = new byte[bytes.length];
		for (int i = 0; i < bytes.length; i++) {
			result[i] = (byte) (bytes[i] ^ key);
		} 
		return new String(result, StandardCharsets.UTF_8);	
	}

	/**
	 * Breaks the single-byte XOR cipher by identifying the "best" key.
	 * <p>
	 * Set 1, <a href="https://cryptopals.com/sets/1/challenges/3">Challenge 3</a>
	 * of The Cryptopals Crypto Challenges
	 *
	 * @param message A string containing the hexadecimal-encoded message to
	 *                decrypt.
	 * @return The single byte key identified to "best" decrypt the message.
	 * @throws IOException
	 * @throws URISyntaxException
	 */
	public static byte breakSingleByteXORCipher(String message) {
		double high = 0,current=0;
		byte result = 0;
		try {
			shakespeare();
			characters= scoreDataUsingArrays(messagesOfShakespeare);
			englishFrequency =calculateFrequency(characters);
			
			for(int i=0;i<256;i++) {
				byte key = (byte)i;
				String decodedString  = decryptSingleByteXOR(message,key);
				List<String> list =  new ArrayList<String>();
				list.add(0, decodedString);
				double[] givenStringFrequency;			
				givenStringFrequency = calculateFrequency(scoreDataUsingArrays(list));
				current= cosineSimilarity(englishFrequency, givenStringFrequency);
				if(current>high) {
					result=key;
					high=current;						
				}				
			}
			} catch (URISyntaxException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		return result;
	}
	/**
	 * Identifies the message most likely to have been encrypted with a single-byte
	 * XOR.
	 * <p>
	 * Set 1, <a href="https://cryptopals.com/sets/1/challenges/4">Challenge 4</a>
	 * of The Cryptopals Crypto Challenges
	 *
	 * @param messages A collection of messages to test for single-byte XOR
	 *                 encryption.
	 * @return The message most likely to have been encrypted with a single-byte
	 *         XOR.
	 */
	public static String detectSingleByteXORCipher(Collection<String> messages) {
		/*https://www.baeldung.com/java-convert-collection-arraylist*/
		ArrayList<String> collection=new ArrayList<String>(messages);
		String string="";
		for(int i=0;i<collection.size();i++) {
			byte resultKey=breakSingleByteXORCipher(collection.get(i));
			if(resultKey!=0) {
				string=collection.get(i);
			}
		}
		return string;
	}

	/**
	 * Encrypts the message using the repeating-key XOR cipher and the provided key.
	 * <p>
	 * Set 1, <a href="https://cryptopals.com/sets/1/challenges/5">Challenge 5</a>
	 * of The Cryptopals Crypto Challenges
	 *
	 * @param message A UTF-8 String containing the plaintext message to encrypt.
	 * @param key     A byte array containing the key to use to encrypt the message.
	 * @return A byte array containing the ciphertext after repeating-key XOR
	 *         encryption.
	 */
	public static byte[] repeatingKeyXOR(String message, byte[] key) {
		byte[] defaultBytes = message.getBytes();
		byte[] xorByte = new byte[defaultBytes.length];

		for (int i = 0, j = 0; i < defaultBytes.length && j < key.length; i++) {
			xorByte[i] = (byte) (defaultBytes[i] ^ key[j]);
			j++;
			if (j == 3)
				j = 0;
		}
		return xorByte;
	}
	/*
	 * The body of the method contains two line of code that is related to passing the source file
	 * is taken from the
	 * given method: testDetectSingleByteXORCipher() in BasicsTest.Java file.
	 */
	public static void shakespeare() throws URISyntaxException, IOException {
		Path resourcePath = Paths.get(Basics.class.getResource("/pg100.txt").toURI());
		messagesOfShakespeare = Files.readAllLines(resourcePath, StandardCharsets.UTF_8);
	}
	/* The method calculates the total occurrence of each character when an list of strings is given as an input*/
	public static long[] scoreDataUsingArrays(List<String> messages) {
		long[] characterCount = new long[65536];
		for (int i = 0; i < messages.size(); i++) {
			for (int j = 0; j < messages.get(i).length(); j++) {
				char c = messages.get(i).charAt(j);
				characterCount[c]++;
			}
		}
		return characterCount;
	}
	
	/* Calculates the frequency when an array of long type is given */
	public static double[] calculateFrequency(long[] characters) throws URISyntaxException, IOException {		
		int totalGivenCharacters = 0;
		double[] frequency = new double[65536];
		for (int i = 0; i < 65536; i++) {
			totalGivenCharacters += characters[i];
		}
		for (int k = 0; k < 65536; k++) {
			if (characters[k] != 0) {
				frequency[k] = (double) (characters[k] * 100) / totalGivenCharacters;
			}
		}
		return frequency;
	}
	
	/* https://stackoverflow.com/questions/520241/how-do-i-calculate-the-cosine-similarity-of-two-vectors
	 * The following method calculates the cosine similarity of two vectors that are passed as arguments*/
	public static double cosineSimilarity(double[] vectorA,double [] vectorB) {
		double dotProduct = 0.0;
	    double normA = 0.0;
	    double normB = 0.0;
	    for (int i = 0; i < vectorA.length; i++) {
	        dotProduct += vectorA[i] * vectorB[i];
	        normA += Math.pow(vectorA[i], 2);
	        normB += Math.pow(vectorB[i], 2);
	    }   
	    return dotProduct / (Math.sqrt(normA) * Math.sqrt(normB));		
	}
}
