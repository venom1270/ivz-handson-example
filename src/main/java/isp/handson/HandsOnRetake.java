package isp.handson;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.xml.bind.DatatypeConverter;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

public class HandsOnRetake {
    public static void main(String[] args) throws Exception {

        final BlockingQueue<byte[]> alice2bob = new LinkedBlockingQueue<>();
        final BlockingQueue<byte[]> bob2alice = new LinkedBlockingQueue<>();

        final SecretKey sharedSecret = KeyGenerator.getInstance("AES").generateKey();
        final KeyPair signKey = KeyPairGenerator.getInstance("RSA").generateKeyPair();

        final Agent alice = new Agent("alice", null, null, null, "AES/GCM/NoPadding") {
            @Override
            public void execute() throws Exception {

                final String message = "The package is in room 102";
                System.out.println("[MESSAGE] " + message);


                final byte[] clearText = message.getBytes("UTF-8");
                System.out.println("[PT] " + DatatypeConverter.printHexBinary(clearText));

                //  STEP 2: Create a cipher, encrypt the PT and, optionally, extract cipher parameters (such as IV)
                final Cipher encryption = Cipher.getInstance(cipher);
                encryption.init(Cipher.ENCRYPT_MODE, sharedSecret);
                final byte[] cipherText = encryption.doFinal(clearText);

                // STEP 3: Print out cipher text (in HEX) [this is what an attacker would see]
                System.out.println("[CT] " + DatatypeConverter.printHexBinary(cipherText));


                alice2bob.put(cipherText);
                alice2bob.put(encryption.getIV());






                final byte[] ct = bob2alice.take();
                final byte[] signature = bob2alice.take();
                final byte[] IV = bob2alice.take();

                /*
                 * To verify the signature, we create another signature object
                 * and specify its algorithm
                 */
                final String signingAlgorithm =
                        "SHA256withRSA";
                final Signature verifier = Signature.getInstance(signingAlgorithm);
                System.out.println("[MESSAGE] " + new String(ct, "UTF-8"));
                /*
                 * We have to initialize in the verification mode. We only need
                 * to know public key of the signer.
                 */
                verifier.initVerify(signKey.getPublic());

                // Check whether the signature is valid
                verifier.update(ct);

                if (verifier.verify(signature)) {
                    System.out.println("Valid signature.");
                    System.out.println("[MESSAGE] " + new String(ct, "UTF-8"));

                    final Cipher decryption = Cipher.getInstance("AES/CTR/NoPadding");
                    decryption.init(Cipher.DECRYPT_MODE, sharedSecret, new IvParameterSpec(IV));
                    final byte[] decryptedText = decryption.doFinal(ct);
                    System.out.println("[PT] " + DatatypeConverter.printHexBinary(decryptedText));
                    System.out.println("[MESSAGE] " + new String(decryptedText, "UTF-8"));
                } else {
                    System.err.println("Invalid signature.");
                }


            }
        };

        final Agent bob = new Agent("bob", null, null, null, null) {
            @Override
            public void execute() throws Exception {

                final byte[] cipherText = alice2bob.take();
                final byte[] IV = alice2bob.take();


                final Cipher decryption = Cipher.getInstance("AES/GCM/NoPadding");
                decryption.init(Cipher.DECRYPT_MODE, sharedSecret, new GCMParameterSpec(128, IV));
                final byte[] decryptedText = decryption.doFinal(cipherText);
                System.out.println("[PT] " + DatatypeConverter.printHexBinary(decryptedText));
                // STEP 5: Create a string from a byte aray
                System.out.println("[MESSAGE] " + new String(decryptedText, "UTF-8"));


                // ACK


                final String message = "Acknowledged";
                final byte[] clearText = message.getBytes("UTF-8");
                System.out.println("[PT] " + DatatypeConverter.printHexBinary(clearText));

                //  STEP 2: Create a cipher, encrypt the PT and, optionally, extract cipher parameters (such as IV)
                final Cipher encryption = Cipher.getInstance("AES/CTR/NoPadding");
                encryption.init(Cipher.ENCRYPT_MODE, sharedSecret);
                final byte[] ct = encryption.doFinal(clearText);

                // STEP 3: Print out cipher text (in HEX) [this is what an attacker would see]
                System.out.println("[CT] " + DatatypeConverter.printHexBinary(cipherText));


                final String signingAlgorithm =
                        "SHA256withRSA";
                // "SHA256withDSA";
                //"SHA256withECDSA";
                // "RSA";
                // "EC";

                final Signature signer = Signature.getInstance(signingAlgorithm);

                /*
                 * We initialize the signature object with
                 * - Operation modes (SIGN) and
                 * - provides appropriate ***Private*** Key
                 */
                signer.initSign(signKey.getPrivate());


                // Finally, we load the document into the signature object and sign it
                signer.update(ct);
                final byte[] signature = signer.sign();
                System.out.println("Signature: " + DatatypeConverter.printHexBinary(signature));



                //POSLJEMO CT
                //SIGNAMTURE POSEBI
                //IV POSEBI

                bob2alice.put(ct);
                bob2alice.put(signature);
                bob2alice.put(encryption.getIV());


            }
        };

        alice.start();
        bob.start();
    }
}
