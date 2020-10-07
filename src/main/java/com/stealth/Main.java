/*
 * Copyright (c) 2020 Angel Castillo.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.stealth;

/* IMPORTS *******************************************************************/

import com.stealth.security.EllipticCurveKeyPair;
import com.stealth.security.EllipticCurveProvider;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECPoint;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/* IMPLEMENTATION ************************************************************/

/**
 * Application main class.
 */
public class Main
{
    // Constants
    private final static char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
    
    // Static Fields
    private static final X9ECParameters     s_curve  = SECNamedCurves.getByName ("secp256k1");
    private static final ECDomainParameters s_domain = new ECDomainParameters(s_curve.getCurve(),
            s_curve.getG(),
            s_curve.getN(),
            s_curve.getH());

    /**
     * Application entry point.
     *
     * @param args Arguments.
     */
    public static void main(String[] args) throws InvalidKeyException, NoSuchAlgorithmException
    {
        /*
         * The receiver has two private/public key pairs (s, S) and (b, B), where S = s·G and B = b·G
         * are ‘scan public key’ and ‘spend public key’, respectively. Here G is the base point of an
         * elliptic curve group.
         */
        EllipticCurveKeyPair spendKey = new EllipticCurveKeyPair();
        EllipticCurveKeyPair scanKey  = new EllipticCurveKeyPair();

        // Provide to the sender both of our key-pairs public keys.
        BigInteger s = scanKey.getPrivateKey();
        ECPoint    S = s_domain.getCurve().decodePoint(scanKey.getPublicKey());
        BigInteger b = spendKey.getPrivateKey();
        ECPoint    B = s_domain.getCurve().decodePoint(spendKey.getPublicKey());

        // Sender then generates and ephemeral key pair and transmits it with the xt.:
        EllipticCurveKeyPair ephemeralKey = new EllipticCurveKeyPair();

        /*
         * The sender generates an ephemeral key pair (r, R), where R = r·G and transmits it with the transaction.
         */
        BigInteger r = ephemeralKey.getPrivateKey();
        ECPoint    R = s_domain.getCurve().decodePoint(ephemeralKey.getPublicKey());  //Transmit with transaction.

        /*
         * Both the sender and receiver can compute a shared secret c using the ECDH: c = H(r·s·G) = H(r·S) = H(s·R),
         * where H(·) is a cryptographic hash function.
         */

        // Sender: H(r·S)
        byte[] c = keyDerivationFunction(S.multiply(r).getEncoded(true));
        // Receiver: H(s·R)
        byte[] cReceiver = keyDerivationFunction(R.multiply(s).getEncoded(true));

        System.out.printf("Sender computed secret: %s\n", toHexString(c));
        System.out.printf("Receiver computed secret: %s\n", toHexString(cReceiver));

        /*
         * The sender uses c·G + B as the ephemeral destination address for sending the payment.
         */
        byte[] publicKey = s_domain.getG().multiply(new BigInteger(c)).add(B).getEncoded(true);
        System.out.printf("Sender computed ephemeral address: %s \n", toHexString(publicKey));

        /*
         * The receiver actively monitors the blockchain and checks whether some transaction has been sent to the
         * purported destination address c·G + B. The receiver can compute the same destination address in two different
         * ways, i.e., c·G + B = (c + b)·G. If there is a match, the payment can be spent using the corresponding
         * private key c + b. Note that the ephemeral private key c + b can only be computed by the receiver.
         */
        byte[] receiverPublicKey = s_domain.getG().multiply(new BigInteger(c).add(b)).getEncoded(true);
        System.out.printf("Receiver computed ephemeral address: %s \n", toHexString(receiverPublicKey));

        /*
         * The receiver can share the ‘scan private key’ s and the ‘spend public key’ B with an auditor/proxy server so
         * that those entities can scan the blockchain transaction on behalf of the receiver. However, they are not able
         * the compute the ephemeral private key c + b and spend the payment.
         *
         * The auditor/proxy server can compute the ephemeral public address as follows:
         */
        byte[] auditorC = keyDerivationFunction(R.multiply(s).getEncoded(true));
        System.out.printf("auditor/proxy computed secret: %s\n", toHexString(auditorC));

        /*
         * The auditor/proxy server now uses c·G + B to compute the ephemeral address.
         */
        byte[] auditorPublicKey = s_domain.getG().multiply(new BigInteger(auditorC)).add(B).getEncoded(true);
        System.out.printf("auditor/proxy server computed ephemeral address: %s \n", toHexString(auditorPublicKey));

        /*
         * Compute the ephemeral private key c + b and spend the payment.
         */
        BigInteger privateKey = new BigInteger(c).add(b);

        EllipticCurveKeyPair newKeys = new EllipticCurveKeyPair(privateKey);

        byte[] data = new byte[]{ 1, 2, 3, 4 };

        byte[] signature = EllipticCurveProvider.sign(data, newKeys.getPrivateKey());

        if (EllipticCurveProvider.verify(data, signature, publicKey))
        {
            System.out.println("verified!");
        }
        else
        {
            System.out.println("Did not verify!");
        }
    }

    /**
     * We use HmacSHA256 to derivative a new key.
     *
     * @param seed The seed of the new key.
     *
     * @return The new key.
     */
    public static byte[] keyDerivationFunction(byte[] seed) throws NoSuchAlgorithmException, InvalidKeyException
    {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(
                new byte[33]/* We use as a 'key' to the HMAC an array with all zeroes*/
                , "HmacSHA256"));

        return mac.doFinal(seed);
    }

    /**
     * Return the given byte array encoded as a hex string.
     *
     * @param bytes The data to be encoded.
     *
     * @return The encoded string
     */
    private static String toHexString(byte[] bytes)
    {
        char[] hexChars = new char[bytes.length * 2];

        for (int i = 0; i < bytes.length; ++i)
        {
            int value = bytes[i] & 0xFF;

            hexChars[i * 2]     = HEX_ARRAY[value >>> 4];
            hexChars[i * 2 + 1] = HEX_ARRAY[value & 0x0F];
        }

        return new String(hexChars);
    }
}