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

package com.stealth.security;

/* IMPORTS *******************************************************************/

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequenceGenerator;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;

/* IMPLEMENTATION ************************************************************/

/**
 * Elliptic Curve signature provider.
 *
 * Signs and verify signatures using the secp256k1 Elliptic Curve.
 */
public class EllipticCurveProvider
{
    // Static Fields
    private static final X9ECParameters     s_curve  = SECNamedCurves.getByName ("secp256k1");
    private static final ECDomainParameters s_domain = new ECDomainParameters(s_curve.getCurve(),
                                                                              s_curve.getG(),
                                                                              s_curve.getN(),
                                                                              s_curve.getH());

    /**
     * Generates a signature for the given input data.
     *
     * @param data The data to be signed.
     *
     * @return The DER-encoded signature.
     */
    public static byte[] sign(byte[] data, BigInteger privateKey)
    {
        Sha256Hash sha256Hash = Sha256Digester.digest(data);

        ECDSASigner signer     = new ECDSASigner();
        ECPrivateKeyParameters privateKeyParameters = new ECPrivateKeyParameters(privateKey, s_domain);

        signer.init(true, privateKeyParameters);

        BigInteger[] signature = signer.generateSignature(sha256Hash.serialize());
        return encodeToDER(signature[0], signature[1]);
    }

    /**
     * Verifies given signature against a hash using the public key.
     *
     * @param data      Hash of the data to verify.
     * @param signature The DER-encoded signature.
     * @param publicKey The public key bytes to use.
     */
    public static boolean verify(byte[] data, byte[] signature, byte[] publicKey)
    {
        Sha256Hash sha256Hash = Sha256Digester.digest(data);

        BigInteger[] decodedSignature = decodeFromDer(signature);

        ECDSASigner           signer = new ECDSASigner();
        ECPublicKeyParameters params = new ECPublicKeyParameters(s_domain.getCurve().decodePoint(publicKey), s_domain);
        signer.init(false, params);

        BigInteger r = decodedSignature[0];
        BigInteger s = decodedSignature[1];

        return signer.verifySignature(sha256Hash.serialize(), r, s);
    }

    /**
     * Gets the secp256k1 elliptic curve domain parameters.
     *
     * @return The domain parameters.
     */
    public static ECDomainParameters getDomain()
    {
        return s_domain;
    }

    /**
     * Creates a digital signature from the DER-encoded values
     *
     * @param encodedSignature DER-encoded value.
     */
    private static BigInteger[] decodeFromDer(byte[] encodedSignature)
    {
        BigInteger[] signature = new BigInteger[2];

        try
        {
            try (ASN1InputStream decoder = new ASN1InputStream(encodedSignature))
            {
                DLSequence seq = (DLSequence)decoder.readObject();
                signature[0] = ((ASN1Integer)seq.getObjectAt(0)).getPositiveValue();
                signature[1] = ((ASN1Integer)seq.getObjectAt(1)).getPositiveValue();
            }

        }
        catch (ClassCastException | IOException exc)
        {
            throw new RuntimeException("Unable to decode signature", exc);
        }

        return signature;
    }


    /**
     * Encodes R and S as a DER-encoded byte array
     *
     * @return A byte array with the DER-encoded signature.
     */
    private static byte[] encodeToDER(BigInteger r, BigInteger s)
    {
        byte[] encodedBytes = null;

        try
        {
            try (ByteArrayOutputStream outStream = new ByteArrayOutputStream())
            {
                DERSequenceGenerator seq = new DERSequenceGenerator(outStream);
                seq.addObject(new ASN1Integer(r));
                seq.addObject(new ASN1Integer(s));
                seq.close();
                encodedBytes = outStream.toByteArray();
            }
        }
        catch (IOException exc)
        {
            throw new IllegalStateException("Unexpected IOException", exc);
        }

        return encodedBytes;
    }
}
