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

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;

import java.math.BigInteger;
import java.security.SecureRandom;

/* IMPLEMENTATION ************************************************************/

/**
 * Wrapper class for a secp256k1 elliptic curve key pair.
 */
public class EllipticCurveKeyPair
{
    // Static Fields
    private static final SecureRandom s_secureRandom = new SecureRandom();

    // Instance fields.
    private final BigInteger m_private;
    private final byte[]     m_public;

    /**
     * Generates a fresh elliptic curve key pair.
     */
    public EllipticCurveKeyPair()
    {
        ECKeyPairGenerator        generator    = new ECKeyPairGenerator();
        ECKeyGenerationParameters keygenParams = new ECKeyGenerationParameters(EllipticCurveProvider.getDomain(), s_secureRandom);

        generator.init(keygenParams);

        AsymmetricCipherKeyPair keypair       = generator.generateKeyPair();
        ECPrivateKeyParameters  privateParams = (ECPrivateKeyParameters) keypair.getPrivate();
        ECPublicKeyParameters   publicParams  = (ECPublicKeyParameters) keypair.getPublic();

        m_private = privateParams.getD();
        m_public  = publicParams.getQ().getEncoded(true);
    }

    /**
     * Generates an elliptic curve key pair from the private key.
     *
     * @param key The private key.
     */
    public EllipticCurveKeyPair(BigInteger key)
    {
        m_private = key;
        m_public  = derivePublicKey(key);
    }

    /**
     * Gets the public key component.
     *
     * @return The public key.
     */
    public byte[] getPublicKey()
    {
        return m_public;
    }

    /**
     * Gets the private key component.
     *
     * @return The private key.
     */
    public BigInteger getPrivateKey()
    {
        return m_private;
    }

    /**
     * Derives a public key from the given private key.
     *
     * @param key The private key.
     *
     * @return The public key.
     */
    private static byte[] derivePublicKey(BigInteger key)
    {
        return EllipticCurveProvider.getDomain().getG().multiply(key).getEncoded(true);
    }
}