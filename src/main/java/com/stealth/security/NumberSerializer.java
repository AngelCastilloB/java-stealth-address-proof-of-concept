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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;

/* IMPLEMENTATION ************************************************************/

/**
 * This class serialize numbers into byte arrays.
 */
public class NumberSerializer
{
    /**
     * Serializes a long into a byte array.
     *
     * @param number The number to be serialized.
     *
     * @return The serialized number.
     */
    static public byte[] serialize(long number)
    {
        return ByteBuffer.allocate(Long.BYTES).putLong(number).array();
    }

    /**
     * Serializes a int into a byte array.
     *
     * @param number The number to be serialized.
     *
     * @return The serialized number.
     */
    static public byte[] serialize(int number)
    {
        return ByteBuffer.allocate(Integer.BYTES).putInt(number).array();
    }

    /**
     * Serializes a double into a byte array.
     *
     * @param number The number to be serialized.
     *
     * @return The serialized number.
     */
    static public byte[] serialize(double number)
    {
        return ByteBuffer.allocate(Double.BYTES).putDouble(number).array();
    }

    /**
     * Serializes a short into a byte array.
     *
     * @param number The number to be serialized.
     *
     * @return The serialized number.
     */
    static public byte[] serialize(short number)
    {
        return ByteBuffer.allocate(Short.BYTES).putShort(number).array();
    }

    /**
     * Serializes a BigInteger into a byte array.
     *
     * @param number The number to be serialized.
     *
     * @return The serialized number.
     */
    static public byte[] serialize(BigInteger number)
    {
        ByteArrayOutputStream data = new ByteArrayOutputStream();

        byte[] numberBytes = number.toByteArray();

        if (numberBytes.length > 8)
            throw new IllegalStateException("Number value is too big.");

        if (numberBytes.length < 8)
        {
            for (int i = 0; i < 8 - numberBytes.length; i++)
                data.write(0);
        }

        try
        {
            data.write(numberBytes);
        }
        catch (IOException e)
        {
            e.printStackTrace();
        }

        return data.toByteArray();
    }
}
