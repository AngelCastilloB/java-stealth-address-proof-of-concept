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

/* IMPLEMENTATION ************************************************************/

import java.util.ArrayList;
import java.util.List;

/**
 * Utility class for data conventions.
 */
public class Convert
{
    private final static char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

    /**
     * Return the given byte array encoded as a hex string.
     *
     * @param bytes The data to be encoded.
     *
     * @return The encoded string
     */
    public static String toHexString(byte[] bytes)
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

    /**
     * Converts a hex string to byte array.
     *
     * @param hex The hex string.
     *
     * @return The byte array.
     */
    public static byte[] hexStringToByteArray(String hex)
    {
        byte[] b = new byte[hex.length() / 2];

        for (int i = 0; i < b.length; ++i)
        {
            int index = i * 2;

            int v = Integer.parseInt(hex.substring(index, index + 2), 16);

            b[i] = (byte) v;
        }

        return b;
    }

    /**
     * Converts a collection of byte[] to a collection of HEX string representation.
     *
     * @param bytes The collection of bytes.
     *
     * @return The new list of HEX string representation.
     */
    public static List<String> toHexStringArray(List<byte[]> bytes)
    {
        List<String> hexArray = new ArrayList<>();

        for (byte[] array: bytes)
            hexArray.add(String.format("\"%s\"", toHexString(array)));

        return hexArray;
    }

    /**
     * Tabs a string with white spaces. The tabs are added to all lines of the string.
     *
     * @param string The string to be tabbed.
     * @param tabs   The numbers of tabs to add.
     *
     * @return The enw tabbed string.
     */
    public static String toTabbedString(String string, int tabs)
    {
        String        lines[] = string.split("\\r?\\n", -1);
        StringBuilder result  = new StringBuilder();

        for (int i = 0; i < lines.length; ++i)
        {
            String line = lines[i];
            StringBuilder stringBuilder = new StringBuilder();

            for(int j = 0; j < tabs; ++j)
                stringBuilder.append(" ");

            stringBuilder.append(line);

            if (i < lines.length - 1)
                stringBuilder.append(System.lineSeparator());

            result.append(stringBuilder);
        }

        return result.toString();
    }

    /**
     * Converts the given array of objects to a JSON array like string.
     *
     * @param collection  The collection of items.
     * @param indentLevel The level of indentation.
     * @param <T>         The type of the collection item.
     *
     * @return The JSON array like string.
     */
    public static <T> String toJsonArrayLikeString(List<T> collection, int indentLevel)
    {
        StringBuilder builder = new StringBuilder();

        for(int j = 0; j < indentLevel; ++j)
            builder.append(" ");
        builder.append("[");

        builder.append(System.lineSeparator());

        for (int i = 0; i < collection.size(); ++i)
        {
            builder.append(Convert.toTabbedString(collection.get(i).toString(), indentLevel + 4));

            if (i < collection.size() - 1)
                builder.append(',');

            builder.append(System.lineSeparator());
        }

        for(int j = 0; j < indentLevel; ++j)
            builder.append(" ");
        builder.append("]");

        return builder.toString();
    }

    /**
     * Pads the given string to the left using the given pad character.
     *
     * @param originalString The string ot be padded.
     * @param length         The length of the final string (including padding).
     * @param padCharacter   The character to be use as padding.
     *
     * @return The new padded string.
     */
    public static String padLeft(String originalString, int length, char padCharacter)
    {
        StringBuilder sb = new StringBuilder();

        while (sb.length() + originalString.length() < length)
            sb.append(padCharacter);

        sb.append(originalString);

        return sb.toString();
    }
}
