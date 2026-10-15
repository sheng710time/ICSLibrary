package org.icslibrary.core.scanners.s7;

import java.math.BigInteger;

public class S7Tools {

    /**
     * Convert a byte array to a hexadecimal string without spaces.
     *
     * @param data the byte array to convert
     * @return the hexadecimal string representation
     */
    static String convertDataToHex(byte[] data) {
        StringBuilder hexData = new StringBuilder();
        for (byte b : data) {
            hexData.append(String.format("%02X ", b));
        }
        return hexData.toString().replaceAll(" ", "");
    }

    /**
     * Print a hexadecimal string with a space between every two characters.
     *
     * @param hexData the hexadecimal payload
     */
    static void printHexData(String hexData) {
        System.out.println("SZL Data (Hex):");

        StringBuilder formattedHex = new StringBuilder();
        for (int i = 0; i < hexData.length(); i += 2) {
            // Extract two characters at a time from the original string.
            if (i + 2 <= hexData.length()) {
                formattedHex.append(hexData.substring(i, i + 2));
            } else {
                // Handle the last character when the string length is odd.
                formattedHex.append(hexData.substring(i, i + 1));
            }
            // Add a separating space between byte groups.
            if (i + 2 < hexData.length()) {
                formattedHex.append(" ");
            }
        }
        System.out.println(formattedHex); // Print the formatted hexadecimal string.
    }

    /**
     * Split a string into two parts at the given index.
     *
     * @param str the input string
     * @param index the split position; this index belongs to the second part
     * @return a two-element array containing the split parts
     */
    static String[] cutString(String str, int index){
        String part1 = str.substring(0, index);
        String part2 = str.substring(index);
        String[] result = {part1, part2};
        return result;
    }

    /**
     * Split the SZL payload into fixed-length data-tree records and parse each
     * record with {@link #identityHexData(String)}.
     *
     * @param hexData the hexadecimal SZL payload
     * @return parsed SZL records
     */
    static S7SZLReceiver[] cutHexDataIntoParts(String hexData) {
        if (hexData == null || hexData.isEmpty()) {
            return new S7SZLReceiver[]{new S7SZLReceiver("No data", "No data", "No data", "No data", "No data")};
        }
        S7SZLReceiver[] szlDataTrees = new S7SZLReceiver[4];
        int i = 0;

        // Split the payload into 56-character data-tree chunks.
        while (true) {
            String[] cutted = cutString(hexData, 56);
            String dataTree = cutted[0];
            hexData = cutted[1];

            // Parse each individual data tree.
            szlDataTrees[i] = identityHexData(dataTree);

            // Stop when the remaining payload is shorter than one record.
            if (hexData.length() < 56) {
                break;
            }
            i++;
        }

        return szlDataTrees;
    }

    /**
     * Convert a hexadecimal string to ASCII.
     *
     * @param hexStr the hexadecimal string
     * @return the ASCII string, or {@code null} if the input is all zeros
     */
    public static String hexToAscii(String hexStr) {
        boolean allZeros = true;
        for (int i = 0; i < hexStr.length(); i++) {
            if (hexStr.charAt(i) != '0') {
                allZeros = false;
                break;
            }
        }
        // Return null when the whole field is padding.
        if (allZeros) {
            return null;
        }
        StringBuilder output = new StringBuilder("");
        for (int i = 0; i < hexStr.length(); i += 2) {
            String str = hexStr.substring(i, i + 2);
            int asciiValue = Integer.parseInt(str, 16);
            // Ignore non-printable and null characters.
            if (asciiValue >= 32 && asciiValue <= 126) {
                output.append((char) asciiValue);
            }
        }
        return output.toString();
    }

    /**
     * Convert a hexadecimal string to a decimal string.
     *
     * @param hexStr the hexadecimal string
     * @return the decimal string representation
     */
    public static String hexToDecimalString(String hexStr) {
        // Convert the hexadecimal value with BigInteger.
        BigInteger decimal = new BigInteger(hexStr, 16);
        return decimal.toString();
    }

    /**
     * Decode one SZL field according to its expected type.
     *
     * @param hexData the field value
     * @param type the field type identifier
     * @return the decoded field value
     */
    static String identityParameter(String hexData, int type){
        String result = "";

        switch (type){
            case 1:
                switch (hexData){
                    case "0001":
                        result = "Identification of the module";
                        return result;
                    case "0006":
                        result = "Identification of the basic hardware";
                        return result;
                    case "0007":
                        result = "Identification of the basic firmware";
                        return result;
                    case "0081":
                        result = "Identification of the firmware-extension";
                        return result;
                    default:
                        result = "Unknown";
                        return result;
                }
            case 2:
                result = hexToAscii(hexData);
                return result;
            case 3:
                result = "0x" + hexData;
                return result;
            case 4:
                result = hexToDecimalString(hexData);
                return result;
            case 5:
                result = hexToDecimalString(hexData);
                return result;
        }


        result = "cannot identify the parameter type.";
        return result;
    }

    /**
     * Parse one SZL data-tree record into a structured receiver object.
     *
     * @param hexData one SZL data-tree record
     * @return the parsed receiver
     */
    static S7SZLReceiver identityHexData(String hexData) {
        // Extract Index.
        String[] cutted = cutString(hexData, 4);
        String index = cutted[0];
        hexData = cutted[1];

        // Extract MLFB.
        cutted = cutString(hexData, 40);
        String mlfb = cutted[0];
        hexData = cutted[1];

        // Extract BGTyp.
        cutted = cutString(hexData, 4);
        String bgTyp = cutted[0];
        hexData = cutted[1];

        // Extract Ausbg.
        cutted = cutString(hexData, 4);
        String ausbg = cutted[0];
        hexData = cutted[1];

        // Extract Ausbe.
        cutted = cutString(hexData, 4);
        String ausbe = cutted[0];

        // Decode each field.
        String indexCode = identityParameter(index, 1);
        String mlfbCode = identityParameter(mlfb, 2);
        String bgTypCode = identityParameter(bgTyp, 3);
        String ausbgCode = identityParameter(ausbg, 4);
        String ausbeCode = identityParameter(ausbe, 5);

        // Build the parsed receiver object.
        return new S7SZLReceiver(indexCode, mlfbCode, bgTypCode, ausbgCode, ausbeCode);
    }

}

