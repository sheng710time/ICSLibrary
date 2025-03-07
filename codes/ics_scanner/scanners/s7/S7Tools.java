package com.sia.icsdeviceidentifier.core.scanners.s7;

import java.math.BigInteger;

public class S7Tools {

    /**
     * 将byte数组转换为十六进制字符串并返回，会去掉空格
     * @param data 被转化数组
     * @return  十六进制字符串，且无空格
     */
    static String convertDataToHex(byte[] data) {
        StringBuilder hexData = new StringBuilder();
        for (byte b : data) {
            hexData.append(String.format("%02X ", b));
        }
        return hexData.toString().replaceAll(" ", "");
    }

    /**
     * 输出十六进制数据字符串，每两个字符之间加一个空格，用于控制台显示报文原始内容
     * @param hexData 十六进制报文
     */
    static void printHexData(String hexData) {
        System.out.println("SZL Data (Hex):");

        StringBuilder formattedHex = new StringBuilder();
        for (int i = 0; i < hexData.length(); i += 2) {
            // 从原始字符串中提取每两个字符
            if (i + 2 <= hexData.length()) {
                formattedHex.append(hexData.substring(i, i + 2));
            } else {
                // 如果字符串长度为奇数，处理最后一个字符
                formattedHex.append(hexData.substring(i, i + 1));
            }
            // 除了最后一组字符外，每两个字符后面加一个空格
            if (i + 2 < hexData.length()) {
                formattedHex.append(" ");
            }
        }
        System.out.println(formattedHex.toString()); // 输出格式化后的十六进制数据字符串
    }

    /**
     * 将字符串str从index位置切割为两部分，并返回切割后的两部分
     * @param str 被切割字符串
     * @param index 切割的起始位置，index将会属于第二部分
     * @return  一个长度为2的字符串数组，第一个元素为第一部分，第二个元素为第二部分
     */
    static String[] cutString(String str, int index){
        String part1 = str.substring(0, index);
        String part2 = str.substring(index);
        String[] result = {part1, part2};
        return result;
    }

    /**
     * 将szldata数据包根据每一个szl data tree的长度拆开为单个的data tree数据包，长度暂时为56，余下的部分会被舍弃
     * 并且通过调用identityHexData函数对每一个szl data tree进行解析
     * @param hexData 数据包
     * @return  一个二维字符串数组，每一个results[i]代表一个szl data tree, results[i][j]代表szl data tree中的第j个数据
     */
    static S7SZLReceiver[] cutHexDataIntoParts(String hexData) {
        if (hexData == null || hexData.isEmpty()) {
            return new S7SZLReceiver[]{new S7SZLReceiver("No data", "No data", "No data", "No data", "No data")};
        }
        S7SZLReceiver[] szlDataTrees = new S7SZLReceiver[4];
        int i = 0;

        // 切割数据
        while (true) {
            String[] cutted = cutString(hexData, 56);
            String dataTree = cutted[0];
            hexData = cutted[1];

            // 使用identityHexData解析每个data tree
            szlDataTrees[i] = identityHexData(dataTree);

            // 如果剩余长度不足56字符，终止循环
            if (hexData.length() < 56) {
                break;
            }
            i++;
        }

        return szlDataTrees;
    }

    /**
     * 将十六进制字符串转换为ASCII字符串并返回
     * @param hexStr 十六进制字符串
     * @return  ASCII字符串
     */
    public static String hexToAscii(String hexStr) {
        boolean allZeros = true;
        for (int i = 0; i < hexStr.length(); i++) {
            if (hexStr.charAt(i) != '0') {
                allZeros = false;
                break;
            }
        }
        // 如果全部由0组成，则直接返回null
        if (allZeros) {
            return null;
        }
        StringBuilder output = new StringBuilder("");
        for (int i = 0; i < hexStr.length(); i += 2) {
            String str = hexStr.substring(i, i + 2);
            int asciiValue = Integer.parseInt(str, 16);
            // 忽略非可打印字符和空字符
            if (asciiValue >= 32 && asciiValue <= 126) {
                output.append((char) asciiValue);
            }
        }
        return output.toString();
    }

    /**
     * 将十六进制字符串转换为十进制字符串并返回
     * @param hexStr 十六进制字符串
     * @return  十进制字符串
     */
    public static String hexToDecimalString(String hexStr) {
        // 使用BigInteger将十六进制字符串转换为十进制数
        BigInteger decimal = new BigInteger(hexStr, 16);
        // 将十进制数转换为字符串并返回
        return decimal.toString();
    }

    /**
     * 根据参数类型对参数值进行解析并返回
     * @param hexData 参数值
     * @param type 参数类型
     * @return  参数值的解析结果
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
     * 对每一个szl data tree进行解析，解析出每一个参数的值并返回
     * @param hexData szl data tree
     * @return  一个字符串数组，包含解析结果
     */
    static S7SZLReceiver identityHexData(String hexData) {
        // 切割Index
        String[] cutted = cutString(hexData, 4);
        String index = cutted[0];
        hexData = cutted[1];

        // 切割MLFB
        cutted = cutString(hexData, 40);
        String mlfb = cutted[0];
        hexData = cutted[1];

        // 切割BGTyp
        cutted = cutString(hexData, 4);
        String bgTyp = cutted[0];
        hexData = cutted[1];

        // 切割Ausbg
        cutted = cutString(hexData, 4);
        String ausbg = cutted[0];
        hexData = cutted[1];

        // 切割Ausbe
        cutted = cutString(hexData, 4);
        String ausbe = cutted[0];

        // 使用identityParameter解析每个字段
        String indexCode = identityParameter(index, 1);
        String mlfbCode = identityParameter(mlfb, 2);
        String bgTypCode = identityParameter(bgTyp, 3);
        String ausbgCode = identityParameter(ausbg, 4);
        String ausbeCode = identityParameter(ausbe, 5);

        // 创建S7SZLReceiver对象并返回
        return new S7SZLReceiver(indexCode, mlfbCode, bgTypCode, ausbgCode, ausbeCode);
    }

}
