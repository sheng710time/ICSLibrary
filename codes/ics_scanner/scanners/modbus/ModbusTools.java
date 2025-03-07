package com.sia.icsdeviceidentifier.core.scanners.modbus;

import com.intelligt.modbus.jlibmodbus.data.mei.ReadDeviceIdentificationInterface;
import com.intelligt.modbus.jlibmodbus.msg.base.mei.MEIReadDeviceIdentification;
import com.sia.icsdeviceidentifier.entity.fingerprintSpace.DeviceSignature;

/**
 * @Author: CSheng
 * @Version: 2.1.4
 * @Data: 2024/10/21 10:44
 */
public class ModbusTools {

    public static DeviceSignature parseModbusSignature (MEIReadDeviceIdentification deviceIdentification){
        if(deviceIdentification == null){
            return null;
        }

        DeviceSignature deviceSignature = new DeviceSignature();
        ReadDeviceIdentificationInterface.DataObject[] dataObjects = deviceIdentification.getObjects();
        for(int a=0; a<dataObjects.length; a++){
            StringBuilder asciiString = new StringBuilder();
            for (byte b : dataObjects[a].getValue()) {// 将字节数组转换为 ASCII 字符串
                char asciiChar = (char) (b & 0xFF); // 转换为无符号字符
                asciiString.append(asciiChar);
            }
            String objectValue =  asciiString.toString();
            switch (dataObjects[a].getId()){ //0: VendorName, 1: ProductCode, 2: MajorMinorRevision, 3: VendorUrl, 4: ProductName, 5: ModelName, 6: UserApplicationName, 7-255: others
                case 0:
                    deviceSignature.setVendor(objectValue);break;
                case 1:
                    deviceSignature.setProductCode(objectValue);break;
                case 2:
                    deviceSignature.setRevision(objectValue);break;
                case 4:
                    deviceSignature.setProductName(objectValue);break;
                case 5:
                    deviceSignature.setModelName(objectValue);break;
                default:
                    break;
            }
        }

        return deviceSignature;
    }


}
