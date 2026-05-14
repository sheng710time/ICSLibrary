package org.icslibrary.core.scanners.modbus;

import com.intelligt.modbus.jlibmodbus.data.mei.ReadDeviceIdentificationInterface;
import com.intelligt.modbus.jlibmodbus.msg.base.mei.MEIReadDeviceIdentification;
import org.icslibrary.entity.fingerprintSpace.DeviceSignature;

public class ModbusTools {

    public static DeviceSignature parseModbusSignature (MEIReadDeviceIdentification deviceIdentification){
        if(deviceIdentification == null){
            return null;
        }

        DeviceSignature deviceSignature = new DeviceSignature();
        ReadDeviceIdentificationInterface.DataObject[] dataObjects = deviceIdentification.getObjects();
        for(int a=0; a<dataObjects.length; a++){
            StringBuilder asciiString = new StringBuilder();
            for (byte b : dataObjects[a].getValue()) { // Convert the byte array to an ASCII string.
                char asciiChar = (char) (b & 0xFF); // Treat each byte as an unsigned character.
                asciiString.append(asciiChar);
            }
            String objectValue =  asciiString.toString();
            switch (dataObjects[a].getId()){ // 0: VendorName, 1: ProductCode, 2: MajorMinorRevision, 3: VendorUrl, 4: ProductName, 5: ModelName, 6: UserApplicationName, 7-255: others
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

