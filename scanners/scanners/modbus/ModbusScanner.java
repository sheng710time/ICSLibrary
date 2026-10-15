package org.icslibrary.core.scanners.modbus;

import com.intelligt.modbus.jlibmodbus.Modbus;
import com.intelligt.modbus.jlibmodbus.exception.ModbusIOException;
import com.intelligt.modbus.jlibmodbus.exception.ModbusNumberException;
import com.intelligt.modbus.jlibmodbus.exception.ModbusProtocolException;
import com.intelligt.modbus.jlibmodbus.msg.base.mei.MEIReadDeviceIdentification;
import com.intelligt.modbus.jlibmodbus.msg.base.mei.ReadDeviceIdentificationCode;
import com.intelligt.modbus.jlibmodbus.tcp.TcpParameters;
import org.icslibrary.core.scanners.modbus.modbusmaster.MyModbusMaster;
import org.icslibrary.core.scanners.modbus.modbusmaster.MyModbusMasterFactory;
import org.icslibrary.entity.fingerprintSpace.DeviceSignature;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@Component
@Data
public class ModbusScanner {

    public Map<String, String> scan(String ipStr, int port) {  //TODO test
        // Configure TCP parameters for the target host.
        TcpParameters tcpParameters = new TcpParameters();
        InetAddress adress = null;
        try {
            adress = InetAddress.getByName(ipStr);
        } catch (UnknownHostException e) {
            throw new RuntimeException(e);
        }
        tcpParameters.setHost(adress);
        tcpParameters.setKeepAlive(false); // Use short-lived connections.
        tcpParameters.setPort(port);

        MyModbusMaster master = MyModbusMasterFactory.createModbusMasterTCP(tcpParameters);
        Modbus.setAutoIncrementTransactionId(true);
        master.setResponseTimeout(5000); // default 1000 [ms]

        Map<String, String> resultMap = new HashMap<>();
        try {
            if (!master.isConnected()) {
                master.connect(); // Open the TCP connection on demand.
            }

            int serverAddress = 1; // Common Unit Identifier used by the scanner.
            int objectId = 0; // Start from object 0 to request the full device-identification block.
            MEIReadDeviceIdentification deviceIdentification = master.readDeviceIdentification(serverAddress, objectId, ReadDeviceIdentificationCode.REGULAR_STREAM_ACCESS);
            DeviceSignature deviceSignature = ModbusTools.parseModbusSignature(deviceIdentification);
            if(deviceSignature!=null){
                resultMap.put("vendorStr", deviceSignature.getVendor());
                resultMap.put("deviceType", deviceSignature.getDeviceType());
                resultMap.put("productCode", deviceSignature.getProductCode());
                resultMap.put("productName", deviceSignature.getProductName());
                resultMap.put("modelName", deviceSignature.getModelName());
                resultMap.put("revision", deviceSignature.getRevision());
            }
            resultMap.put("response", "successful");
        } catch (ModbusProtocolException e) {
            String response = e.getMessage();
            resultMap.put("response", response);
        } catch (ModbusNumberException e) {
            String response = e.getMessage();
            resultMap.put("response", response);
        } catch (ModbusIOException e) {
            String response = e.getMessage();
            resultMap.put("response", response);
        } finally {
            try {
                master.disconnect();
                return resultMap;
            } catch (ModbusIOException e) {
                throw new RuntimeException(e);
            }
        }
    }
}

