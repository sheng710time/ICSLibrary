package com.sia.icsdeviceidentifier.core.scanners.modbus;

import com.intelligt.modbus.jlibmodbus.Modbus;
import com.intelligt.modbus.jlibmodbus.exception.ModbusIOException;
import com.intelligt.modbus.jlibmodbus.exception.ModbusNumberException;
import com.intelligt.modbus.jlibmodbus.exception.ModbusProtocolException;
import com.intelligt.modbus.jlibmodbus.msg.base.mei.MEIReadDeviceIdentification;
import com.intelligt.modbus.jlibmodbus.msg.base.mei.ReadDeviceIdentificationCode;
import com.intelligt.modbus.jlibmodbus.tcp.TcpParameters;
import com.sia.icsdeviceidentifier.core.scanners.modbus.modbusmaster.MyModbusMaster;
import com.sia.icsdeviceidentifier.core.scanners.modbus.modbusmaster.MyModbusMasterFactory;
import com.sia.icsdeviceidentifier.entity.fingerprintSpace.DeviceSignature;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.HashMap;
import java.util.Map;

/**
 * @Author: CSheng
 * @Version: 1.0
 * @Data: 2022/12/13 16:07
 */
@Slf4j
@Component
@Data
public class ModbusScanner {

    public Map<String, String> scan(String ipStr, int port) {  //TODO test
        // 设置主机TCP参数
        TcpParameters tcpParameters = new TcpParameters();
        // 设置TCP的ip地址
        InetAddress adress = null;
        try {
            adress = InetAddress.getByName(ipStr);
        } catch (UnknownHostException e) {
            throw new RuntimeException(e);
        }
        tcpParameters.setHost(adress);
        // TCP设置长连接
        tcpParameters.setKeepAlive(false);
        // TCP设置端口
        tcpParameters.setPort(port);
        // 创建一个主机
        MyModbusMaster master = MyModbusMasterFactory.createModbusMasterTCP(tcpParameters);
        Modbus.setAutoIncrementTransactionId(true);
        master.setResponseTimeout(5000); //default 1000 [ms]

        Map<String, String> resultMap = new HashMap<>();
        try {
            if (!master.isConnected()) {
                master.connect();// 开启连接
            }

            int serverAddress = 1; //Modbus协议的Unit Identifier字段，一般地址在1-247之间，shodan共使用了0,1,255三个值
            int objectId = 0; //objectId为读取Objects信息的起始位置，设置为0则能够读取全部Object信息
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



