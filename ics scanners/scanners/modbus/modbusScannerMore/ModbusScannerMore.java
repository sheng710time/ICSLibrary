package org.icslibrary.core.scanners.modbus.modbusScannerMore;

import com.intelligt.modbus.jlibmodbus.Modbus;
import com.intelligt.modbus.jlibmodbus.exception.ModbusIOException;
import com.intelligt.modbus.jlibmodbus.exception.ModbusNumberException;
import com.intelligt.modbus.jlibmodbus.exception.ModbusProtocolException;
import com.intelligt.modbus.jlibmodbus.msg.base.mei.MEIReadDeviceIdentification;
import com.intelligt.modbus.jlibmodbus.msg.base.mei.ReadDeviceIdentificationCode;
import com.intelligt.modbus.jlibmodbus.tcp.TcpParameters;
import org.icslibrary.core.scanners.modbus.modbusmaster.MyModbusMaster;
import org.icslibrary.core.scanners.modbus.modbusmaster.MyModbusMasterFactory;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.net.InetAddress;

@Slf4j
@Component
public class ModbusScannerMore {

    public String scan(String ipStr, int port, int serverAddress, int functionCode) {
        String response = null;
        try {
            // Configure TCP parameters for the target host.
            TcpParameters tcpParameters = new TcpParameters();
            InetAddress adress = InetAddress.getByName(ipStr);
            tcpParameters.setHost(adress);
            tcpParameters.setKeepAlive(false); // Use short-lived connections.
            tcpParameters.setPort(port);

            MyModbusMaster master = MyModbusMasterFactory.createModbusMasterTCP(tcpParameters);
            Modbus.setAutoIncrementTransactionId(true);
            master.setResponseTimeout(5000); // default 1000 [ms]

            try {
                if (!master.isConnected()) {
                    master.connect(); // Open the TCP connection on demand.
                }

                int objectId = 0; // Start from object 0 to request the full device-identification block.
                int startAddress = 0;  // Start address for coil and register reads.
                int numberOfCoils = 1; // Read a single coil.
                int numberOfRegisters = 1; // Read a single holding register for function code 3.

                // Dispatch the request by Modbus function code.
                switch (functionCode) {
                    case 1:
                        // Read Coils
                        boolean[] readCoils = master.readCoils(serverAddress, startAddress, numberOfCoils);
                        response = "successful";
                        break;

                    case 2:
                        // Read Discrete Inputs
                        boolean[] readDiscreteInputs = master.readDiscreteInputs(serverAddress, startAddress, numberOfRegisters);
                        response = "successful";
                        break;

                    case 3:
                        // Read Holding Registers
                        int[] registerValues = master.readHoldingRegisters(serverAddress, startAddress, numberOfRegisters);
                        response = "successful";
                        break;

                    case 17:
                        // Report Slave ID
                        byte[] reportSlaveId = master.reportSlaveId(serverAddress);
                        response = "successful";
                        break;

                    case 43:
                        // Read Device Identification
                        MEIReadDeviceIdentification deviceIdentification =
                                master.readDeviceIdentification(serverAddress, objectId, ReadDeviceIdentificationCode.BASIC_STREAM_ACCESS);
                        response = "successful";
                        break;

                    default:
                        response = "Unsupported function code: " + functionCode;
                }
                response = "successful";

            } catch (ModbusProtocolException e) {
                response = e.getMessage();
            } catch (ModbusNumberException e) {
                response = e.getMessage();
            } catch (ModbusIOException e) {
                response = e.getMessage();
            } catch (Exception e) {
                response = e.getMessage();
            } finally {
                try {
                    master.disconnect();
                    return response;
                } catch (ModbusIOException e) {
                    e.printStackTrace();
                }
            }
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return response;
    }
}

