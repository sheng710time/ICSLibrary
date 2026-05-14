package org.icslibrary.core.scanners.enip;

import com.digitalpetri.enip.EtherNetIpClient;
import com.digitalpetri.enip.EtherNetIpClientConfig;
import com.digitalpetri.enip.commands.*;
import com.digitalpetri.enip.cpf.CpfItem;
import com.digitalpetri.enip.cpf.CpfPacket;
import com.digitalpetri.enip.cpf.NullAddressItem;
import com.digitalpetri.enip.cpf.UnconnectedDataItemRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ConnectException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutionException;

@Component
@Slf4j
public class EnipScannerMore {

    /**
     * Encapsulation Layer Command
     *
     * @param ipStr
     * @param command
     *          List Identity    0x0063    (short) 0x0063;
     *          List Services    0x0004    (short) 0x0004;
     *          List Interfaces  0x0064    (short) 0x0064;
     * @return
     */
    public Map<String, String> sendEnipCommand(String ipStr, short command) {
        Socket socket = null;
        int port = 44818;
        Map<String, String> resultMap = new HashMap<>();
        try {
            // Open socket and set timeout.
            socket = new Socket();
            socket.connect(new InetSocketAddress(ipStr, port), 5000); // 5s connect timeout
            socket.setSoTimeout(5000); // 5s read timeout

            // Build the encapsulation-layer request (24 bytes).
            ByteBuffer buffer = ByteBuffer.allocate(24);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            buffer.putShort(command);
            buffer.putShort((short) 0x0000);
            buffer.putInt(0);
            buffer.putInt(0);
            buffer.putLong(0);
            buffer.putInt(0);

            // Send the request.
            OutputStream out = socket.getOutputStream();
            out.write(buffer.array());
            out.flush();

            // Read the response.
            InputStream in = socket.getInputStream();
            byte[] response = new byte[1024];
            int len = in.read(response); // May throw SocketTimeoutException
            resultMap.put("response", "successful");
        } catch (SocketTimeoutException ste) {
            resultMap.put("response", ste.toString());
        } catch (ConnectException ce) {
            resultMap.put("response", ce.toString());
        } catch (Exception e) {
            resultMap.put("response", e.toString());
        } finally {
            // Always close the socket.
            if (socket != null && !socket.isClosed()) {
                try {
                    socket.close();
                } catch (Exception e) {
                    resultMap.put("response", e.toString());
                }
            }
            return resultMap;
        }
    }

    /**
     * Register session
     *
     * @param ipStr
     * @return
     */
    public Map<String, String> scanRegisterSession(String ipStr) {
        // Create the EtherNet/IP client configuration.
        EtherNetIpClientConfig config = EtherNetIpClientConfig.builder(ipStr)
                .setSerialNumber(0x00)
                .setVendorId(0x00)
                .setTimeout(Duration.ofSeconds(5))
                .build();

        // Create the EtherNet/IP client instance.
        EtherNetIpClient client = new EtherNetIpClient(config);
        Map<String, String> resultMap = new HashMap<>();

        try {
            // Connect to the device and register a session.
            client.connect().get();
            RegisterSession registerSession = new RegisterSession();
            client.sendCommand(new Command(CommandCode.RegisterSession) {
            });
            resultMap.put("response", "successful");

        } catch (InterruptedException | ExecutionException e) {
            // Record communication failures in the response map.
            resultMap.put("response", processMessage(e.getMessage()));
        } finally {
            try {
                // Disconnect from the device.
                client.disconnect().get();
            } catch (InterruptedException | ExecutionException e) {
                resultMap.put("response", processMessage(e.getMessage()));
            }
            return resultMap;
        }
    }

    /**
     * sendRRDataIdentity, read the identity by sendRRData
     *
     * @param ipStr
     * @return
     */
    public Map<String, String> sendRRDataIdentity(String ipStr) {
        // Configure the EtherNet/IP client.
        EtherNetIpClientConfig config = EtherNetIpClientConfig.builder(ipStr)
                .setSerialNumber(0x00) // Serial number
                .setVendorId(0x00)     // Vendor ID
                .setTimeout(Duration.ofSeconds(5)) // Timeout
                .build();

        EtherNetIpClient client = new EtherNetIpClient(config);
        Map<String, String> resultMap = new HashMap<>();
        try {
            // Connect to the target device.
            client.connect().get();

            // Build the CIP request payload.
            ByteBuffer cipData = ByteBuffer.allocate(6); // CIP payload length: 6 bytes
            cipData.order(ByteOrder.LITTLE_ENDIAN);
            cipData.put((byte) 0x01); // Service: Get Attributes All (0x01)
            cipData.put((byte) 0x02); // Request Path Size: 2 words
            cipData.put((byte) 0x20); // Path Segment: Class ID
            cipData.put((byte) 0x01); // Class ID: Identity Object
            cipData.put((byte) 0x24); // Path Segment: Instance ID
            cipData.put((byte) 0x01); // Instance ID: 0x01

            // Build the Null Address Item.
            CpfItem nullAddressItem = new NullAddressItem();

            // Build the Unconnected Data Item with the CIP payload.
            CpfItem unconnectedDataItem = new UnconnectedDataItemRequest(buffer -> {
                buffer.writeBytes(cipData.array());
            });

            // Build the CPF packet with both items.
            CpfPacket cpfPacket = new CpfPacket(nullAddressItem, unconnectedDataItem);

            // Wrap the CPF packet in a SendRRData request.
            SendRRData sendRRData = new SendRRData(cpfPacket);

            // Send the request and wait for the response.
            client.sendRRData(sendRRData).whenComplete((response, ex) -> {
                if (ex != null) {
                    resultMap.put("response", processMessage(ex.toString()));
                } else {
                    resultMap.put("response", "successful");
                }
            }).get(); // Block until the response is available.

        } catch (Exception e) {
            resultMap.put("response", processMessage(e.getMessage()));
        } finally {
            try {
                // Disconnect from the target.
                client.disconnect().get();
            } catch (Exception e) {
                resultMap.put("response", processMessage(e.getMessage()));
            }
            return resultMap;
        }
    }

    /**
     * sendRRDataObject, read one customized object by sendRRData
     * @param ipStr
     * @return
     */
    public Map<String, String> sendRRDataObject(String ipStr) {
        // Configure the EtherNet/IP client.
        EtherNetIpClientConfig config = EtherNetIpClientConfig.builder(ipStr)
                .setSerialNumber(0x00) // Serial number
                .setVendorId(0x00)     // Vendor ID
                .setTimeout(Duration.ofSeconds(5)) // Timeout
                .build();

        EtherNetIpClient client = new EtherNetIpClient(config);
        Map<String, String> resultMap = new HashMap<>();
        try {
            // Connect to the target device.
            client.connect().get();

            // Build the CIP request payload.
            ByteBuffer cipData = ByteBuffer.allocate(6); // CIP payload length: 6 bytes
            cipData.order(ByteOrder.LITTLE_ENDIAN);
            cipData.put((byte) 0x01); // Service: Get Attributes All (0x01)
            cipData.put((byte) 0x02); // Request Path Size: 2 words
            cipData.put((byte) 0x20); // Path Segment: Class ID
            cipData.put((byte) 0x64); // Class ID: Identity Object
            cipData.put((byte) 0x24); // Path Segment: Instance ID
            cipData.put((byte) 0x01); // Instance ID: 0x01

            // Build the Null Address Item.
            CpfItem nullAddressItem = new NullAddressItem();

            // Build the Unconnected Data Item with the CIP payload.
            CpfItem unconnectedDataItem = new UnconnectedDataItemRequest(buffer -> {
                buffer.writeBytes(cipData.array());
            });

            // Build the CPF packet with both items.
            CpfPacket cpfPacket = new CpfPacket(nullAddressItem, unconnectedDataItem);

            // Wrap the CPF packet in a SendRRData request.
            SendRRData sendRRData = new SendRRData(cpfPacket);

            // Send the request and wait for the response.
            client.sendRRData(sendRRData).whenComplete((response, ex) -> {
                if (ex != null) {
                    resultMap.put("response", processMessage(ex.toString()));
                } else {
                    resultMap.put("response", "successful");
                }
            }).get(); // Block until the response is available.

        } catch (Exception e) {
            resultMap.put("response", processMessage(e.getMessage()));
        } finally {
            try {
                // Disconnect from the target.
                client.disconnect().get();
            } catch (Exception e) {
                resultMap.put("response", processMessage(e.getMessage()));
            }
            return resultMap;
        }
    }

    /**
     * sendRRDataObject, read one tag by sendRRData
     * @param ipStr
     * @return
     */
    public Map<String, String> sendRRDataTag(String ipStr) {
        // Configure the EtherNet/IP client.
        EtherNetIpClientConfig config = EtherNetIpClientConfig.builder(ipStr)
                .setTimeout(Duration.ofSeconds(5)) // Timeout
                .build();

        EtherNetIpClient client = new EtherNetIpClient(config);
        Map<String, String> resultMap = new HashMap<>();
        try {
            // Connect to the target device.
            client.connect().get();

            // 1. Tag name
            String tagName = "Pressure";
            byte[] tagNameBytes = tagName.getBytes(StandardCharsets.UTF_8);
            int tagLength = tagNameBytes.length;

            // 2. Build the Symbol Segment: 0x4C <length> <tag bytes> [padding]
            ByteArrayOutputStream pathStream = new ByteArrayOutputStream();
            pathStream.write(0x4C);                 // Symbol Segment type
            pathStream.write(tagLength);            // Tag length
            pathStream.write(tagNameBytes);         // Tag bytes
            if (tagLength % 2 != 0) {
                pathStream.write(0x00);             // Padding if length is odd
            }

            byte[] pathBytes = pathStream.toByteArray();

            // 3. Build the CIP message: 0x0E <path size> <path bytes>
            ByteArrayOutputStream cip = new ByteArrayOutputStream();
            cip.write(0x0E);                                 // Service: Get_Attribute_Single
            cip.write(pathBytes.length / 2);                // Path size in WORDs
            cip.write(pathBytes);                           // Path data

            byte[] cipBytes = cip.toByteArray();

            // 4. Build the ENIP packet (SendRRData)
            CpfItem nullAddressItem = new NullAddressItem();
            CpfItem unconnectedDataItem = new UnconnectedDataItemRequest(buffer -> {
                buffer.writeBytes(cipBytes);
            });

            CpfPacket cpfPacket = new CpfPacket(nullAddressItem, unconnectedDataItem);
            SendRRData sendRRData = new SendRRData(cpfPacket);

            // Send the request and wait for the response.
            client.sendRRData(sendRRData).whenComplete((response, ex) -> {
                if (ex != null) {
                    resultMap.put("response", processMessage(ex.toString()));
                } else {
                    resultMap.put("response", "successful");
                }
            }).get(); // Block until the response is available.

        } catch (Exception e) {
            // Capture and record the exception.
            resultMap.put("response", processMessage(e.getMessage()));
        } finally {
            try {
                // Disconnect from the target.
                client.disconnect().get();
            } catch (Exception e) {
                resultMap.put("response", processMessage(e.getMessage()));
            }
            return resultMap;
        }
    }

    // sendUnitData
    public Map<String, String> sendUnitDataIdentity(String ipStr) { //TODO incomplete
        EtherNetIpClientConfig config = EtherNetIpClientConfig.builder(ipStr)
                .setSerialNumber(0x00)
                .setVendorId(0x00)
                .setTimeout(Duration.ofSeconds(10)) // Longer timeout for this path
                .build();

        EtherNetIpClient client = new EtherNetIpClient(config);
        Map<String, String> resultMap = new HashMap<>();
        try {
            System.out.println("Connecting to: " + ipStr + ":44818");
            client.connect().get(); // Attempt to connect
            System.out.println("Connection successful");

            // Build the CIP request payload.
            byte[] cipData = constructCipRequest();

            // Build the Null Address Item and Unconnected Data Item.
            CpfItem nullAddressItem = new NullAddressItem();
            CpfItem unconnectedDataItem = new UnconnectedDataItemRequest(buffer -> {
                buffer.writeBytes(cipData);
            });

            // Build the CPF packet.
            CpfPacket cpfPacket = new CpfPacket(nullAddressItem, unconnectedDataItem);

            // Wrap the CPF packet in a SendUnitData request.
            SendUnitData sendUnitData = new SendUnitData(cpfPacket);

            // Send the request and wait for the response.
            client.sendUnitData(sendUnitData).whenComplete((response, ex) -> {
                if (ex != null) {
                    System.err.println("Error: " + ex.getMessage());
                    resultMap.put("response", "Failed: " + ex.getMessage());
                } else {
                    System.out.println("Response received: " + response.toString());
                    resultMap.put("response", "Success: " + response.toString());
                }
            }).get();

        } catch (Exception e) {
            resultMap.put("response", "Error: " + e.getMessage());
            e.printStackTrace();
        } finally {
            try {
                client.disconnect().get(); // Disconnect from the target
                System.out.println("Disconnected");
            } catch (Exception e) {
                resultMap.put("response", "Disconnect Error: " + e.getMessage());
            }
        }
        return resultMap;
    }

    /**
     * Build the CIP request payload.
     */
    private byte[] constructCipRequest() {
        ByteBuffer cipData = ByteBuffer.allocate(8); // CIP payload length
        cipData.order(ByteOrder.LITTLE_ENDIAN);

        cipData.put((byte) 0x01); // Service Code: Get_Attributes_All (0x01)
        cipData.put((byte) 0x02); // Path Size: 2 words
        cipData.put((byte) 0x20); // Path Segment: Class ID
        cipData.put((byte) 0x01); // Class ID: Identity Object (0x01)
        cipData.put((byte) 0x24); // Path Segment: Instance ID
        cipData.put((byte) 0x01); // Instance ID: 1

        return cipData.array();
    }

    private String processMessage (String message) {
        String response;
        if (message == null) {
            return message;
        } else { // remove IP after '/'
            int index = findSlashBeforeIp(message);
            if (index == -1) {
                return message;
            } else {
                return  message.substring(0, index);
            }
        }
    }

    public static int findSlashBeforeIp(String input) {
        int index = input.indexOf('/');
        while (index != -1 && index + 1 < input.length()) {
            if (Character.isDigit(input.charAt(index + 1))) {
                return index;  // Found a slash followed by a digit.
            }
            // Continue searching for the next slash.
            index = input.indexOf('/', index + 1);
        }
        return -1; // No matching slash was found.
    }
}

