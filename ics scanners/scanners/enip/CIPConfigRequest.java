package org.icslibrary.core.scanners.enip;

import com.digitalpetri.enip.EtherNetIpClient;
import com.digitalpetri.enip.EtherNetIpClientConfig;
import com.digitalpetri.enip.commands.SendRRData;
import com.digitalpetri.enip.cpf.CpfItem;
import com.digitalpetri.enip.cpf.CpfPacket;
import com.digitalpetri.enip.cpf.UnconnectedDataItemRequest;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;

import java.time.Duration;
import java.util.function.Consumer;

public class CIPConfigRequest {
    public static void main(String[] args) {
        // Create EtherNet/IP client configuration with target device IP
        EtherNetIpClientConfig config = EtherNetIpClientConfig.builder("192.0.2.10")
                .setSerialNumber(0x00)
                .setVendorId(0x00)
                .setTimeout(Duration.ofSeconds(2))
                .build();

        EtherNetIpClient client = new EtherNetIpClient(config);

        try {
            client.connect().get(); // Establish connection

            // Define a ByteBuf encoder to write the CIP request
            Consumer<ByteBuf> encoder = buffer -> {
                buffer.writeByte(0x0E); // Get Attribute Single service
                buffer.writeShort(0x01); // Class ID (Identity Object)
                buffer.writeShort(0x01); // Instance ID
                buffer.writeShort(0x04); // Attribute ID (Product Name)
            };

            // Create UnconnectedDataItemRequest with the encoder
            UnconnectedDataItemRequest request = new UnconnectedDataItemRequest(encoder);

            // Wrap in a CPF packet
            CpfPacket cpfPacket = new CpfPacket(request);

            // Create SendRRData command
            SendRRData sendRRData = new SendRRData(cpfPacket);

            SendRRData data = client.sendRRData(sendRRData).get();
            if (data != null) {
                handleResponse(data);
            }
            // Send the request and handle response
//            CompletableFuture<SendRRData> future = client.sendRRData(sendRRData);
//            future.whenComplete((response, ex) -> {
//                if (response != null) {
//                    handleResponse(response);
//                } else {
//                    ex.printStackTrace();
//                }
//            });

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
//                client.disconnect().get();  // Disconnect the client
                client.disconnect().thenRun(() -> {
                    System.out.println("Disconnected with proper channel close.");
                });
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    // Handle response by extracting CPF items and payload data
    private static void handleResponse(SendRRData response) {
        for (CpfItem item : response.getPacket().getItems()) {
            if (item instanceof UnconnectedDataItemRequest) {
                Consumer<ByteBuf> encoder = ((UnconnectedDataItemRequest) item).getEncoder();
                // Create a ByteBuf and apply the encoder to it
                ByteBuf byteBuf = Unpooled.buffer();
                encoder.accept(byteBuf);  // Apply the consumer to the buffer
                String productName = extractStringFromBuffer(byteBuf);
                System.out.println("Product Name: " + productName);
            }
        }
    }

    // Helper method to extract string from ByteBuf
    private static String extractStringFromBuffer(ByteBuf buffer) {
        byte[] bytes = new byte[buffer.readableBytes()];
        buffer.readBytes(bytes);
        return new String(bytes);
    }
}

