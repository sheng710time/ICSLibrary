package com.sia.icsdeviceidentifier.core.scanners.enip;

import com.digitalpetri.enip.EtherNetIpClient;
import com.digitalpetri.enip.EtherNetIpClientConfig;
import com.digitalpetri.enip.commands.ListIdentity;
import com.sia.icsdeviceidentifier.core.scanners.enip.enipidentity.EnipIdentity;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutionException;

/**
 * @Author: CSheng
 * @Version: 1.0
 * @Data: 2023/4/21 14:10
 */
@Component
@Slf4j
public class EnipScanner {

    public Map<String, String> scan(String ipStr) {
        EtherNetIpClientConfig config = EtherNetIpClientConfig.builder(ipStr)
                .setSerialNumber(0x00)
                .setVendorId(0x00)
                .setTimeout(Duration.ofSeconds(5))
                .build();

        EtherNetIpClient client = new EtherNetIpClient(config);
        Map<String, String> resultMap = new HashMap<>();
        try {
            client.connect().get();
            ListIdentity li = client.listIdentity().get();
            li.getIdentityItem().ifPresent(id -> {
                resultMap.put("vendorStr", EnipIdentity.getVendorStr(id.getVendorId()));
                resultMap.put("deviceType", EnipIdentity.getDeviceTypeStr(id.getDeviceType()));
                resultMap.put("productCode", id.getProductCode()+"");
                resultMap.put("productName", id.getProductName());
                resultMap.put("revision", id.getRevisionMajor()+"."+id.getRevisionMinor());
            });
            resultMap.put("response", "successful");
        } catch (InterruptedException e) {
//            throw new RuntimeException(e);
            resultMap.put("response", e.getMessage().substring(0,e.getMessage().indexOf('/')));
        } catch (ExecutionException e) {
//            throw new RuntimeException(e);
            resultMap.put("response", e.getMessage().substring(0,e.getMessage().indexOf('/')));
        } finally {
            try {
                client.disconnect().get();
                return resultMap;
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            } catch (ExecutionException e) {
                throw new RuntimeException(e);
            }
        }
    }
}
