package org.icslibrary.core.scanners.s7;

import com.sourceforge.snap7.moka7.S7Client;
import com.sourceforge.snap7.moka7.S7Szl;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

import static org.icslibrary.core.scanners.s7.S7Tools.*;

@Slf4j
@Component
public class S7Scanner {

    /**
     * Scan a target PLC and retrieve its SZL payload.
     *
     * @param ip_address the target IP address
     */
    public Map<String, String> scan(String ip_address) {
        S7Client client = new S7Client();
        Map<String, String> resultMap = new HashMap<>();

        try {
            int result = client.ConnectTo(ip_address, 0, 0);

            if (result == 0) {
                resultMap.put("respond", "successful");
                S7Szl szl = new S7Szl(128);
                int id = 0x0011; // Default SZL ID used by the scanner.
                int index = 0x0000; // Default SZL index.
                result = client.ReadSZL(id, index, szl);

                if (result == 0) {
                    resultMap.put("origin_data", convertDataToHex(szl.Data));
                }
            }else{
                resultMap.put("respond",client.ErrorText(result));
            }
        } catch (Exception e) {
            resultMap.put("respond",e.getMessage());
        } finally {

            client.Disconnect();

        }
        return resultMap;
    }

    public S7SZLReceiver[] identifyScanData(String respond,String origin_data) {
        if(respond=="successful"){
            return cutHexDataIntoParts(origin_data);
        }else{
            S7SZLReceiver[] f_results = new S7SZLReceiver[]{new S7SZLReceiver("No data", "No data", "No data", "No data", "No data")};
            return f_results;
        }
    }

    public boolean isAlive(String ip_address){
        S7Client client = new S7Client();
        int result = client.ConnectTo(ip_address, 0, 0); // Attempt to connect to the PLC.
        if (result==0){
            System.out.println("PLC ["+ip_address+"] is alive.");
            client.Disconnect(); // Disconnect after a successful liveness check.
            return true;
        }else {
            System.out.println("PLC ["+ip_address+"] is not alive.");
            return false;
        }
    }

    public static void main(String[] args) {
        S7Scanner sc = new S7Scanner();
        sc.scan("185.142.173.188");
    }
}

