package com.sia.icsdeviceidentifier.core.scanners.s7;

import com.sourceforge.snap7.moka7.S7Client;
import com.sourceforge.snap7.moka7.S7Szl;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

import static com.sia.icsdeviceidentifier.core.scanners.s7.S7Tools.*;

@Slf4j
@Component
public class S7Scanner {

    /**
     * 扫描目标IP地址的PLC，获取PLC的SZL数据
     * @param ip_address 目标IP地址
     */
    public Map<String, String> scan(String ip_address) {
        S7Client client = new S7Client();
        Map<String, String> resultMap = new HashMap<>();

        try {
            int result = client.ConnectTo(ip_address, 0, 0);

            if (result == 0) {
                resultMap.put("respond", "successful");
                S7Szl szl = new S7Szl(128);
                int id = 0x0011; // SZL ID，根据实际需求设置
                int index = 0x0000; // SZL Index，通常设置为0
                result = client.ReadSZL(id, index, szl);

                if (result == 0) {
                    int size = szl.DataSize;
                    resultMap.put("origin_data",convertDataToHex(szl.Data));
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
        int result = client.ConnectTo(ip_address, 0, 0); // 尝试连接到PLC
        if (result==0){
            System.out.println("PLC ["+ip_address+"] is alive.");
            client.Disconnect(); // 断开连接
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



