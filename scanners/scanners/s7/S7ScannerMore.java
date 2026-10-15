package org.icslibrary.core.scanners.s7;

import com.sourceforge.snap7.moka7.S7BlockInfo;
import com.sourceforge.snap7.moka7.S7Client;
import com.sourceforge.snap7.moka7.S7Szl;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.sourceforge.snap7.moka7.S7.S7AreaDB;

@Slf4j
@Component
public class S7ScannerMore {

    // Function-code combinations used by the extended scanner; the first five are enabled here.
    // List<Integer> szlIdList = Arrays.asList(0x0011,0x0424,0x0012,0x0013,0x0014,0x0015,0x001C,0x0022,0x0074,0x0091,0x0092,0x00A0);
    List<Integer> szlIdList = Arrays.asList(0x0011,0x0424,0x0012,0x0013,0x0014); // Working subset

    public Map<String,String> scan(String ip_address, int main_function_code, int function_group_code, int szl_id){
        S7Client client = new S7Client();
        Map<String, String> resultMap = new HashMap<>();
        try{
            int result = client.ConnectTo(ip_address,0,0);

            if(result==0){
                resultMap.put("respond", "successful");

                if(main_function_code==0x00){
                    if(function_group_code==4){
                        S7Szl szl = new S7Szl(1024);
                        client.ReadSZL(szl_id,0x0000,szl);
                    }else if(function_group_code==3){
                        S7BlockInfo blockInfo = new S7BlockInfo();
                        client.GetAgBlockInfo(0x04,1,blockInfo);
                    }else if(function_group_code==7){
                        Date plcDateTime = new Date();
                        client.GetPlcDateTime(plcDateTime);
                    }
                }else if(main_function_code==0x04){
                    byte[] buffer = new byte[10];
                    client.ReadArea(S7AreaDB,1,0,10,buffer);
                }
            }else{
                resultMap.put("respond",client.ErrorText(result));
            }
        }catch(Exception e){
            resultMap.put("respond",e.getMessage());
        }finally {
            client.Disconnect();

        }
        return resultMap;
    }

    public static void main(String[] args) {
        S7ScannerMore scanner = new S7ScannerMore();
    }
}

