package org.icslibrary.core.schedulers.enip;

import com.digitalpetri.enip.EtherNetIpShared;
import org.icslibrary.core.scanners.enip.EnipScanner;
import org.icslibrary.entity.EnipEntity;
import org.icslibrary.entity.EnipScanInfo;
import org.icslibrary.entity.EnipScanLog;
import org.icslibrary.mapper.EnipEntityMapper;
import org.icslibrary.mapper.EnipScanInfoMapper;
import org.icslibrary.mapper.EnipScanLogMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.text.DecimalFormat;
import java.util.*;

@Component
@Slf4j
public class EnipSchedulerSingleT {

    @Autowired
    private EnipScanner enipScanner;

    @Autowired
    private EnipEntityMapper enipEntityMapper;

    @Autowired
    private EnipScanInfoMapper enipScanInfoMapper;

    @Autowired
    private EnipScanLogMapper enipScanLogMapper;

    public void enipScanList (boolean storeEnable, List<String> ipList, String country) {
        // Start a scan from an in-memory IP list.
        start(storeEnable, ipList, country);
    }

    public void enipScanDB (boolean storeEnable, String country) {
        // Load the scan list from the database.
        List<EnipEntity> entityList = enipEntityMapper.getAllEnipEntities();
        List<String> ipList = new ArrayList<>();
        for(EnipEntity entity : entityList){
            ipList.add(entity.getIp());
        }
        start(storeEnable, ipList, country);
    }

    public void start (boolean storeEnable, List<String> ipList, String country){
        // Load the previous scan round and advance it.
        EnipScanInfo scanInfo = enipScanInfoMapper.getLastEnipScanInfo(country);
        final int round = scanInfo.getRound()+1;

        Map<String, Integer> scanningMap = new HashMap<>();
        int count = 0;
        log.info("*********************************** ENIP Start scanning (single-threaded) **********************************");
        long st = System.currentTimeMillis();
        Date sTime = new Date(st);
        for(int a=0; a<ipList.size(); a++){
            String ip = ipList.get(a);
            Date startTime = new Date(System.currentTimeMillis());
            Map<String, String> resultMap = enipScanner.scan(ip);
            Date endTime = new Date(System.currentTimeMillis());
            if(scanningMap.containsKey(resultMap.get("response"))){
                scanningMap.put(resultMap.get("response"), scanningMap.get(resultMap.get("response"))+1);
            }else {
                scanningMap.put(resultMap.get("response"), 1);
            }

            if(storeEnable){
                EnipScanLog scanLog = new EnipScanLog();
                scanLog.setIp(ip);
                scanLog.setPort(44818);
                scanLog.setRound(round);
                scanLog.setStartTime(startTime);
                scanLog.setEndTime(endTime);
                scanLog.setResponse(resultMap.get("response"));
                if(resultMap.containsKey("vendorStr")){
                    scanLog.setVendor(resultMap.get("vendorStr"));
                }
                if(resultMap.containsKey("deviceType")){
                    scanLog.setDeviceType(resultMap.get("deviceType"));
                }
                if(resultMap.containsKey("productCode")){
                    scanLog.setProductCode(resultMap.get("productCode"));
                }
                if(resultMap.containsKey("productName")){
                    scanLog.setProductName(resultMap.get("productName"));
                }
                if(resultMap.containsKey("revision")){
                    scanLog.setRevision(resultMap.get("revision"));
                }
                scanLog.setCountry(country);
                enipScanLogMapper.addEnipScanLog(scanLog);
            }

            count++;
            if(count>0 && count%5==0){
                log.info("------------> " + count + " IP addresses have been scanned with a progress " + percent(count, ipList.size()));
            }
        }

        // Release shared EtherNet/IP resources before shutdown.
        EtherNetIpShared.releaseSharedResources();

        long et = System.currentTimeMillis();
        Date eTime = new Date(et);
        log.info(">>>>>>>>>>>>> All (" + count + ") IP addresses have been scanned within " + (et-st)/1000 + " seconds.");
        for(Map.Entry<String, Integer> entry : scanningMap.entrySet()){
            log.info(entry.getKey() + ": (" + entry.getValue() + " )");
        }

        log.info("*******************************************************************************************************");
        if(storeEnable){
            EnipScanInfo scanInfoNew = new EnipScanInfo();
            scanInfoNew.setTotalIps(ipList.size());
            scanInfoNew.setScannedIps(count);
            scanInfoNew.setStartTime(sTime);
            scanInfoNew.setEndTime(eTime);
            scanInfoNew.setRound(round);
            scanInfoNew.setCountry(country);
            enipScanInfoMapper.addEnipScanInfo(scanInfoNew);
        }
    }

    // Calculate the scan progress percentage.
    public String percent(int x, int y) {
        String percent = "";
        double xx = x * 100.0;
        double yy = y * 100.0;
        double zz = xx / yy;
        DecimalFormat df = new DecimalFormat("##.00%");
        if(Math.abs(zz)<0.000000000001){
            percent = "0.00%";
        } else {
            percent = df.format(zz);
        }
        return percent;
    }
}

