package org.icslibrary.core.schedulers.modbus;

import org.icslibrary.core.preprocessor.ModbusPreprocessor;
import org.icslibrary.core.scanners.modbus.ModbusScanner;
import org.icslibrary.entity.ModbusEntity;
import org.icslibrary.entity.ModbusScanInfo;
import org.icslibrary.entity.ModbusScanLog;
import org.icslibrary.mapper.ModbusEntityMapper;
import org.icslibrary.mapper.ModbusScanInfoMapper;
import org.icslibrary.mapper.ModbusScanLogMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.text.DecimalFormat;
import java.util.*;

@Slf4j
@Component
public class ModbusSchedulerSingleT {

    @Autowired
    private ModbusEntityMapper modbusEntityMapper;

    @Autowired
    private ModbusScanInfoMapper modbusScanInfoMapper;

    @Autowired
    private ModbusScanLogMapper modbusScanLogMapper;

    @Autowired
    private ModbusScanner modbusScanner;

    @Autowired
    private ModbusPreprocessor modbusPreprocessor;

    public void modbusScanList (boolean storeEnable, List<String[]> ipList, String country) {
        start(storeEnable, ipList, country);
    }

    public void modbusScanCSV (boolean storeEnable, String filepath, String country) {
        List<String[]> ipList = modbusPreprocessor.extractScanningIpList(filepath);
        start(storeEnable, ipList, country);
    }

    public void modbusScanDB (boolean storeEnable, String country) {
        List<ModbusEntity> entityList = modbusEntityMapper.getAllModbusEntities();
        List<String[]> strsList = new ArrayList<>();
        for(ModbusEntity entity : entityList){
            String[] strs = new String[2];
            strs[0] = entity.getIp();
            strs[1] = entity.getPort()+"";
            strsList.add(strs);
        }
        start(storeEnable, strsList, country);
    }

    public void start (boolean storeEnable, List<String[]> ipList, String country){
        ModbusScanInfo scanInfo = modbusScanInfoMapper.getLastModbusScanInfo(country);
        int round = scanInfo.getRound()+1;

        Map<String, Integer> scanningMap = new HashMap<>();
        int count = 0;
        log.info("*********************************** Modbus Start scanning (single-threaded) **********************************");
        long st = System.currentTimeMillis();
        Date sTime = new Date(st);
        for(int a=0; a<ipList.size(); a++){
            String ip = ipList.get(a)[0];
            int port = Integer.parseInt(ipList.get(a)[1]);
            Date startTime = new Date(System.currentTimeMillis());
            Map<String, String> resultMap =modbusScanner.scan(ip, port);
            Date endTime = new Date(System.currentTimeMillis());
            if(scanningMap.containsKey(resultMap.get("response"))){
                scanningMap.put(resultMap.get("response"), scanningMap.get(resultMap.get("response"))+1);
            }else {
                scanningMap.put(resultMap.get("response"), 1);
            }

            if(storeEnable){
                ModbusScanLog scanLog = new ModbusScanLog();
                scanLog.setIp(ip);
                scanLog.setPort(port);
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
                if(resultMap.containsKey("modelName")){
                    scanLog.setModelName(resultMap.get("modelName"));
                }
                if(resultMap.containsKey("revision")){
                    scanLog.setRevision(resultMap.get("revision"));
                }
                scanLog.setCountry(country);
                modbusScanLogMapper.addModbusScanLog(scanLog);
            }

            count++;
            if(count>0 && count%5==0){
                log.info("------------> " + count + " IP addresses have been scanned with a progress " + percent(count, ipList.size()));
            }
        }
        long et = System.currentTimeMillis();
        Date eTime = new Date(et);
        log.info(">>>>>>>>>>>>> All (" + count + ") IP addresses have been scanned within " + (et-st)/1000 + " seconds.");
        for(Map.Entry<String, Integer> entry : scanningMap.entrySet()){
            log.info(entry.getKey() + ": (" + entry.getValue() + ")");
        }

        log.info("*******************************************************************************************************");
        if(storeEnable){
            ModbusScanInfo scanInfoNew = new ModbusScanInfo();
            scanInfoNew.setTotalIps(ipList.size());
            scanInfoNew.setScannedIps(count);
            scanInfoNew.setStartTime(sTime);
            scanInfoNew.setEndTime(eTime);
            scanInfoNew.setRound(round);
            scanInfoNew.setCountry(country);
            modbusScanInfoMapper.addModbusScanInfo(scanInfoNew);
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

