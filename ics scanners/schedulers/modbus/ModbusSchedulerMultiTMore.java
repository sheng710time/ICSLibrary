package org.icslibrary.core.schedulers.modbus;

import org.icslibrary.core.preprocessor.ModbusPreprocessor;
import org.icslibrary.core.scanners.modbus.modbusScannerMore.ModbusScannerMore;
import org.icslibrary.entity.ModbusEntity;
import org.icslibrary.entity.ModbusScanInfoMore;
import org.icslibrary.entity.ModbusScanLogMore;
import org.icslibrary.mapper.ModbusEntityMapper;
import org.icslibrary.mapper.ModbusScanInfoMoreMapper;
import org.icslibrary.mapper.ModbusScanLogMoreMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@Slf4j
@Component
public class ModbusSchedulerMultiTMore {
    @Autowired
    private ModbusEntityMapper modbusEntityMapper;

    @Autowired
    private ModbusScanInfoMoreMapper modbusScanInfoMoreMapper;

    @Autowired
    private ModbusScanLogMoreMapper modbusScanLogMoreMapper;

    @Autowired
    private ModbusScannerMore modbusScannerMore;

    @Autowired
    private ModbusPreprocessor modbusPreprocessor;

    public static int scannedIpCounter = 0;

    synchronized void addScannedIpCounter (int count) {
        scannedIpCounter += count;
    }

    synchronized int getScannedIpCounter () {
        return scannedIpCounter;
    }

    synchronized void resetScannedIpCounter () {
        scannedIpCounter = 0;
    }

    public void modbusScanDB (boolean storeEnable, int coreThreadNum, int threadSize, String country) {
        List<ModbusEntity> entityList = modbusEntityMapper.getAllModbusEntities();
        List<String[]> ipList = new ArrayList<>();
        for(ModbusEntity entity : entityList){
            String[] strs = new String[2];
            strs[0] = entity.getIp();
            strs[1] = entity.getPort()+"";
            ipList.add(strs);
        }

        // Larger batches reduce thread count but typically increase total runtime.
        startMultiT (storeEnable, ipList, coreThreadNum, threadSize, country);
    }

    public void modbusScanCSV (boolean storeEnable, String filepath, int coreThreadNum, int threadSize, String country) {
        List<String[]> ipList = modbusPreprocessor.extractScanningIpList(filepath);

        // The same batching strategy applies to CSV-driven scans.
        startMultiT (storeEnable, ipList, coreThreadNum, threadSize, country);
    }

    public void startMultiT (boolean storeEnable, List<String[]> ipList, int coreThreadNum, int threadSize, String country) {
        resetScannedIpCounter();
        int dataSize = ipList.size(); // Total number of targets.
        int threadNum = dataSize / threadSize + 1; // Number of worker tasks.
        boolean special = dataSize % threadSize == 0; // Whether the split is even.

        ExecutorService exec = Executors.newFixedThreadPool(coreThreadNum);
        List<Callable<Integer>> tasks = new ArrayList<Callable<Integer>>();
        Callable<Integer> task = null;
        List<String[]> cutList = null;

        ModbusScanInfoMore scanInfo = modbusScanInfoMoreMapper.getLastModbusScanInfoMore(country);
        int round = scanInfo.getRound()+1;

        for (int i = 0; i < threadNum; i++) {
            if (i == threadNum - 1) {
                if (special) {
                    break;
                }
                cutList = ipList.subList(threadSize * i, dataSize);
            } else {
                cutList = ipList.subList(threadSize * i, threadSize * (i + 1));
            }
            final List<String[]> listStr = cutList;
            final Integer no = i;

            task = new Callable<Integer>() {
                @Override
                public Integer call() throws Exception {
                    int count = 0;
                    if (listStr != null && listStr.size() > 0) {
                        count = start(storeEnable, listStr, round, no, country);
                    }
                    addScannedIpCounter(count);
                    return count;
                }
            };
            tasks.add(task);
        }

        long st = System.currentTimeMillis();
        Date sTime = new Date(st);
        try {
            log.info("*********************************** Modbus Start scanning (multiple-threaded) **********************************");
            exec.invokeAll(tasks);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        exec.shutdown(); // Shut down the thread pool.

        long et = System.currentTimeMillis();
        Date eTime = new Date(et);
        if(storeEnable){
            ModbusScanInfoMore scanInfoNew = new ModbusScanInfoMore();
            scanInfoNew.setTotalIps(ipList.size());
            scanInfoNew.setScannedIps(getScannedIpCounter());
            scanInfoNew.setStartTime(sTime);
            scanInfoNew.setEndTime(eTime);
            scanInfoNew.setRound(round);
            scanInfoNew.setCountry(country);
            modbusScanInfoMoreMapper.addModbusScanInfoMore(scanInfoNew);
        }
        log.info(">>>>>>>>>>>>> All (" + ipList.size() + "<-->" +getScannedIpCounter() + ") IP addresses have been scanned within " + (et-st)/1000 + " seconds.");
        log.info("*******************************************************************************************************");
    }

    public int start (boolean storeEnable, List<String[]> ipList, int round, int no, String country){
        Map<String, Integer> scanningMap = new HashMap<>();
        int count = 0;
        log.info("Start scanning thread ["+no+"] with " + ipList.size() + " ips.");
        long st = System.currentTimeMillis();

        // Configure the Unit Identifier and function-code combinations.
//        int[] unitIds = {0, 1, 255}; // Example Unit Identifier values used by Internet scanners.
        int[] unitIds = {1}; // Keep a single Unit Identifier for the current scan.
        int[] functionCodes = {1, 2, 3, 17, 43};
//        int[] functionCodes = {17, 43};
//        int scanWay = 1; // 0: basic scan, 1: multi-function scan
        for (int unitId : unitIds) {
            for (int functionCode : functionCodes) {
                for(int a=0; a<ipList.size(); a++){
                    String ip = ipList.get(a)[0];
                    int port = Integer.parseInt(ipList.get(a)[1]);
                    Date startTime = new Date(System.currentTimeMillis());
                    String response = modbusScannerMore.scan(ip, port, unitId, functionCode);
                    Date endTime = new Date(System.currentTimeMillis());
                    if(scanningMap.containsKey(response)){
                        scanningMap.put(response, scanningMap.get(response)+1);
                    }else {
                        scanningMap.put(response, 1);
                    }
                    if(storeEnable){
                        ModbusScanLogMore scanLog = new ModbusScanLogMore();
                        scanLog.setIp(ip);
                        scanLog.setPort(port);
                        scanLog.setRound(round);
                        scanLog.setScanWay(functionCode+"");
                        scanLog.setStartTime(startTime);
                        scanLog.setEndTime(endTime);
                        scanLog.setResponse(response);
                        scanLog.setCountry(country);
                        modbusScanLogMoreMapper.addModbusScanLogMore(scanLog);
                    }

                    count++;
                }
                try {
                    Thread.sleep(100000); // Pause 100 seconds between function-code groups.
                } catch (InterruptedException e) {
                    throw new RuntimeException(e);
                }
            }
        }

        long et = System.currentTimeMillis();
        if(count < ipList.size()){
            log.warn("scanning thread ["+no+"]: Part (" + count + "<-->" + ipList.size() + ") IP addresses have been scanned within " + (et-st)/1000 + " seconds.");
        } else {
            log.info("scanning thread ["+no+"]: All (" + count + ") IP addresses have been scanned within " + (et-st)/1000 + " seconds.");
        }

        return count;
    }
}

