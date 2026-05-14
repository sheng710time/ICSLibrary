package org.icslibrary.core.schedulers.s7;

import org.icslibrary.core.scanners.s7.S7SZLReceiver;
import org.icslibrary.core.scanners.s7.S7Scanner;
import org.icslibrary.entity.S7Entity;
import org.icslibrary.entity.S7ScanInfo;
import org.icslibrary.entity.S7ScanLog;
import org.icslibrary.mapper.S7EntityMapper;
import org.icslibrary.mapper.S7ScanInfoMapper;
import org.icslibrary.mapper.S7ScanLogMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

@Slf4j
@Component
public class S7SchedulerMultiT {
    @Autowired
    private S7EntityMapper s7EntityMapper;

    @Autowired
    private S7ScanInfoMapper s7ScanInfoMapper;

    @Autowired
    private S7ScanLogMapper s7ScanLogMapper;

    @Autowired
    private S7Scanner s7Scanner;

    //TODO:
    //private S7Preprocessor s7Preprocessor;

    public static int scannedIpCount = 0;

    synchronized void addScannedIpCounter(int count) {
        scannedIpCount += count;
    }

    synchronized int getScannedIpCounter(){
        return scannedIpCount;
    }

    synchronized void resetScannedIpCounter() {
        scannedIpCount = 0;
    }

    public void s7ScanDB(boolean storeEnable, int coreThreadNum, int threadSize, String country){
        List<S7Entity> entityList = s7EntityMapper.getAllS7Entities();
        List<String[]> ipList = new ArrayList<>();
        for(S7Entity entity : entityList){
            String[] strs = new String[2];
            strs[0] = entity.getIp();
            strs[1] = entity.getPort()+"";
            ipList.add(strs);
        }

        startMultiT (storeEnable, ipList, coreThreadNum, threadSize, country);
    }

    public void startMultiT(boolean storeEnable, List<String[]> ipList, int coreThreadNum, int threadSize, String country) {
        resetScannedIpCounter();

        int dataSize = ipList.size();
        int threadNum = dataSize / threadSize + 1;
        boolean special = dataSize % threadSize == 0;

        ExecutorService exec = Executors.newFixedThreadPool(coreThreadNum);
        List<Callable<Integer>> tasks = new ArrayList<Callable<Integer>>();
        Callable<Integer> task = null;
        List<String[]> cutList = null;

        S7ScanInfo scanInfo = s7ScanInfoMapper.getLastS7ScanInfo();
        int round = scanInfo.getRound()+1;

        for(int i=0; i<threadNum; i++){
            if(i == threadNum-1){
                if(special) break;
                cutList = ipList.subList(threadSize * i, dataSize);
            } else{
                cutList = ipList.subList(threadSize * i, threadSize * (i + 1));
            }
            final List<String[]> listStr = cutList;
            final Integer no = i;

            task = new Callable<Integer>(){
                @Override
                public Integer call() throws Exception{
                    int count = 0;
                    if(listStr != null && listStr.size() > 0){
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
        try{
            log.info("*********************************** S7 Start scanning (multiple-threaded) **********************************");
            List<Future<Integer>> results = exec.invokeAll(tasks);

            // Inspect each task result and report failures explicitly.
            int totalScanned = 0;
            for (Future<Integer> result : results) {
                try {
                    int taskCount = result.get();  // Retrieve the task result.
                    totalScanned += taskCount;
                    log.info("Task completed, scanned " + taskCount + " IPs.");
                } catch (Exception e) {
                    log.error("Task execution failed", e);
                }
            }
            log.info("Total scanned IPs (calculated from tasks): " + totalScanned);
        }catch(InterruptedException e){
            e.printStackTrace();
        }

        exec.shutdown();

        long et = System.currentTimeMillis();
        Date eTime = new Date(et);
        if(storeEnable){
            S7ScanInfo scanInfoNew = new S7ScanInfo();
            scanInfoNew.setTotalIps(ipList.size());
            scanInfoNew.setScannedIps(getScannedIpCounter());
            scanInfoNew.setCountry(country);
            scanInfoNew.setStartTime(sTime);
            scanInfoNew.setEndTime(eTime);
            scanInfoNew.setRound(round);
            s7ScanInfoMapper.addS7ScanInfo(scanInfoNew);
        }
        log.info(">>>>>>>>>>>>> All (" + ipList.size() + "<-->" +getScannedIpCounter() + ") IP addresses have been scanned within " + (et-st)/1000 + " seconds.");
        log.info("*******************************************************************************************************");
    }

    public int start(boolean storeEnable, List<String[]> ipList, int round, int no, String country){
        Map<String, Integer> scanningMap = new HashMap<>();
        int count = 0;
        log.info("Start scanning thread ["+no+"] with " + ipList.size() + " ips.");
        long st = System.currentTimeMillis();

        for(int a=0; a<ipList.size(); a++){
            String ip = ipList.get(a)[0];
            int port = Integer.parseInt(ipList.get(a)[1]);
            Date startTime = new Date(System.currentTimeMillis());

            Map<String, String> resultMap = s7Scanner.scan(ip);
            if (resultMap == null) {
                log.warn("Scan result is null for IP: " + ip);
                continue;
            }
            String origin_data = resultMap.get("origin_data");
            String response = resultMap.get("respond");

            S7SZLReceiver[] receivers = s7Scanner.identifyScanData(response,origin_data);

            String vendor = "Siemens";
            String model,hardware,firmware;
            if(receivers.length==1){
                model = "null";
                hardware = "null";
                firmware = "null";
            }else{
                model = receivers[0].getMlfb();
                hardware = receivers[1].getMlfb();
                String firmware1 = receivers[2] != null ? receivers[2].getMlfb() : "";
                String firmware2 = receivers[3] != null ? receivers[3].getMlfb() : "";
                if (firmware1 == null || firmware1.trim().isEmpty()) {
                    firmware = "::" + firmware2;
                } else {
                    firmware = firmware1 + "::" + firmware2;
                }
            }

            Date endTime = new Date(System.currentTimeMillis());
            if(scanningMap.containsKey(response)){
                scanningMap.put(response, scanningMap.get(response)+1);
            }else{
                scanningMap.put(response,1);
            }
            if(storeEnable){
                S7ScanLog scanLog = new S7ScanLog();
                scanLog.setIp(ip);
                scanLog.setPort(port);
                scanLog.setCountry(country);
                scanLog.setRound(round);
                scanLog.setStartTime(startTime);
                scanLog.setEndTime(endTime);
                scanLog.setResponse(response);
                scanLog.setVendor(vendor);
                if(!Objects.equals(model, "null")) scanLog.setProductName(model);
                if(!Objects.equals(hardware, "null")) scanLog.setProductCode(hardware);
                if(!Objects.equals(firmware, "null")) scanLog.setRevision(firmware);
                s7ScanLogMapper.addS7ScanLog(scanLog);
            }
            count++;
        }
        long et = System.currentTimeMillis();
        if(count < ipList.size()){
            log.warn("scanning thread ["+no+"]: Part (" + count + "<-->" + ipList.size() + ") IP addresses have been scanned within " + (et-st)/1000 + " seconds.");
        } else {
            log.info("scanning thread ["+no+"]: All (" + count + ") IP addresses have been scanned within " + (et-st)/1000 + " seconds.");
        }
        return count;
    }

    public String getSecondElement(String str) {
        // Return null when the input is missing.
        if (str == null || str.isEmpty()) {
            return null;
        }

        // Locate the first two commas.
        int firstCommaIndex = str.indexOf(',');
        int secondCommaIndex = str.indexOf(',', firstCommaIndex + 1);

        // Continue only if both commas exist.
        if (firstCommaIndex != -1 && secondCommaIndex != -1) {
            String detail = str.substring(firstCommaIndex + 1, secondCommaIndex).trim();
            // Return null when the middle field is empty.
            if (detail.isEmpty()) {
                return null;
            }
            return detail;
        }

        // Return null when the input does not contain two commas.
        return null;
    }
}

