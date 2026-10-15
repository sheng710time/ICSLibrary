package org.icslibrary.core.schedulers.enip;

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

import java.util.*;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@Component
@Slf4j
public class EnipSchedulerMultiT {

    @Autowired
    private EnipScanner enipScanner;

    @Autowired
    private EnipEntityMapper enipEntityMapper;

    @Autowired
    private EnipScanInfoMapper enipScanInfoMapper;

    @Autowired
    private EnipScanLogMapper enipScanLogMapper;

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

    public void enipScanList (boolean storeEnable, List<String> ipList, int coreThreadNum, int threadSize, String country) {
        startMultiT(storeEnable, ipList, coreThreadNum, threadSize, country);
    }

    public void enipScanDB (boolean storeEnable, int coreThreadNum, int threadSize, String country) {
        List<EnipEntity> entityList = enipEntityMapper.getAllEnipEntities();
        List<String> ipList = new ArrayList<>();
        for(EnipEntity entity : entityList){
            ipList.add(entity.getIp());
        }
        startMultiT(storeEnable, ipList, coreThreadNum, threadSize, country);
    }

    public void startMultiT (boolean storeEnable, List<String> ipList, int coreThreadNum, int threadSize, String country) {
        resetScannedIpCounter();
        int dataSize = ipList.size(); // Total number of targets.
        int threadNum = dataSize / threadSize + 1; // Number of worker tasks.
        boolean special = dataSize % threadSize == 0; // Whether the split is even.

        ExecutorService exec = Executors.newFixedThreadPool(coreThreadNum);
        List<Callable<Integer>> tasks = new ArrayList<Callable<Integer>>();
        Callable<Integer> task = null;
        List<String> cutList = null;

        EnipScanInfo scanInfo = enipScanInfoMapper.getLastEnipScanInfo(country);
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
            final List<String> listStr = cutList;
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
            log.info("*********************************** ENIP Start scanning (multiple-threaded) **********************************");
            exec.invokeAll(tasks);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        exec.shutdown(); // Shut down the thread pool.

        long et = System.currentTimeMillis();
        Date eTime = new Date(et);
        if(storeEnable){
            EnipScanInfo scanInfoNew = new EnipScanInfo();
            scanInfoNew.setTotalIps(ipList.size());
            scanInfoNew.setScannedIps(getScannedIpCounter());
            scanInfoNew.setStartTime(sTime);
            scanInfoNew.setEndTime(eTime);
            scanInfoNew.setRound(round);
            scanInfoNew.setCountry(country);
            enipScanInfoMapper.addEnipScanInfo(scanInfoNew);
        }
        log.info(">>>>>>>>>>>>> All (" + ipList.size() + "<-->" +getScannedIpCounter() + ") IP addresses have been scanned within " + (et-st)/1000 + " seconds.");
        log.info("*******************************************************************************************************");
    }

    public int start (boolean storeEnable, List<String> ipList, int round, int no, String country){
        Map<String, Integer> scanningMap = new HashMap<>();
        int count = 0;
        log.info("Start scanning thread ["+no+"] with " + ipList.size() + " ips.");
        long st = System.currentTimeMillis();

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

