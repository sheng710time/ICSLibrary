package com.sia.icsdeviceidentifier.core.schedulers.modbus;

import com.sia.icsdeviceidentifier.core.preprocessor.ModbusPreprocessor;
import com.sia.icsdeviceidentifier.core.scanners.modbus.ModbusScanner;
import com.sia.icsdeviceidentifier.entity.ModbusEntity;
import com.sia.icsdeviceidentifier.entity.ModbusScanInfo;
import com.sia.icsdeviceidentifier.entity.ModbusScanLog;
import com.sia.icsdeviceidentifier.mapper.ModbusEntityMapper;
import com.sia.icsdeviceidentifier.mapper.ModbusScanInfoMapper;
import com.sia.icsdeviceidentifier.mapper.ModbusScanLogMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;


/**
 * 多线程分段处理List集合
 * @author Mengmeng
 *
 */
@Slf4j
@Component
public class ModbusSchedulerMultiT {
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

        // 每500条数据开启一条线程:18分钟，每100条数据开启一条线程:5分钟
        startMultiT (storeEnable, ipList, coreThreadNum, threadSize, country);
    }

    public void modbusScanCSV (boolean storeEnable, String filepath, int coreThreadNum, int threadSize, String country) {
        // get scanning ips from the DB
        List<String[]> ipList = modbusPreprocessor.extractScanningIpList(filepath);

        // 每500条数据开启一条线程:18分钟，每100条数据开启一条线程:5分钟
        startMultiT (storeEnable, ipList, coreThreadNum, threadSize, country);
    }

    public void startMultiT (boolean storeEnable, List<String[]> ipList, int coreThreadNum, int threadSize, String country) {
        resetScannedIpCounter();
        // 总数据条数
        int dataSize = ipList.size();
        // 线程数
        int threadNum = dataSize / threadSize + 1;
        // 定义标记,过滤threadNum为整数
        boolean special = dataSize % threadSize == 0;

        // 创建一个线程池
        ExecutorService exec = Executors.newFixedThreadPool(coreThreadNum);
        // 定义一个任务集合
        List<Callable<Integer>> tasks = new ArrayList<Callable<Integer>>();
        Callable<Integer> task = null;
        List<String[]> cutList = null;

        // 确定每条线程的数据
        // get scanning information from the DB
        ModbusScanInfo scanInfo = modbusScanInfoMapper.getLastModbusScanInfo(country);
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
//                    System.out.println("Thread [" + no + "] --》 count: " + count);
//                    System.out.println("Thread [" + no + "] --》 ScannedIpCounter: " + getScannedIpCounter());
                    addScannedIpCounter(count);
//                    System.out.println("Thread [" + no + "] --》 ScannedIpCounter: " + getScannedIpCounter());
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
        // 关闭线程池
        exec.shutdown();
        // create scanning info
        long et = System.currentTimeMillis();
        Date eTime = new Date(et);
        if(storeEnable){
            ModbusScanInfo scanInfoNew = new ModbusScanInfo();
            scanInfoNew.setTotalIps(ipList.size());
            scanInfoNew.setScannedIps(getScannedIpCounter());
            scanInfoNew.setStartTime(sTime);
            scanInfoNew.setEndTime(eTime);
            scanInfoNew.setRound(round);
            scanInfoNew.setCountry(country);
            modbusScanInfoMapper.addModbusScanInfo(scanInfoNew);
        }
        log.info(">>>>>>>>>>>>> All (" + ipList.size() + "<-->" +getScannedIpCounter() + ") IP addresses have been scanned within " + (et-st)/1000 + " seconds.");
        log.info("*******************************************************************************************************");
    }

    public int start (boolean storeEnable, List<String[]> ipList, int round, int no, String country){
        // scan all ips
        Map<String, Integer> scanningMap = new HashMap<>();
        int count = 0;
        log.info("Start scanning thread ["+no+"] with " + ipList.size() + " ips.");
        long st = System.currentTimeMillis();
        Date sTime = new Date(st);

//        System.out.println("The first ip: " + ipList.get(0)[0]);

        for(int a=0; a<ipList.size(); a++){
            // scan ip:port
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

            // create scanning log
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
        }
        long et = System.currentTimeMillis();
        Date eTime = new Date(et);
        if(count < ipList.size()){
            log.warn("scanning thread ["+no+"]: Part (" + count + "<-->" + ipList.size() + ") IP addresses have been scanned within " + (et-st)/1000 + " seconds.");
        } else {
            log.info("scanning thread ["+no+"]: All (" + count + ") IP addresses have been scanned within " + (et-st)/1000 + " seconds.");
        }

        return count;
    }

}