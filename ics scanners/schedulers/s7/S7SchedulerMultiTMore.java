package org.icslibrary.core.schedulers.s7;

import org.icslibrary.core.preprocessor.S7Preprocessor;
import org.icslibrary.core.scanners.s7.S7ScannerMore;
import org.icslibrary.entity.S7Entity;
import org.icslibrary.entity.S7ScanInfoMore;
import org.icslibrary.entity.S7ScanLogMore;
import org.icslibrary.mapper.S7EntityMapper;
import org.icslibrary.mapper.S7ScanInfoMoreMapper;
import org.icslibrary.mapper.S7ScanLogMoreMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@Slf4j
@Component
public class S7SchedulerMultiTMore {
    @Autowired
    private S7EntityMapper s7EntityMapper;

    @Autowired
    private S7ScanInfoMoreMapper s7ScanInfoMoreMapper;

    @Autowired
    private S7ScanLogMoreMapper s7ScanLogMoreMapper;

    @Autowired
    private S7ScannerMore s7ScannerMore;

    @Autowired
    private S7Preprocessor s7Preprocessor;

    public static int scannedIpCounter = 0;

    synchronized void addScannedIpCounter(int count) {
        scannedIpCounter += count;
    }

    synchronized int getScannedIpCounter() {return scannedIpCounter;}

    synchronized void resetScannedIpCounter() {scannedIpCounter = 0;}

    public void s7ScanDB(boolean storeEnable, int coreThreadNum, int threadSize, String country){
        List<S7Entity> entityList = s7EntityMapper.getAllS7Entities();
        List<String[]> ipList = new ArrayList<>();
        for(S7Entity entity: entityList){
            String[] temp = new String[2];
            temp[0] = entity.getIp();
            temp[1] = entity.getPort()+"";
            ipList.add(temp);
        }

        startMultiT(storeEnable, ipList,coreThreadNum, threadSize, country);
    }

    public void s7ScanCSV(boolean storeEnable, String filepath, int coreThreadNum, int threadSize, String country){
        List<String[]> ipList = s7Preprocessor.extractScanningIpList(filepath);
        startMultiT(storeEnable, ipList, coreThreadNum, threadSize, country);
    }

    public void startMultiT(boolean storeEnable, List<String[]> ipList, int coreThreadNum, int threadSize, String country){
        resetScannedIpCounter();

        int dataSize = ipList.size();
        int threadNum = dataSize / threadSize + 1;
        boolean special = dataSize % threadSize == 0;

        ExecutorService exec = Executors.newFixedThreadPool(coreThreadNum);
        List<Callable<Integer>> tasks = new ArrayList<Callable<Integer>>();
        Callable<Integer> task = null;
        List<String[]> cutList = null;

        S7ScanInfoMore scanInfo = s7ScanInfoMoreMapper.getLastS7ScanInfoMore(country);
        int round;
        if(scanInfo != null){
            round = scanInfo.getRound()+1;
        }else{
            round = 1;
        }


        for(int i=0; i<threadNum; i++){
            if(i == threadNum-1){
                if(special) break;
                cutList = ipList.subList(threadSize*i,dataSize);
            }else{
                cutList = ipList.subList(threadSize*i, threadSize*(i+1));
            }
            final List<String[]> listStr = cutList;
            final Integer no = i;

            task = new Callable<Integer>(){
                @Override
                public Integer call() throws Exception {
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
            exec.invokeAll(tasks);
        }catch (InterruptedException e){
            e.printStackTrace();
        }

        exec.shutdown();
        long et = System.currentTimeMillis();
        Date eTime = new Date(et);

        if(storeEnable){
            S7ScanInfoMore scanInfoNew = new S7ScanInfoMore();
            scanInfoNew.setTotalIps(ipList.size());
            scanInfoNew.setScannedIps(getScannedIpCounter());
            scanInfoNew.setStartTime(sTime);
            scanInfoNew.setEndTime(eTime);
            scanInfoNew.setRound(round);
            scanInfoNew.setCountry(country);
            s7ScanInfoMoreMapper.addS7ScanInfoMore(scanInfoNew);
        }
        log.info(">>>>>>>>>>>>> All (" + ipList.size() + "<-->" +getScannedIpCounter() + ") IP addresses have been scanned within " + (et-st)/1000 + " seconds.");
        log.info("*******************************************************************************************************");
    }

    public int start (boolean storeEnable, List<String[]> ipList, int round, int no, String country){
        Map<String, Integer> scanningMap = new HashMap<>();
        int count = 0;
        log.info("Start scanning thread ["+no+"] with " + ipList.size() + " ips.");
        long st = System.currentTimeMillis();
        Date sTime = new Date(st);

        int[] szlIds = {0x0011,0x0424,0x0012,0x0013,0x0014};

        //0x00::4::szlId
        for(int szlId: szlIds){
            for(int a=0; a<ipList.size(); a++){
                String ip = ipList.get(a)[0];
                int port = Integer.parseInt(ipList.get(a)[1]);
                Date startTime = new Date(System.currentTimeMillis());
                Map<String,String> resultMap = s7ScannerMore.scan(ip,0x00,4,szlId);
                String respond = resultMap.get("respond");
                Date endTime = new Date(System.currentTimeMillis());
                if(scanningMap.containsKey(respond)){
                    scanningMap.put(respond, scanningMap.get(respond)+1);
                }else{
                    scanningMap.put(respond, 1);
                }
                if(storeEnable){
                    S7ScanLogMore scanLog = new S7ScanLogMore();
                    scanLog.setIp(ip);
                    scanLog.setPort(port);
                    scanLog.setRound(round);
                    scanLog.setScanWay("0x00::4::"+szlId);
                    scanLog.setStartTime(startTime);
                    scanLog.setEndTime(endTime);
                    scanLog.setResponse(respond);
                    scanLog.setCountry(country);
                    s7ScanLogMoreMapper.addS7ScanLogMore(scanLog);
                }
                count++;
            }
            try{
                Thread.sleep(100000);
            }catch (InterruptedException e){
                throw new RuntimeException(e);
            }
        }

        //0x00::3
        for(int a=0; a<ipList.size(); a++){
            String ip = ipList.get(a)[0];
            int port = Integer.parseInt(ipList.get(a)[1]);
            Date startTime = new Date(System.currentTimeMillis());
            Map<String,String> resultMap =s7ScannerMore.scan(ip,0x00,3,0);
            String respond = resultMap.get("respond");
            Date endTime = new Date(System.currentTimeMillis());
            if(scanningMap.containsKey(respond)){
                scanningMap.put(respond, scanningMap.get(respond)+1);
            }else{
                scanningMap.put(respond, 1);
            }
            if(storeEnable){
                S7ScanLogMore scanLog = new S7ScanLogMore();
                scanLog.setIp(ip);
                scanLog.setPort(port);
                scanLog.setRound(round);
                scanLog.setScanWay("0x00::3");
                scanLog.setStartTime(startTime);
                scanLog.setEndTime(endTime);
                scanLog.setResponse(respond);
                scanLog.setCountry(country);
                s7ScanLogMoreMapper.addS7ScanLogMore(scanLog);
            }
            count++;
        }
        try{
            Thread.sleep(100000);
        }catch (InterruptedException e){
            throw new RuntimeException(e);
        }

        //0x00::7
        for(int a=0; a<ipList.size(); a++){
            String ip = ipList.get(a)[0];
            int port = Integer.parseInt(ipList.get(a)[1]);
            Date startTime = new Date(System.currentTimeMillis());
            Map<String,String> resultMap =s7ScannerMore.scan(ip,0x00,7,0);
            String respond = resultMap.get("respond");
            Date endTime = new Date(System.currentTimeMillis());
            if(scanningMap.containsKey(respond)){
                scanningMap.put(respond, scanningMap.get(respond)+1);
            }else{
                scanningMap.put(respond, 1);
            }
            if(storeEnable){
                S7ScanLogMore scanLog = new S7ScanLogMore();
                scanLog.setIp(ip);
                scanLog.setPort(port);
                scanLog.setRound(round);
                scanLog.setScanWay("0x00::7");
                scanLog.setStartTime(startTime);
                scanLog.setEndTime(endTime);
                scanLog.setResponse(respond);
                scanLog.setCountry(country);
                s7ScanLogMoreMapper.addS7ScanLogMore(scanLog);
            }
            count++;
        }
        try{
            Thread.sleep(100000);
        }catch (InterruptedException e){
            throw new RuntimeException(e);
        }

        //0x04
        for(int a=0; a<ipList.size(); a++){
            String ip = ipList.get(a)[0];
            int port = Integer.parseInt(ipList.get(a)[1]);
            Date startTime = new Date(System.currentTimeMillis());
            Map<String,String> resultMap =s7ScannerMore.scan(ip,0x04,0,0);
            String respond = resultMap.get("respond");
            Date endTime = new Date(System.currentTimeMillis());
            if(scanningMap.containsKey(respond)){
                scanningMap.put(respond, scanningMap.get(respond)+1);
            }else{
                scanningMap.put(respond, 1);
            }
            if(storeEnable){
                S7ScanLogMore scanLog = new S7ScanLogMore();
                scanLog.setIp(ip);
                scanLog.setPort(port);
                scanLog.setRound(round);
                scanLog.setScanWay("0x04");
                scanLog.setStartTime(startTime);
                scanLog.setEndTime(endTime);
                scanLog.setResponse(respond);
                scanLog.setCountry(country);
                s7ScanLogMoreMapper.addS7ScanLogMore(scanLog);
            }
            count++;
        }
        try{
            Thread.sleep(100000);
        }catch (InterruptedException e){
            throw new RuntimeException(e);
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

