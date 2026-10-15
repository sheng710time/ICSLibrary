package org.icslibrary;

import org.icslibrary.core.schedulers.enip.EnipSchedulerMultiTMore;
import org.icslibrary.core.schedulers.modbus.ModbusSchedulerMultiTMore;
import org.icslibrary.core.schedulers.s7.S7SchedulerMultiTMore;
import org.icslibrary.util.CSVUtil;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.ArrayList;
import java.util.List;

@SpringBootTest
@Slf4j
class ScannersMoreTest {

    @Autowired
    public ModbusSchedulerMultiTMore modbusSchedulerMultiTMore;

    @Autowired
    public S7SchedulerMultiTMore s7SchedulerMultiTMore;

    @Autowired
    public EnipSchedulerMultiTMore enipSchedulerMultiTMore;


    @Test
    void modbusScanDBMultiTMore() throws InterruptedException {
        boolean storeEnable = true;
        int coreThreadNum = 100;
        int threadSize = 100;
        String region = "Region A";
        modbusSchedulerMultiTMore.modbusScanDB(storeEnable, coreThreadNum, threadSize, region);
        log.info("modbusScanDBMultiTMore");
    }


    @Test
    void s7ScanDBMultiTMore() throws InterruptedException {
        boolean storeEnable = true;
        int coreThreadNum = 100;
        int threadSize = 100;
        String region = "Region A";
        s7SchedulerMultiTMore.s7ScanDB(storeEnable, coreThreadNum, threadSize, region);
    }


    @Test
    void enipScanDBMultiTMore() {
        boolean storeEnable = true;
        int coreThreadNum = 100;
        int threadSize = 100;
        String region = "Region A";
        enipSchedulerMultiTMore.enipScanDB(storeEnable, coreThreadNum, threadSize, region);
        log.info("enipScanDBMultiT");
    }

}

