package com.sia.icsdeviceidentifier.core.scanners.s7;

public class S7SZLReceiver {
    private String index;    // Index: 模块标识等
    private String mlfb;     // MLFB: 模块订单号
    private String bgTyp;    // BGTyp: 模块类型ID
    private String ausbg;    // Ausbg: 模块版本或操作系统版本
    private String ausbe;    // Ausbe: 描述文件的版本

    // 构造函数，用于初始化各个字段
    public S7SZLReceiver(String index, String mlfb, String bgTyp, String ausbg, String ausbe) {
        this.index = index;
        this.mlfb = mlfb;
        this.bgTyp = bgTyp;
        this.ausbg = ausbg;
        this.ausbe = ausbe;
    }

    // 各字段的getter方法
    public String getIndex() {
        return index;
    }

    public String getMlfb() {
        return mlfb;
    }

    public String getBgTyp() {
        return bgTyp;
    }

    public String getAusbg() {
        return ausbg;
    }

    public String getAusbe() {
        return ausbe;
    }

    // 将所有成员对象打印出来
    @Override
    public String toString() {
        return "S7SZLReceiver{" +
                "Index='" + index + '\'' +
                ", MLFB='" + mlfb + '\'' +
                ", BGTyp='" + bgTyp + '\'' +
                ", Ausbg='" + ausbg + '\'' +
                ", Ausbe='" + ausbe + '\'' +
                '}';
    }
}
