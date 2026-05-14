package org.icslibrary.core.scanners.s7;

public class S7SZLReceiver {
    private String index;    // Index: module identifier and related metadata
    private String mlfb;     // MLFB: module order number
    private String bgTyp;    // BGTyp: module type identifier
    private String ausbg;    // Ausbg: module or operating-system version
    private String ausbe;    // Ausbe: description-file version

    // Constructor used to initialize all parsed fields.
    public S7SZLReceiver(String index, String mlfb, String bgTyp, String ausbg, String ausbe) {
        this.index = index;
        this.mlfb = mlfb;
        this.bgTyp = bgTyp;
        this.ausbg = ausbg;
        this.ausbe = ausbe;
    }

    // Getter methods for each field.
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

    // Print all member fields for debugging.
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

