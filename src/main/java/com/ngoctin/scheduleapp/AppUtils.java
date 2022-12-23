package com.ngoctin.scheduleapp;

import java.util.Date;

public class AppUtils {

    public static String generateID(){
        return "U".concat(new Date().getTime() + "");
    }

}
