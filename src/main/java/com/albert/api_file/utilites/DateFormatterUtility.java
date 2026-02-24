package com.albert.api_file.utilites;

import java.time.format.DateTimeFormatter;

public class DateFormatterUtility {
    public static final DateTimeFormatter DATE_TIME_FORMATTER =
            DateTimeFormatter.ofPattern("EEEE d MMMM yyyy HH:mm");
}
