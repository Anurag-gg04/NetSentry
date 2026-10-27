package com.netsentry.util;

import java.net.InetAddress;

public final class IpValidator {

    private IpValidator() {
    }

    public static boolean isValid(String value) {
        if (value == null || value.isBlank() || value.length() > 45)
            return false;
        String ip = value.trim();
        if (ip.contains(":")) {
            if (!ip.matches("[0-9a-fA-F:.%]+"))
                return false;
            try {
                return InetAddress.getByName(ip).getAddress().length == 16;
            } catch (Exception ignored) {
                return false;
            }
        }
        String[] parts = ip.split("\\.", -1);
        if (parts.length != 4)
            return false;
        for (String part : parts) {
            if (part.isEmpty() || !part.matches("\\d{1,3}"))
                return false;
            try {
                int n = Integer.parseInt(part);
                if (n < 0 || n > 255)
                    return false;
            } catch (NumberFormatException ex) {
                return false;
            }
        }
        return true;
    }
}
