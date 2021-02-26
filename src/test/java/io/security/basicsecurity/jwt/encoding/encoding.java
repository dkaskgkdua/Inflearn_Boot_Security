package io.security.basicsecurity.jwt.encoding;

import org.junit.jupiter.api.Test;

import java.util.Base64;

public class encoding {
    @Test
    public void base64Test() throws Exception {

        byte[] en = Base64.getDecoder().decode("thisistesttest");
        for(byte e:  en) {
            System.out.println(e);
        }

    }
}
