package com.apiproject.control.iam;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AdminTokenHasherTest {

    @Test
    void hashesTokensAsLowercaseSha256Hex() {
        assertEquals(
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                AdminTokenHasher.hash("abc")
        );
    }

    @Test
    void rejectsBlankTokenMaterial() {
        assertThrows(
                IllegalArgumentException.class,
                () -> AdminTokenHasher.hash(null)
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> AdminTokenHasher.hash(" ")
        );
    }
}
