package com.justinribeiro.demo.apps.hostcardemulation;

import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.nfc.NdefMessage;
import android.nfc.NdefRecord;
import android.nfc.cardemulation.HostApduService;
import android.os.Bundle;
import android.util.Log;
import android.view.Gravity;
import android.widget.Toast;

import java.math.BigInteger;
import java.nio.charset.Charset;
import java.util.Arrays;

/**
 * Created by justin.ribeiro on 10/27/2014.
 *
 * The following definitions are based on two things:
 *   1. NFC Forum Type 4 Tag Operation Technical Specification, version 3.0 2014-07-30
 *   2. APDU example in libnfc: http://nfc-tools.org/index.php?title=Libnfc:APDU_example
 *
 */
public class myHostApduService extends HostApduService {

    private static final String TAG = "JDR HostApduService";

    //
    // We use the default AID from the HCE Android documentation
    // https://developer.android.com/guide/topics/connectivity/nfc/hce.html
    //
    // Ala... <aid-filter android:name="F0394148148100" />
    //
    private static final byte[] APDU_SELECT = {
        (byte)0x00, // CLA	- Class - Class of instruction
        (byte)0xA4, // INS	- Instruction - Instruction code
        (byte)0x04, // P1	- Parameter 1 - Instruction parameter 1
        (byte)0x00, // P2	- Parameter 2 - Instruction parameter 2
        (byte)0x07, // Lc field	- Number of bytes present in the data field of the command
        (byte)0xD2, 0x76, 0x00, 0x00, (byte)0x85, 0x01, 0x01,
        //(byte)0xF0, (byte)0x39, (byte)0x41, (byte)0x48, (byte)0x14, (byte)0x81, (byte)0x00, // NDEF Tag Application name
        (byte)0x00  // Le field	- Maximum number of bytes expected in the data field of the response to the command
    };

    private static final byte[] CAPABILITY_CONTAINER = {
            (byte)0x00, // CLA	- Class - Class of instruction
            (byte)0xa4, // INS	- Instruction - Instruction code
            (byte)0x00, // P1	- Parameter 1 - Instruction parameter 1
            (byte)0x0c, // P2	- Parameter 2 - Instruction parameter 2
            (byte)0x02, // Lc field	- Number of bytes present in the data field of the command
            (byte)0xe1, (byte)0x03 // file identifier of the CC file
    };

    private static final byte[] READ_CAPABILITY_CONTAINER = {
            (byte)0x00, // CLA	- Class - Class of instruction
            (byte)0xb0, // INS	- Instruction - Instruction code
            (byte)0x00, // P1	- Parameter 1 - Instruction parameter 1
            (byte)0x00, // P2	- Parameter 2 - Instruction parameter 2
            (byte)0x0f  // Lc field	- Number of bytes present in the data field of the command
    };

    // In the scenario that we have done a CC read, the same byte[] match
    // for ReadBinary would trigger and we don't want that in succession
    private int readStage = 0;
    private final static int READ_HEADER = 0;
    private final static int READ_STAGE_CAPABILITY_CONTAINER = 1;
    private final static int READ_NDEF = 2;

    private static final byte[] READ_CAPABILITY_CONTAINER_RESPONSE = {
            (byte)0x00, (byte)0x0F, // CCLEN length of the CC file
            (byte)0x20, // Mapping Version 2.0
            (byte)0x00, (byte)0xff, // MLe maximum 59 bytes R-APDU data size
            (byte)0x00, (byte)0xff, // MLc maximum 52 bytes C-APDU data size
            (byte)0x04, // T field of the NDEF File Control TLV
            (byte)0x06, // L field of the NDEF File Control TLV
            (byte)0xE1, (byte)0x04, // File Identifier of NDEF file
            (byte)0x00, (byte)0xff, // Maximum NDEF file size of 50 bytes
            (byte)0x00, // Read access without any security
            (byte)0x00, // Write access without any security
            (byte)0x90, (byte)0x00 // A_OKAY
    };

    private static final byte[] NDEF_SELECT = {
            (byte)0x00, // CLA	- Class - Class of instruction
            (byte)0xa4, // Instruction byte (INS) for Select command
            (byte)0x00, // Parameter byte (P1), select by identifier
            (byte)0x0c, // Parameter byte (P1), select by identifier
            (byte)0x02, // Lc field	- Number of bytes present in the data field of the command
            (byte)0xE1, (byte)0x04 // file identifier of the NDEF file retrieved from the CC file
    };

    private static final byte[] NDEF_READ_BINARY_NLEN = {
            (byte)0x00, // Class byte (CLA)
            (byte)0xb0, // Instruction byte (INS) for ReadBinary command
            (byte)0x00, (byte)0x00, // Parameter byte (P1, P2), offset inside the CC file
            (byte)0x02  // Le field - length field
    };

    private static final byte[] NDEF_READ_BINARY_GET_NDEF = {
            (byte)0x00, // Class byte (CLA)
            (byte)0xb0, // Instruction byte (INS) for ReadBinary command
            (byte)0x00, (byte)0x00, // Parameter byte (P1, P2), offset inside the CC file
            (byte)0x0f  //  Le field
    };

    private static final byte[] A_OKAY = {
            (byte)0x90,  // SW1	Status byte 1 - Command processing status
            (byte)0x00   // SW2	Status byte 2 - Command processing qualifier
    };

    private static final byte[] NDEF_ID = {
            (byte)0xE1,
            (byte)0x04
    };

    private NdefRecord NDEF_URI = new NdefRecord(
            NdefRecord.TNF_WELL_KNOWN,
            NdefRecord.RTD_TEXT,
            NDEF_ID,
            "Hello world!".getBytes(Charset.forName("UTF-8"))
    );
    private byte[] NDEF_URI_BYTES = NDEF_URI.toByteArray();
    private byte[] NDEF_URI_LEN = BigInteger.valueOf(NDEF_URI_BYTES.length).toByteArray();

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {

        if (intent.hasExtra("ndefMessage")) {

            NDEF_URI = new NdefRecord(
                    NdefRecord.TNF_WELL_KNOWN,
                    NdefRecord.RTD_TEXT,
                    NDEF_ID,
                    intent.getStringExtra("ndefMessage").getBytes(Charset.forName("UTF-8"))
            );

            // zhuowei: modified
            // https://stackoverflow.com/q/22357664
            NdefRecord uriNdefRecord = NdefRecord.createUri(Uri.parse(intent.getStringExtra("ndefMessage"))); //RTD_URI
            NdefRecord uuidRecord = NdefRecord.createTextRecord("EN", intent.getStringExtra("ndefUuid")); //RTD_URI
            NdefMessage smartPosterContentMessage = new NdefMessage(new NdefRecord[] {uriNdefRecord, uuidRecord});

            NdefRecord smartPosterTopLevelRecord = new NdefRecord(
                    NdefRecord.TNF_WELL_KNOWN,
                    NdefRecord.RTD_SMART_POSTER,
                    NDEF_ID,
                    smartPosterContentMessage.toByteArray());
            NdefRecord theUrl = NdefRecord.createUri("https://www.flipkick.io/authenticate");
            NDEF_URI = theUrl;
            NdefMessage theWholeTopLevelRecord = new NdefMessage(theUrl, smartPosterTopLevelRecord);

            NDEF_URI_BYTES = theWholeTopLevelRecord.toByteArray();
            NDEF_URI_LEN = new byte[] {(byte)((NDEF_URI_BYTES.length >> 8) & 0xff), (byte)(NDEF_URI_BYTES.length & 0xff)};
            Log.i(TAG, "ok " + utils.bytesToHex(NDEF_URI_BYTES) + ":" + utils.bytesToHex(NDEF_URI_BYTES));
            Log.i(TAG, "bytes" + utils.bytesToHex(NDEF_URI_BYTES) + ":" + utils.bytesToHex(NDEF_URI_LEN));

            Context context = getApplicationContext();
            CharSequence text = "Your NDEF text has been set!";
            int duration = Toast.LENGTH_SHORT;
            Toast toast = Toast.makeText(context, text, duration);
            toast.setGravity(Gravity.CENTER, 0, 0);
            toast.show();
        }

        Log.i(TAG, "onStartCommand() | NDEF" + NDEF_URI.toString());

        return 0;
    }

    @Override
    public byte[] processCommandApdu(byte[] commandApdu, Bundle extras) {

        //
        // The following flow is based on Appendix E "Example of Mapping Version 2.0 Command Flow"
        // in the NFC Forum specification
        //
        Log.i(TAG, "processCommandApdu() | incoming commandApdu: " + utils.bytesToHex(commandApdu));
        Log.i(TAG, "stage " + readStage);
        //
        // First command: NDEF Tag Application select (Section 5.5.2 in NFC Forum spec)
        //
        if (utils.isEqual(APDU_SELECT, commandApdu)) {
            Log.i(TAG, "APDU_SELECT triggered. Our Response: " + utils.bytesToHex(A_OKAY));
            readStage = READ_HEADER;
            return A_OKAY;
        }

        //
        // Second command: Capability Container select (Section 5.5.3 in NFC Forum spec)
        //
        if (utils.isEqual(CAPABILITY_CONTAINER, commandApdu)) {
            Log.i(TAG, "CAPABILITY_CONTAINER triggered. Our Response: " + utils.bytesToHex(A_OKAY));
            readStage = READ_STAGE_CAPABILITY_CONTAINER;
            return A_OKAY;
        }

        //
        // Third command: ReadBinary data from CC file (Section 5.5.4 in NFC Forum spec)
        //
        if (utils.isEqual(READ_CAPABILITY_CONTAINER, commandApdu) && readStage == READ_STAGE_CAPABILITY_CONTAINER) {
            Log.i(TAG, "READ_CAPABILITY_CONTAINER triggered. Our Response: " + utils.bytesToHex(READ_CAPABILITY_CONTAINER_RESPONSE));
            return READ_CAPABILITY_CONTAINER_RESPONSE;
        }

        //
        // Fourth command: NDEF Select command (Section 5.5.5 in NFC Forum spec)
        //
        if (utils.isEqual(NDEF_SELECT, commandApdu)) {
            Log.i(TAG, "NDEF_SELECT triggered. Our Response: " + utils.bytesToHex(A_OKAY));
            readStage = READ_NDEF;
            return A_OKAY;
        }

        //
        // Fifth command:  ReadBinary, read NLEN field
        //
        if (readStage == READ_NDEF && commandApdu.length == 5 && commandApdu[0] == 0x00 && commandApdu[1] == (byte)0xb0) {

            int readLength = (commandApdu[4] & 0xff);
            byte[] response = new byte[readLength + A_OKAY.length];

            byte[] theCrap = new byte[NDEF_URI_LEN.length + NDEF_URI_BYTES.length];
            System.arraycopy(NDEF_URI_LEN, 0, theCrap, 0, NDEF_URI_LEN.length);
            System.arraycopy(NDEF_URI_BYTES, 0, theCrap, NDEF_URI_LEN.length, NDEF_URI_BYTES.length);

            System.arraycopy(theCrap, commandApdu[3] & 0xff, response, 0, readLength);
            System.arraycopy(A_OKAY, 0, response, readLength, A_OKAY.length);

            Log.i(TAG, response.toString());
            Log.i(TAG, "NDEF_READ_BINARY_NLEN triggered. Our Response: " + utils.bytesToHex(response));

            return response;
        }

        //
        // We're doing something outside our scope
        //
        Log.wtf(TAG, "processCommandApdu() | I don't know what's going on!!!.");
        return "Can I help you?".getBytes();
    }

    @Override
    public void onDeactivated(int reason) {
        Log.i(TAG, "onDeactivated() Fired! Reason: " + reason);
    }
}
