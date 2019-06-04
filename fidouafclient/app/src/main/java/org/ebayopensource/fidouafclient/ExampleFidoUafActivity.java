/*
 * Copyright 2015 eBay Software Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.ebayopensource.fidouafclient;

import android.app.Activity;
import android.content.Intent;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.os.Bundle;
import android.support.annotation.RequiresApi;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.TextView;

import com.google.gson.Gson;

import org.ebayopensource.fido.uaf.client.op.Auth;
import org.ebayopensource.fido.uaf.client.op.Dereg;
import org.ebayopensource.fido.uaf.client.op.Reg;
import org.ebayopensource.fido.uaf.crypto.FidoKeystore;
import org.ebayopensource.fido.uaf.crypto.FidoSigner;
import org.ebayopensource.fido.uaf.crypto.FidoSignerAndroidM;
import org.ebayopensource.fido.uaf.msg.RegistrationRequest;
import org.ebayopensource.fidouafclient.fp.FingerprintAuthProcessor;
import org.ebayopensource.fidouafclient.fp.FingerprintAuthenticationDialogFragment;
import org.ebayopensource.fidouafclient.util.Preferences;
import org.json.JSONObject;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

public class ExampleFidoUafActivity extends Activity implements FingerprintAuthProcessor {

    private static final String TAG = ExampleFidoUafActivity.class.getSimpleName();

    private static final Logger logger = Logger.getLogger(ExampleFidoUafActivity.class.getName());

    private Gson gson = new Gson();
    private TextView uafMsg;
    private Auth authOp = new Auth();

    private static final String DIALOG_FRAGMENT_TAG = "fpDialogFragment";

    private String uafMsgTxt;

    private FidoKeystore fidoKeystore;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        fidoKeystore = FidoKeystore.createKeyStore(getApplicationContext());

        Bundle extras = this.getIntent().getExtras();
        setContentView(R.layout.activity_fido_uaf);
        TextView operation = findViewById(R.id.textViewOperation);
        uafMsg = findViewById(R.id.textViewOpMsg);
        operation.setText(Objects.requireNonNull(extras).getString("UAFIntentType"));
        uafMsg.setText(Objects.requireNonNull(extras).getString("message"));
        proceed(null);
    }

    private void processOpAndFinish() {
        String uafReq = Objects.requireNonNull(this.getIntent().getExtras()).getString("message");
        Log.d(TAG, "uafReq " + uafReq);

        if (uafReq != null && uafReq.length() > 0) {
            processOp(uafReq);
        } else {
            Log.w(TAG, "uafReq is empty");
        }
    }

    private void finishWithError(String errorMessage) {
        Bundle data = new Bundle();

        data.putString("message", errorMessage);
        Intent intent = new Intent();
        intent.putExtras(data);
        setResult(RESULT_CANCELED, intent);
        finish();
    }


    private void processOp(String inUafOperationMsg) {
        Log.d(TAG, "processOp: " + inUafOperationMsg);

        try {
            uafMsgTxt = extract(inUafOperationMsg);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M && supportsFingerprintAuth()) {
                if (isAuthOp()) {
                    Log.d(TAG, "op=Auth");
                    String username = Preferences.getSettingsParam("username");
                    Log.d(TAG, "username: " + username);
                    startFingerprintAuth();
                } else if (isRegOp() || isDeregOp()) {
                    startFingerprintReg();
                }
            }
        } catch (GeneralSecurityException | SecurityException e) {
            String errorMessage = "Error : " + e.getMessage();
            Log.e(TAG, errorMessage, e);
            finishWithError(errorMessage);
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private void startFingerprintAuth() throws GeneralSecurityException {
        Signature signature = Signature.getInstance("SHA256withECDSA");
        PrivateKey privateKey = fidoKeystore.getKeyPair(
                Preferences.getSettingsParam("username")).getPrivate();
        signature.initSign(privateKey);

        FingerprintAuthenticationDialogFragment fragment
                = new FingerprintAuthenticationDialogFragment();
        FingerprintManager.CryptoObject cryptoObj = new FingerprintManager.CryptoObject(signature);
        fragment.setCryptoObject(cryptoObj);
        fragment.setStage(
                FingerprintAuthenticationDialogFragment.Stage.FINGERPRINT);

        Log.d(TAG, "Showing fragment: " + fragment);
        fragment.show(getFragmentManager(), DIALOG_FRAGMENT_TAG);
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private void startFingerprintReg() {

        FingerprintAuthenticationDialogFragment fragment
                = new FingerprintAuthenticationDialogFragment();
        fragment.setStage(
                FingerprintAuthenticationDialogFragment.Stage.FINGERPRINT);

        Log.d(TAG, "Showing fragment: " + fragment);
        fragment.show(getFragmentManager(), DIALOG_FRAGMENT_TAG);
    }

    private void returnResultAndFinish(String msg) {
        Bundle data = new Bundle();
        data.putString("message", msg);
        Intent intent = new Intent();
        intent.putExtras(data);
        setResult(RESULT_OK, intent);
        finish();
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    @Override
    public void processAuthentication(FingerprintManager.CryptoObject cryptObj) {
        Log.d(TAG, "Completed fingerprint authentication");
        // check what function processing
        if (isAuthOp()) {
            // processing authentication
            // fido signer doesn't need key pair, handled internally
            FidoSigner fidoSigner = new FidoSignerAndroidM(cryptObj.getSignature());
            String msg = authOp.auth(uafMsgTxt, fidoSigner, null);
            returnResultAndFinish(msg);
        }
        else if (isRegOp()){
            RegistrationRequest regRequest = gson.fromJson(uafMsgTxt, RegistrationRequest[].class)[0];
            Reg regOp = new Reg(regRequest.username, fidoKeystore);
            String msg = regOp.register(uafMsgTxt);
            returnResultAndFinish(msg);
        }
        else if (isDeregOp()) {
            Log.d(TAG, "op=Dereg");
            Dereg deregOp = new Dereg(Preferences.getSettingsParam("username"), fidoKeystore);
            String msg = deregOp.dereg(uafMsgTxt);
            Log.d(TAG, "msg= " + msg);
            returnResultAndFinish(msg);
        }
        else {
            Log.d(TAG, "Unable to determine what process to invoke following " +
                    "fingerprint authentication");
        }
    }

    @Override
    public void onCancel() {
        Log.d(TAG, "Fingerprint authentication cancelled");
        finishWithError("Fingerprint authentication cancelled");
    }

    private static boolean isAndroidM() {
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.M;

    }

    private boolean supportsFingerprintAuth() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            FingerprintManager fingerprintManager = getSystemService(FingerprintManager.class);

            // noinspection ResourceType
            return Objects.requireNonNull(fingerprintManager).isHardwareDetected()
                    && fingerprintManager.hasEnrolledFingerprints();
        }

        return false;
     }

    public void proceed(View view) {
        if (isAndroidM() && supportsFingerprintAuth()) processOpAndFinish();
    }

    private boolean isAuthOp() {
        // XXX uglish, needed to avoid double auth in case of Android M+
        if (uafMsgTxt.contains("\"Auth\"")) {
            Log.d(TAG, "op=Auth");
            return true;
        }

        return false;
    }

    private boolean isRegOp() {
        // XXX uglish, needed to avoid double auth in case of Android M+
        if (uafMsgTxt.contains("\"Reg\"")) {
            Log.d(TAG, "op=Reg");
            return true;
        }

        return false;
    }

    private boolean isDeregOp() {
        // XXX uglish, needed to avoid double auth in case of Android M+
        if (uafMsgTxt.contains("\"Dereg\"")) {
            Log.d(TAG, "op=Dereg");
            return true;
        }

        return false;
    }

    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        int REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS = 1;
        if (requestCode == REQUEST_CODE_CONFIRM_DEVICE_CREDENTIALS) {
            // Challenge completed, proceed with using cipher
            if (resultCode == RESULT_OK) {
                processOpAndFinish();
            } else {
                // The user canceled or didn’t complete the lock screen
                // operation. Go to error/cancellation flow.
                String errorMessage = "User cancelled credential verification";
                Log.w(TAG, errorMessage);
                finishWithError(errorMessage);
            }
        }
    }

    public void back(View view) {
        Bundle data = new Bundle();
        String msg = "";
        logger.info("Registration canceled by user");
        data.putString("message", msg);
        Intent intent = new Intent();
        intent.putExtras(data);
        setResult(RESULT_OK, intent);
        finish();
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();
        if (id == R.id.action_settings) {
            startActivity(new Intent(
                    "org.ebayopensource.fidouafclient.SettingsActivity"));
        }
        if (id == R.id.action_save_message) {
            SaveMessageDialog.show(this, uafMsg);
        }
        return super.onOptionsItemSelected(item);
    }

    private String extract(String inMsg) {
        try {
            JSONObject tmpJson = new JSONObject(inMsg);
            return tmpJson.getString("uafProtocolMessage").replace("\\\"", "\"");
        } catch (Exception e) {
            logger.log(Level.WARNING, "Input message is invalid!", e);
            return "";
        }

    }
}
