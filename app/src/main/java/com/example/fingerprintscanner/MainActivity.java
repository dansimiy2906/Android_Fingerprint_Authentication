package com.example.fingerprintscanner;

import androidx.annotation.RequiresApi;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;

import android.Manifest;
import android.annotation.TargetApi;
import android.app.KeyguardManager;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.widget.ImageView;
import android.widget.TextView;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

@RequiresApi(api = Build.VERSION_CODES.M)
public class MainActivity extends AppCompatActivity {

    private TextView mHeadingLabel;
    private ImageView mFingerPrintImage;
    private TextView mparaLabel;

    private FingerprintManager fingerprintManager;
    private KeyguardManager keyguardmanager;
    private KeyStore keyStore;
    private Cipher cipher;
    private String KEY_NAME = "AndroidKey";


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        mHeadingLabel = (TextView) findViewById(R.id.headingLabel);
        mFingerPrintImage = (ImageView) findViewById(R.id.fingerprintImage);
        mparaLabel = (TextView) findViewById(R.id.paraLabel);

        //  check 1: Android Version Should be Greater of Equal to Mashmallow
        //  check 2: Device has Fingerprint Scanner
        //  check 3: Have permission to use Fingerprint scanner in app
        //  check 4: Lock screen is secured with atleast one type of lock
        //  check 5: Atleast one Fingerprint is registered in the device

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {

            fingerprintManager = (FingerprintManager) getSystemService(FINGERPRINT_SERVICE);
            keyguardmanager = (KeyguardManager) getSystemService(KEYGUARD_SERVICE);

            if (!fingerprintManager.isHardwareDetected()){
                mparaLabel.setText("FingerPrint Scanner not detected in this Device");

            }

            else if(ContextCompat.checkSelfPermission(this, Manifest.permission.USE_FINGERPRINT) !=
                    getPackageManager().PERMISSION_GRANTED){

                mparaLabel.setText("Permission not granted to use Fingerprint scanner");

            }

            else if(!keyguardmanager.isKeyguardSecure()){
                mparaLabel.setText("Add phone lock to your device");

            }
            else if(!fingerprintManager.hasEnrolledFingerprints()){
                mparaLabel.setText("No fingerprint has been Enrolled Yet");


            }
            else{
                mparaLabel.setText("Place your Finger on scanner to access the app");
                generateKey();
                if (cipherInit()) {
                    FingerprintManager.CryptoObject cryptoObject = new FingerprintManager.CryptoObject(cipher);
                    FingerPrintHandler fingerprinthandler = new FingerPrintHandler(this);
                    fingerprinthandler.startAuth(fingerprintManager, cryptoObject);
                }



            }

        }

    }

    @TargetApi(Build.VERSION_CODES.M)
    private void generateKey() {

        try {

            keyStore = KeyStore.getInstance("AndroidKeyStore");
            KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");

            keyStore.load(null);
            keyGenerator.init(new
                    KeyGenParameterSpec.Builder(KEY_NAME,
                    KeyProperties.PURPOSE_ENCRYPT |
                            KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setUserAuthenticationRequired(true)
                    .setEncryptionPaddings(
                            KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .build());
            keyGenerator.generateKey();

        } catch (IOException | CertificateException | NoSuchAlgorithmException | InvalidAlgorithmParameterException | NoSuchProviderException | KeyStoreException e) {

            e.printStackTrace();

        }

    }

    @TargetApi(Build.VERSION_CODES.M)
    public boolean cipherInit() {
        try {
            cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/" + KeyProperties.BLOCK_MODE_CBC + "/" + KeyProperties.ENCRYPTION_PADDING_PKCS7);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException("Failed to get Cipher", e);
        }


        try {

            keyStore.load(null);

            SecretKey key = (SecretKey) keyStore.getKey(KEY_NAME,
                    null);

            cipher.init(Cipher.ENCRYPT_MODE, key);

            return true;

        } catch (KeyPermanentlyInvalidatedException e) {
            return false;
        } catch (KeyStoreException | CertificateException | UnrecoverableKeyException | IOException | NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException("Failed to init Cipher", e);
        }

    }
}