/*
 * Copyright (C) 2015 The MITRE Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * NOTICE
 * This software was produced for the U.S. Government under Basic
 * Contract No. W15P7T-13-C-A802, and is subject to the Rights in
 * Noncommercial Computer Software and Noncommercial Computer
 * Software Documentation Clause 252.227-7014
 * (FEB 2012)
 */


package com.example.android.basicmanagedprofile;

import android.app.IntentService;
import android.app.admin.DevicePolicyManager;
import android.content.Context;
import android.content.Intent;
import android.content.res.AssetManager;
import android.security.KeyChain;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.Signature;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;

public class EnrollIntentService extends IntentService {
    public EnrollIntentService() {
        super("EnrollIntentService");
    }

    @Override
    protected void onHandleIntent(Intent intent) {
        try {
            String alias = intent.getExtras().getString("alias");
            String algorithm = intent.getExtras().getString("algorithm");
            int keysize = intent.getExtras().getInt("keysize");
            final DevicePolicyManager manager =
                (DevicePolicyManager) getSystemService(Context.DEVICE_POLICY_SERVICE);
            byte[] pubKeyBytes = manager.generateKeyPair(BasicDeviceAdminReceiver.getComponentName(this),
                    alias, algorithm, keysize);
            SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(pubKeyBytes);
            X500Name X500subject = new X500Name("CN=" + alias);
            final CertificationRequestInfo cri = new CertificationRequestInfo(X500subject, spki,
                    null);
            final byte[] encoding = cri.getEncoded();
            PrivateKey pk = KeyChain.getPrivateKey(this, alias);
            String sigAlg;
            AlgorithmIdentifier ai;
            if (KeyProperties.KEY_ALGORITHM_RSA.equals(algorithm)) {
                sigAlg = "sha256WithRSA";
                ai = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption);
            } else if (KeyProperties.KEY_ALGORITHM_EC.equals(algorithm) &&
                    keysize == 256) {
                sigAlg = "sha256WithECDSA";
                ai = new AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA256);
            } else if (KeyProperties.KEY_ALGORITHM_EC.equals(algorithm) &&
                    keysize == 384) {
                sigAlg = "sha384WithECDSA";
                ai = new AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA256);
            } else {
                return;
            }
            Signature s = Signature.getInstance(sigAlg);
            s.initSign(pk);
            s.update(encoding);
            byte[] sig = s.sign();
            CertificationRequest csr = new CertificationRequest(cri, ai, new DERBitString(sig));
            byte[] csrB64 = android.util.Base64.encode(csr.getEncoded(), Base64.DEFAULT);
            String BEGIN = "-----BEGIN CERTIFICATE REQUEST-----\n";
            String END = "-----END CERTIFICATE REQUEST-----";
            byte[] beginByte = new byte[BEGIN.length()];
            byte[] endByte = new byte[END.length()];
            beginByte = BEGIN.getBytes("UTF-8");
            endByte = END.getBytes("UTF-8");
            byte[] fullcsrB64 = new byte[beginByte.length + csrB64.length + endByte.length];
            System.arraycopy(beginByte, 0, fullcsrB64, 0, beginByte.length);
            System.arraycopy(csrB64, 0, fullcsrB64, beginByte.length, csrB64.length);
            System.arraycopy(endByte, 0, fullcsrB64, beginByte.length + csrB64.length, endByte.length);

            FileOutputStream fos = openFileOutput(alias + ".csr", Context.MODE_PRIVATE);
            fos.write(fullcsrB64);
            fos.close();
            File oldcertFile = new File(getFilesDir().getAbsolutePath(), "newcert.pem");
            if (oldcertFile.exists()) {
                oldcertFile.delete();
            }
            extractFile(this, "estclient");
            extractFile(this, "libcrypto.so.1.0.0");
            extractFile(this, "libssl.so.1.0.0");
            extractFile(this, "qvrca2.pem");
            String[] envp = {
                    "LD_LIBRARY_PATH=" + getFilesDir().getAbsolutePath(),
                    "EST_OPENSSL_CACERT=" + getFilesDir().getAbsolutePath() + File.separator + "qvrca2.pem"
            };
            String[] progarray = {
                    getFilesDir().getAbsolutePath() + File.separator + "estclient",
                    "-e", "-s", "testrfc7030.cisco.com", "-p", "8443", "-u", "estuser",
                    "-h", "estpwd", "-o",
                    getFilesDir().getAbsolutePath(), "-y", alias + ".csr", "--pem-output"
            };
            StringBuffer output = new StringBuffer();
            Process p = Runtime.getRuntime().exec(progarray, envp, getFilesDir());
            p.waitFor();
            // Issued cert is in newcert.pem .
            FileInputStream newcert = openFileInput("newcert.pem");
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            int nRead;
            byte[] data = new byte[256];
            while ((nRead = newcert.read(data, 0, data.length)) != -1) {
                baos.write(data, 0, nRead);
            }
            baos.flush();
            byte[] newCertPEM = baos.toByteArray();
            // remove first 28 char -----BEGIN CERTIFICATE REQUEST-----\n
            // and last 27 char -----END CERTIFICATE REQUEST-----
            byte[] newCertPEM2 = new byte[newCertPEM.length - 28];
            System.arraycopy(newCertPEM, 28, newCertPEM2, 0, newCertPEM.length - 28);
            byte[] newCertPEM3 = new byte[newCertPEM2.length - 27];
            System.arraycopy(newCertPEM2, 0, newCertPEM3, 0, newCertPEM2.length - 27);
            byte[] newCertDER = Base64.decode(newCertPEM3, Base64.DEFAULT);
            manager.setCertificate(BasicDeviceAdminReceiver.getComponentName(this),
                    alias, newCertDER, false);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void extractFile(Context context, String name) {
        try {
            AssetManager assetManager = getAssets();
            InputStream in = assetManager.open(name);
            FileOutputStream fos1 = openFileOutput(name, Context.MODE_PRIVATE);
            byte[] buffer = new byte[256];
            int bytesRead = 0;
            while ((bytesRead = in.read(buffer)) != -1) {
                fos1.write(buffer, 0, bytesRead);
            }
            in.close();
            fos1.flush();
            fos1.close();
            File file1 = new File(context.getFilesDir(), name);
            file1.setExecutable(true);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

