package uk.co.mulecode.pgp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.Iterator;
import lombok.Builder;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.jcajce.JcaPGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import uk.co.mulecode.pgp.exception.PGPDecryptException;

@Slf4j
public class PGPDecryptSign {

  private InputStream publicVerifierKey;

  private InputStream encryptedData;
  private InputStream privateKey;
  private char[] passPhrase;

  private InputStream decryptedContent;

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  @Builder
  public PGPDecryptSign(InputStream encryptedData, InputStream privateKey, char[] passPhrase,
      InputStream publicVerifierKey) {
    this.encryptedData = encryptedData;
    this.privateKey = privateKey;
    this.passPhrase = passPhrase;
    this.publicVerifierKey = publicVerifierKey;
  }

  public InputStream getDecryptContent() {
    return this.decryptedContent;
  }

  public String getDecryptContentAsString() {
    try {
      return IOUtils.toString(decryptedContent, StandardCharsets.UTF_8.name());
    } catch (IOException e) {
      throw new PGPDecryptException("Failure to decrypt", e);
    }
  }

  public PGPDecryptSign decrypt() throws Exception {

    InputStream decoderStream = PGPUtil.getDecoderStream(encryptedData);
    PGPObjectFactory pgpFact = new JcaPGPObjectFactory(decoderStream);

    PGPEncryptedDataList encryptedDataList;
    Object message = pgpFact.nextObject();

//    if (message instanceof PGPCompressedData) {
//      log.info("message is PGPCompressedData");
//      PGPCompressedData compressedData = (PGPCompressedData) message;
//      pgpFact = new JcaPGPObjectFactory(compressedData.getDataStream());
//      message = pgpFact.nextObject();
//      log.info("message is PGPCompressedData - next: {}", message.getClass());
//    }

    if (message instanceof PGPEncryptedDataList) {
      log.info("message is PGPEncryptedDataList");
      encryptedDataList = (PGPEncryptedDataList) message;
      decryptedContent = getDecryptionStream(encryptedDataList);
      decryptedContent = getDecryptedData(decryptedContent);
      message = pgpFact.nextObject();
    }

    if (message == null) {
      log.info("is null");
      return this;
    }

//    PGPOnePassSignatureList p1 = (PGPOnePassSignatureList) pgpFact.nextObject();
//    PGPOnePassSignature ops = p1.get(0);
//
//    PGPLiteralData p2 = (PGPLiteralData) pgpFact.nextObject();
//    InputStream dIn = p2.getInputStream();
//
//    int ch;
//    PGPPublicKeyRingCollection pgpRing = new JcaPGPPublicKeyRingCollection(PGPUtil.getDecoderStream(publicVerifierKey));
//    PGPPublicKey key = pgpRing.getPublicKey(ops.getKeyID());
//
//    ByteArrayOutputStream out = new ByteArrayOutputStream();
//
//    ops.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), key);
//    while ((ch = dIn.read()) >= 0) {
//      ops.update((byte) ch);
//      out.write(ch);
//    }
//    out.close();
//
//    PGPSignatureList p3 = (PGPSignatureList) pgpFact.nextObject();
//    if (ops.verify(p3.get(0))) {
//      System.out.println("signature verified.");
//    } else {
//      System.out.println("signature verification failed.");
//    }
    return this;
  }

  public PGPDecryptSign decrypt2() {
    try {
      InputStream decoderStream = PGPUtil.getDecoderStream(encryptedData);
      JcaPGPObjectFactory objectFactory = new JcaPGPObjectFactory(decoderStream);
      PGPEncryptedDataList cryptedDataList = getDataList(objectFactory);

      PGPPublicKeyEncryptedData encP = (PGPPublicKeyEncryptedData) cryptedDataList.get(0);
      log.info("cryptedDataList {}", cryptedDataList.size());

      InputStream clearStream = encP.getDataStream(new BcPublicKeyDataDecryptorFactory(getPGPPrivateKey(encP.getKeyID())));

      PGPObjectFactory plainFact = new JcaPGPObjectFactory(clearStream);

      Object message = plainFact.nextObject();

      if (message instanceof PGPCompressedData) {
        log.info("message is PGPCompressedData");
        PGPCompressedData compressedData = (PGPCompressedData) message;
        plainFact = new PGPObjectFactory(compressedData.getDataStream(), new JcaKeyFingerprintCalculator());
        message = plainFact.nextObject();
      }

      if (message instanceof PGPLiteralData) {
        log.info("message is PGPLiteralData");
        PGPLiteralData literalData = (PGPLiteralData) message;
        decryptedContent = literalData.getInputStream();
      }

      return this;
    } catch (Exception e) {
      throw new PGPDecryptException("Failure to decrypt", e);
    }
  }

  private PGPPublicKeyRingCollection getPGPPublicKeyRingCollection() throws Exception {
    return new PGPPublicKeyRingCollection(
        this.publicVerifierKey,
        new JcaKeyFingerprintCalculator());
  }

  private PGPSecretKeyRing getPGPSecretKeyRing() throws Exception {
    return new PGPSecretKeyRing(
        PGPUtil.getDecoderStream(privateKey),
        new BcKeyFingerprintCalculator()
    );
  }

  private PGPSecretKey getPgpSecretKey(Long id) throws Exception {
    PGPSecretKeyRing secretKeyRing = getPGPSecretKeyRing();
    final PGPSecretKey key = secretKeyRing.getSecretKey(id);

    if (key == null) {
      throw new IOException("Can't find encryption key in key ring.");
    }

    return key;
  }

//  private PGPSecretKey getPgpSecretKey() throws Exception {
//    Iterator it = getPGPSecretKeyRing().getSecretKeys();
//    while (it.hasNext()) {
//      PGPSecretKey secretKey = (PGPSecretKey) it.next();
//      if (!secretKey.isSigningKey()) {
//        return secretKey;
//      }
//    }
//    throw new IOException("No crypting key found.");
//  }

  private PGPPrivateKey getPGPPrivateKey(Long id) throws Exception {
    return getPgpSecretKey(id)
        .extractPrivateKey(
            new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider())
                .build(this.passPhrase)
        );
  }

  private PGPSecretKey readSecretKeyFromCol(InputStream keyMaterialStream, final long keyId) throws IOException, PGPException {
    InputStream in = PGPUtil.getDecoderStream(keyMaterialStream);
    final PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(in, new BcKeyFingerprintCalculator());
    final PGPSecretKey key = pgpSec.getSecretKey(keyId);

    if (key == null) {
      throw new IllegalArgumentException("Can't find encryption key in key ring.");
    }
    return key;
  }

  private PGPEncryptedDataList getDataList(JcaPGPObjectFactory objectFactory) throws IOException {
    Object object = objectFactory.nextObject();
    // The first object might be a PGP marker packet.
    if (object instanceof PGPEncryptedDataList) {
      return (PGPEncryptedDataList) object;
    }
    return (PGPEncryptedDataList) objectFactory.nextObject();
  }

  private InputStream getDecryptionStream(PGPEncryptedDataList encDataList)
      throws IOException, PGPException {

    Iterator encDataIterator = encDataList.getEncryptedDataObjects();

    PGPPrivateKey privateKey = null;
    PGPPublicKeyEncryptedData encP = null;
    while (privateKey == null && encDataIterator.hasNext()) {
      encP = (PGPPublicKeyEncryptedData) encDataIterator.next();
      PGPSecretKey secretKey = readSecretKeyFromCol(this.privateKey, encP.getKeyID());
      privateKey = secretKey
          .extractPrivateKey(new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(this.passPhrase));
    }

    if (privateKey == null) {
      throw new IllegalArgumentException("Secret key for message not found.");
    }

    return encP.getDataStream(new BcPublicKeyDataDecryptorFactory(privateKey));
  }

  private InputStream getDecryptedData(InputStream decryptionStream) throws PGPException, IOException {
    JcaPGPObjectFactory plainFact = new JcaPGPObjectFactory(decryptionStream);
    JcaPGPObjectFactory pgpFact = null;
    Object message = plainFact.nextObject();

    if (message instanceof PGPCompressedData) {
      log.info("message is PGPCompressedData");
      PGPCompressedData cData = (PGPCompressedData) message;
      pgpFact = new JcaPGPObjectFactory(cData.getDataStream());
      message = pgpFact.nextObject();
    }

    if (message instanceof PGPLiteralData) {
      log.info("message is PGPLiteralData");
      PGPLiteralData literalData = (PGPLiteralData) message;
      return literalData.getInputStream();
    }

    if (message instanceof PGPOnePassSignatureList) {
      log.info("message is PGPOnePassSignatureList");
      PGPOnePassSignatureList p1 = (PGPOnePassSignatureList) message;
      PGPOnePassSignature ops = p1.get(0);
      log.info("> retrieved PGPOnePassSignature");

      PGPLiteralData p2 = (PGPLiteralData) pgpFact.nextObject();
      InputStream dIn = p2.getInputStream();

      int ch;
      PGPPublicKeyRingCollection pgpRing = new JcaPGPPublicKeyRingCollection(PGPUtil.getDecoderStream(publicVerifierKey));
      PGPPublicKey key = pgpRing.getPublicKey(ops.getKeyID());

      ByteArrayOutputStream out = new ByteArrayOutputStream();

      ops.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), key);
      while ((ch = dIn.read()) >= 0) {
        ops.update((byte) ch);
        out.write(ch);
      }
      out.close();

//      PGPSignatureList p3 = (PGPSignatureList) plainFact.nextObject();
//      PGPSignatureList p3 = (PGPSignatureList) pgpFact.nextObject();
//      if (ops.verify(p3.get(0))) {
//        System.out.println("signature verified.");
//      } else {
//        System.out.println("signature verification failed.");
//      }

      return new ByteArrayInputStream(out.toByteArray());
    }

    throw new PGPException("message is not a simple encrypted file - type unknown.");
  }

//  private Object unwrapCompressedData(Object message) throws PGPException, IOException {
//    if (message instanceof PGPCompressedData) {
//      PGPCompressedData cData = (PGPCompressedData) message;
//      JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(cData.getDataStream());
//      return pgpFact.nextObject();
//    }
//    return message;
//  }

  public boolean verify() {
    try {
      publicVerifierKey = PGPUtil.getDecoderStream(publicVerifierKey);
      JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(encryptedData);
      PGPSignature sig = ((PGPSignatureList) pgpFact.nextObject()).get(0);
      PGPPublicKeyRingCollection pgpRing = new JcaPGPPublicKeyRingCollection(PGPUtil.getDecoderStream(publicVerifierKey));
      PGPPublicKey key = pgpRing.getPublicKey(sig.getKeyID());

      sig.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), key);
      byte[] buff = new byte[1024];
      int read = 0;
      while ((read = encryptedData.read(buff)) != -1) {
        sig.update(buff, 0, read);
      }
      encryptedData.close();
      return sig.verify();
    }
    catch (Exception ex) {
      log.error("failed to verify signature, {}", ex.getMessage(), ex);
      return false;
    }
  }
}
