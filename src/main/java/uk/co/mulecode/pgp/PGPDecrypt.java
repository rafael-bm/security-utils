package uk.co.mulecode.pgp;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.Iterator;
import lombok.Builder;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import uk.co.mulecode.pgp.exception.PGPDecryptException;


public class PGPDecrypt {

  private InputStream publicVerifierKey;

  private InputStream encryptedData;
  private InputStream privateKey;
  private char[] passPhrase;

  private InputStream decryptedContent;

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  @Builder
  public PGPDecrypt(InputStream encryptedData, InputStream privateKey, char[] passPhrase,
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

  public PGPDecrypt decrypt() {
    try {
      InputStream decoderStream = PGPUtil.getDecoderStream(encryptedData);
      JcaPGPObjectFactory objectFactory = new JcaPGPObjectFactory(decoderStream);
      PGPEncryptedDataList enc = getDataList(objectFactory);
      InputStream dec = getDecryptionStream(enc);
      decryptedContent = getDecryptedData(dec);
      return this;
    } catch (Exception e) {
      throw new PGPDecryptException("Failure to decrypt", e);
    }
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

  private InputStream getDecryptedData(InputStream decryptionStream) throws PGPException, IOException {
    JcaPGPObjectFactory plainFact = new JcaPGPObjectFactory(decryptionStream);
    Object message = unwrapCompressedData(plainFact.nextObject());

    if (message instanceof PGPLiteralData) {
      PGPLiteralData literalData = (PGPLiteralData) message;
      return literalData.getInputStream();
    }

    throw new PGPException("message is not a simple encrypted file - type unknown.");
  }

  private Object unwrapCompressedData(Object message) throws PGPException, IOException {
    if (message instanceof PGPCompressedData) {
      PGPCompressedData cData = (PGPCompressedData) message;
      JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(cData.getDataStream());
      return pgpFact.nextObject();
    }
    return message;
  }
}
