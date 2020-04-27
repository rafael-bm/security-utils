package uk.co.mulecode.pgp;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import lombok.Builder;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import uk.co.mulecode.pgp.exception.PGPDecryptException;

@Slf4j
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
      PGPEncryptedDataList cryptedDataList = getDataList(objectFactory);

      PGPPublicKeyEncryptedData encP = (PGPPublicKeyEncryptedData) cryptedDataList.get(0);

      InputStream clearStream = encP.getDataStream(new BcPublicKeyDataDecryptorFactory(getPGPPrivateKey(encP.getKeyID())));

      PGPObjectFactory plainFact = new PGPObjectFactory(clearStream, new JcaKeyFingerprintCalculator());

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

  private PGPPrivateKey getPGPPrivateKey(Long id) throws Exception {
    return getPgpSecretKey(id)
        .extractPrivateKey(
            new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider())
                .build(this.passPhrase)
        );
  }

  private PGPEncryptedDataList getDataList(JcaPGPObjectFactory objectFactory) throws IOException {
    Object object = objectFactory.nextObject();
    // The first object might be a PGP marker packet.
    if (object instanceof PGPEncryptedDataList) {
      return (PGPEncryptedDataList) object;
    }
    return (PGPEncryptedDataList) objectFactory.nextObject();
  }

}
