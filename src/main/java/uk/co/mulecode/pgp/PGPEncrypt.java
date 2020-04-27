package uk.co.mulecode.pgp;

import static uk.co.mulecode.pgp.PGPUtils.findSecretKey;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Iterator;
import lombok.Builder;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import uk.co.mulecode.pgp.exception.PGPEncryptException;


public class PGPEncrypt {

  private boolean isArmored;
  private boolean checkIntegrity;
  private boolean isSigning;
  private InputStream rawData;
  private InputStream publicKey;

  private char[] privateSignPassPhrase;
  private InputStream privateSignKey;

  private OutputStream encryptedContent;

  @Builder
  public PGPEncrypt(boolean isArmored, boolean checkIntegrity, boolean isSigning, InputStream rawData, InputStream publicKey,
      InputStream privateSignKey, char[] privateSignPassPhrase) {
    this.isArmored = isArmored;
    this.checkIntegrity = checkIntegrity;
    this.isSigning = isSigning;
    this.rawData = rawData;
    this.publicKey = publicKey;
    this.privateSignKey = privateSignKey;
    this.privateSignPassPhrase = privateSignPassPhrase;
  }

  public InputStream getEncryptedContentAsInputStream() throws Exception {
    return new ByteArrayInputStream(((ByteArrayOutputStream) encryptedContent).toByteArray());
  }

  public OutputStream getEncryptedContent() throws Exception {
    return encryptedContent;
  }

  public PGPEncrypt encrypt() throws Exception {

    PGPEncryptedDataGenerator pedg = new PGPEncryptedDataGenerator(
        new JcePGPDataEncryptorBuilder(
            PGPEncryptedData.CAST5)
            .setWithIntegrityPacket(checkIntegrity)
            .setSecureRandom(new SecureRandom())
            .setProvider(new BouncyCastleProvider())
    );

    PGPPublicKey pgpPublicKey = PGPUtils.readPublicKey(publicKey);

    pedg.addMethod(
        new BcPublicKeyKeyEncryptionMethodGenerator(pgpPublicKey)
    );

    OutputStream byteOutStream = new ByteArrayOutputStream();
    if (isArmored) {
      byteOutStream = new ArmoredOutputStream(byteOutStream);
    }

    OutputStream encryptdOutStream = pedg.open(byteOutStream, new byte[1 << 16]);
    PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);
    OutputStream compressedOutStream = comData.open(encryptdOutStream);

    try {
      PGPSignatureGenerator sigGenerator = null;
      if (isSigning) {
        PGPSecretKey secretKey = findSecretKey(privateSignKey);
        PGPPrivateKey privateKey = secretKey.extractPrivateKey(
            new BcPBESecretKeyDecryptorBuilder(
                new BcPGPDigestCalculatorProvider()
            ).build(this.privateSignPassPhrase)
        );

        sigGenerator = new PGPSignatureGenerator(
            new BcPGPContentSignerBuilder(privateKey.getPublicKeyPacket().getAlgorithm(),
                HashAlgorithmTags.MD5)
        );

//        sigGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey);
        sigGenerator.init(PGPSignature.CANONICAL_TEXT_DOCUMENT, privateKey);

        Iterator it = secretKey.getPublicKey().getUserIDs();

        if (it.hasNext()) {
          PGPSignatureSubpacketGenerator signer = new PGPSignatureSubpacketGenerator();
          signer.setSignerUserID(false, (String) it.next());
          sigGenerator.setHashedSubpackets(signer.generate());
        }
        sigGenerator.generateOnePassVersion(false).encode(compressedOutStream);

      }

      PGPLiteralDataGenerator lg = new PGPLiteralDataGenerator();
      OutputStream literalDataOutStream = lg.open(
          compressedOutStream,
          PGPLiteralData.BINARY,
          "",
          new Date(),
          new byte[1 << 16]
      );

      byte[] bytes = IOUtils.toByteArray(rawData);

      literalDataOutStream.write(bytes);

      if (isSigning && sigGenerator != null) {
        sigGenerator.update(bytes);
        sigGenerator.generate().encode(compressedOutStream);
      }

      literalDataOutStream.close();
      lg.close();
      compressedOutStream.close();
      comData.close();
      pedg.close();
      byteOutStream.close();

      this.encryptedContent = byteOutStream;
      return this;
    } catch (Exception e) {
      throw new PGPEncryptException("Failed to encrypt", e);
    }

  }


}
