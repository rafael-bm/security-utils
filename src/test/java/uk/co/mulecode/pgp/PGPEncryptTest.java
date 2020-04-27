package uk.co.mulecode.pgp;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import org.apache.commons.io.IOUtils;
import org.junit.Test;
import uk.co.mulecode.pgp.exception.PGPDecryptException;


public class PGPEncryptTest {

  public static final String TESTKEY_PASSPHRASE = "testkey";

  @Test
  public void validKeyPair_shouldEncryptAndDecryptContent() throws Exception {

    InputStream publicKey = givenPublicKey();
    InputStream privateKey = givenPrivateKey();

    var encryptedStream = PGPEncrypt.builder()
        .publicKey(publicKey)
        .rawData(givenStringContentStream())
        .build()
        .encrypt()
        .getEncryptedContentAsInputStream();

    var decryptedValue = PGPDecrypt.builder()
        .privateKey(privateKey)
        .passPhrase(TESTKEY_PASSPHRASE.toCharArray())
        .encryptedData(encryptedStream)
        .build()
        .decrypt()
        .getDecryptContentAsString();

    assertThat(decryptedValue).isEqualTo(givenStringContent());
  }

  @Test(expected = PGPDecryptException.class)
  public void InvalidKeyPhrase_shouldThrowException() throws Exception {

    InputStream publicKey = givenPublicKey();
    InputStream privateKey = givenPrivateKey();

    var encryptedStream = PGPEncrypt.builder()
        .publicKey(publicKey)
        .rawData(givenStringContentStream())
        .build()
        .encrypt()
        .getEncryptedContentAsInputStream();

    var decryptedValue = PGPDecrypt.builder()
        .privateKey(privateKey)
        .passPhrase("InvalidPass".toCharArray())
        .encryptedData(encryptedStream)
        .build()
        .decrypt()
        .getDecryptContentAsString();
  }

  @Test(expected = PGPDecryptException.class)
  public void InvalidKeyPair_shouldThrowException() throws Exception {

    InputStream publicKey = givenPublicKey();
    InputStream privateKey = givenSignPrivateKey();

    var encryptedStream = PGPEncrypt.builder()
        .publicKey(publicKey)
        .rawData(givenStringContentStream())
        .build()
        .encrypt()
        .getEncryptedContentAsInputStream();

    var decryptedValue = PGPDecrypt.builder()
        .privateKey(privateKey)
        .passPhrase(TESTKEY_PASSPHRASE.toCharArray())
        .encryptedData(encryptedStream)
        .build()
        .decrypt()
        .getDecryptContentAsString();
  }

  @Test
  public void validKeyPairAndSigned_shouldEncryptAndDecryptContent() throws Exception {

    InputStream publicKey = givenPublicKey();
    InputStream privateSignKey = givenSignPrivateKey();

    InputStream privateKey = givenPrivateKey();
    InputStream publicSignVerifierKey = givenSignPublicKey();

    var encryptedStream = PGPEncrypt.builder()
        .publicKey(publicKey)
        .rawData(givenStringContentStream())
        .isSigning(true)
        .privateSignKey(privateSignKey)
        .privateSignPassPhrase(TESTKEY_PASSPHRASE.toCharArray())
        .build()
        .encrypt()
        .getEncryptedContentAsInputStream();

    var valid = PGPDecryptSign.builder()
        .privateKey(privateKey)
        .passPhrase(TESTKEY_PASSPHRASE.toCharArray())
        .encryptedData(encryptedStream)
        .publicVerifierKey(publicSignVerifierKey)
        .build()
        .verify();
    System.out.println(">>>>>> "+ valid);

//    var decryptedValue = PGPDecryptSign.builder()
//        .privateKey(privateKey)
//        .passPhrase(TESTKEY_PASSPHRASE.toCharArray())
//        .encryptedData(encryptedStream)
//        .publicVerifierKey(publicSignVerifierKey)
//        .build()
//        .decrypt()
//        .getDecryptContentAsString();
//
//    System.out.println(">>>>>> "+ decryptedValue);
//    assertThat(decryptedValue).isEqualTo(givenStringContent());
  }

  private InputStream givenPrivateKey() {
    return this.getClass().getClassLoader().getResourceAsStream("pgp/pgp-private.key");
  }

  private InputStream givenPublicKey() {
    return this.getClass().getClassLoader().getResourceAsStream("pgp/pgp-public.key");
  }

  private InputStream givenSignPrivateKey() {
    return this.getClass().getClassLoader().getResourceAsStream("pgp/sign-private.key");
  }

  private InputStream givenSignPublicKey() {
    return this.getClass().getClassLoader().getResourceAsStream("pgp/sign-public.key");
  }

  private InputStream givenStringContentStream() {
    return IOUtils.toInputStream(givenStringContent(), StandardCharsets.UTF_8);
  }

  private String givenStringContent() {
    return "lorem ipsum";
  }
}
