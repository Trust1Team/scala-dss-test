package utils

import eu.europa.esig.dss.enumerations.{DigestAlgorithm, SignatureAlgorithm}
import org.bouncycastle.util.io.pem.PemReader

import java.io.StringReader
import java.security._
import java.security.spec.PKCS8EncodedKeySpec

object PKIUtil {
  private val MD5_DIGEST = "MD5"
  private val SHA1_DIGEST = "SHA1"
  private val SHA256_DIGEST = "SHA256"
  private val SHA512_DIGEST = "SHA512"

  private val MD5_SIG = "MD5withRSA"
  private val SHA1_SIG = "SHA1withRSA"
  private val SHA256_SIG = "SHA256withRSA"
  private val SHA512_SIG = "SHA512withRSA"

  def getSignatureAlgoFromDigestString(digestAlgorithm: String): String = digestAlgorithm.toUpperCase match {
    case MD5_DIGEST => MD5_SIG
    case SHA1_DIGEST => SHA1_SIG
    case SHA256_DIGEST => SHA256_SIG
    case SHA512_DIGEST => SHA512_SIG
    case _ => SHA256_SIG
  }

  def getSignatureAlgoFromDigest(digestAlgorithm: DigestAlgorithm): String = getSignatureAlgoFromDigestString(digestAlgorithm.getName)

  def getDssSignatureAlgorithm(digestAlgorithm: DigestAlgorithm): SignatureAlgorithm = {
    digestAlgorithm match {
      case DigestAlgorithm.SHA1 => SignatureAlgorithm.RSA_SHA1
      case DigestAlgorithm.SHA256 => SignatureAlgorithm.RSA_SHA256
      case DigestAlgorithm.SHA384 => SignatureAlgorithm.RSA_SHA384
      case DigestAlgorithm.SHA512 => SignatureAlgorithm.RSA_SHA512
      case DigestAlgorithm.RIPEMD160 => SignatureAlgorithm.RSA_RIPEMD160
      case DigestAlgorithm. MD2 => SignatureAlgorithm.RSA_MD2
      case DigestAlgorithm.MD5 => SignatureAlgorithm.RSA_MD5
      case _ => SignatureAlgorithm.RSA_SHA1
    }
  }

  /*def getPrivateKeyAndCertChainFromPfx(filePath: String, alias: String, password: String, rootCert: Option[String]): Pkcs12SignatureToken = {
    val pkcs12TokenFile = new File(filePath)
    new Pkcs12SignatureToken(pkcs12TokenFile, new PasswordProtection("KzuBJW6VtTUkE9KP".toCharArray))
  }*/

  def getPrivateKeyFromPem(pem: String): PrivateKey = {
    val pemReader = new PemReader(new StringReader(pem))
    val content = pemReader.readPemObject.getContent
    val spec = new PKCS8EncodedKeySpec(content)
    val kf = KeyFactory.getInstance("RSA")
    kf.generatePrivate(spec)
  }
}