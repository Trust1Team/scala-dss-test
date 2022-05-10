package services

import akka.Done
import akka.util.ByteString
import com.google.inject.ImplementedBy
import eu.europa.esig.dss.alert.{LogOnStatusAlert, StatusAlert}
import eu.europa.esig.dss.enumerations.{DigestAlgorithm, SignatureLevel, SignaturePackaging}
import eu.europa.esig.dss.model.{InMemoryDocument, SignatureValue}
import eu.europa.esig.dss.pades.signature.PAdESService
import eu.europa.esig.dss.pades.{PAdESSignatureParameters, PAdESTimestampParameters}
import eu.europa.esig.dss.service.crl.OnlineCRLSource
import eu.europa.esig.dss.service.http.commons.{CommonsDataLoader, FileCacheDataLoader, OCSPDataLoader, TimestampDataLoader}
import eu.europa.esig.dss.service.http.proxy.ProxyConfig
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource
import eu.europa.esig.dss.service.tsp.OnlineTSPSource
import eu.europa.esig.dss.spi.DSSUtils
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource
import eu.europa.esig.dss.spi.x509.{CommonTrustedCertificateSource, KeyStoreCertificateSource}
import eu.europa.esig.dss.tsl.cache.CacheCleaner
import eu.europa.esig.dss.tsl.function._
import eu.europa.esig.dss.tsl.job.TLValidationJob
import eu.europa.esig.dss.tsl.source.LOTLSource
import eu.europa.esig.dss.validation.CommonCertificateVerifier
import eu.europa.esig.dss.xades.signature.XAdESService
import org.apache.commons.io.IOUtils
import org.slf4j.event.Level
import play.api.{Configuration, Logging}
import utils.PKIUtil

import java.io.ByteArrayInputStream
import java.nio.file.{Files, Paths}
import java.util.{Base64, Date}
import javax.inject.{Inject, Singleton}
import scala.jdk.CollectionConverters._
import scala.util.{Failure, Success, Try}

@ImplementedBy(classOf[DSSService])
trait SigningService {


  def getDataToSign(docPath: String, certificateChain: Seq[String], digestAlgorithm: DigestAlgorithm): String
  def getHashedDataToSign(docPath: String, certificateChain: Seq[String], digestAlgorithm: DigestAlgorithm): String
  def sign(docPath: String, outputPath: Option[String], signatureBytes: String, certificateChain: Seq[String], digestAlgorithm: DigestAlgorithm): ByteString

  /**
    * Refresh the TSL repository status, and validate against LOTL
    * @return Done when done or errored
    */
  def refreshTslRepositoryValidation: Done
}

@Singleton
final class DSSService @Inject()(config: Configuration) extends SigningService with Logging {

  lazy val keystore: KeyStoreCertificateSource = {
    val keystoreIs = new ByteArrayInputStream(Base64.getDecoder.decode(config.get[String]("dss.lotl-keystore")))
    val ksPwd = config.get[String]("dss.lotl-keystore-pwd")
    val ksType = config.get[String]("dss.lotl-keystore-type")
    new KeyStoreCertificateSource(
      keystoreIs,
      ksType,
      ksPwd
    )
  }

  lazy val trustStoreSource: CommonTrustedCertificateSource = {
    val tlcs = new CommonTrustedCertificateSource
    tlcs.importAsTrusted(keystore)
    tlcs
  }

  lazy val ocspSource: OnlineOCSPSource = {
    val source = new OnlineOCSPSource
    source.setDataLoader(getOCSPDataLoader)
    source
  }

  lazy val crlSource: OnlineCRLSource = {
    val source = new OnlineCRLSource
    source.setDataLoader(getCommonsDataLoader)
    source
  }

  lazy val trustedListCertSource = new TrustedListsCertificateSource

  lazy val euLotlSource: LOTLSource = {
    val ojUrl = config.get[String]("dss.oj-url")
    val lotlUrl = config.get[String]("dss.lotl-url")

    val lotlSource = new LOTLSource
    lotlSource.setUrl(lotlUrl)
    lotlSource.setCertificateSource(trustStoreSource)
    lotlSource.setPivotSupport(true)
    lotlSource.setLotlPredicate(new EULOTLOtherTSLPointer().and(new XMLOtherTSLPointer()))
    lotlSource.setTlPredicate(new EUTLOtherTSLPointer().and(new XMLOtherTSLPointer))
    lotlSource.setSigningCertificatesAnnouncementPredicate(new OfficialJournalSchemeInformationURI(ojUrl))
    lotlSource.setTrustServicePredicate(new GrantedTrustService())
    lotlSource
  }

  lazy val commonCertificateVerifier: CommonCertificateVerifier = {
    val statusAlert: StatusAlert = new LogOnStatusAlert(Level.WARN)
    val certVerifier = new CommonCertificateVerifier
    certVerifier.setTrustedCertSources(trustStoreSource, trustedListCertSource)
    certVerifier.setOcspSource(ocspSource)
    certVerifier.setCrlSource(crlSource)
    certVerifier.setAlertOnInvalidTimestamp(statusAlert)
    certVerifier.setAlertOnMissingRevocationData(statusAlert)
    certVerifier.setAlertOnRevokedCertificate(statusAlert)
    certVerifier
  }

  lazy val tlDataLoader: FileCacheDataLoader = {
    val dssCacheDir = "/tmp"
    val fileLoader = new FileCacheDataLoader
    fileLoader.setCacheExpirationTime(0)
    fileLoader.setDataLoader(getCommonsDataLoader) // instance of DataLoader which can access to Internet (proxy,...)
    val cacheDir = dssCacheDir
    if (cacheDir.nonEmpty) fileLoader.setFileCacheDirectory(Paths.get(cacheDir).toFile)
    fileLoader
  }

  lazy val cacheCleaner: CacheCleaner = {
    val cacheCleaner = new CacheCleaner
    cacheCleaner.setCleanMemory(true) // free the space in memory
    cacheCleaner.setCleanFileSystem(true) // remove the stored file(s) on the file-system
    cacheCleaner.setDSSFileLoader(tlDataLoader)
    cacheCleaner
  }

  lazy val validationJob: TLValidationJob = {
    val tlValidationJob = new TLValidationJob()
    tlValidationJob.setTrustedListCertificateSource(trustedListCertSource)
    tlValidationJob.setTrustedListSources(euLotlSource)
    tlValidationJob.setOnlineDataLoader(tlDataLoader)
    tlValidationJob.setOfflineDataLoader(tlDataLoader)
    tlValidationJob.setCacheCleaner(cacheCleaner)
    tlValidationJob.setListOfTrustedListSources(euLotlSource)
    tlValidationJob
  }

  lazy val tspSource: OnlineTSPSource = {
    val tsaUrl = config.get[String]("dss.tsa-url")
    val source = new OnlineTSPSource()
    source.setDataLoader(getTimestampDataLoader)
    source.setTspServer(tsaUrl)
    source
  }

  lazy val padesService: PAdESService = {
    val pAdESService = new PAdESService(commonCertificateVerifier)
    pAdESService.setTspSource(tspSource)
    pAdESService
  }
  lazy val xadesService: XAdESService = {
    val xAdESService = new XAdESService(commonCertificateVerifier)
    xAdESService.setTspSource(tspSource)
    xAdESService
  }


  override def getDataToSign(docPath: String, certificateChain: Seq[String], digestAlgorithm: DigestAlgorithm): String = {
    val tbs = pAdESDataToSign(document = new InMemoryDocument(Files.readAllBytes(Paths.get(docPath))), certChain = certificateChain,  digestAlgorithm = digestAlgorithm)
    println(s"${digestAlgorithm.getName}: ${tbs.length}")
    Base64.getEncoder.encodeToString(tbs)
  }

  override def getHashedDataToSign(docPath: String, certificateChain: Seq[String], digestAlgorithm: DigestAlgorithm): String = {
    Base64.getEncoder.encodeToString(pAdESDataToSign(document = new InMemoryDocument(Files.readAllBytes(Paths.get(docPath))), certChain = certificateChain,  digestAlgorithm = digestAlgorithm))
  }

  override def sign(docPath: String, outputPath: Option[String], signatureBytes: String, certificateChain: Seq[String], digestAlgorithm: DigestAlgorithm): ByteString = {
    pAdESSign(new InMemoryDocument(Files.readAllBytes(Paths.get(docPath))), certificateChain,  digestAlgorithm, Base64.getDecoder.decode(signatureBytes), outputPath)
  }

  override def refreshTslRepositoryValidation: Done = {
    Try {
      logger.debug("Starting TSL repository validation refresh")
      validationJob.onlineRefresh()
      logger.debug("Finished TSL repository validation refresh")
    } match {
      case Failure(ex) =>
        logger.warn(s"Error refreshing the TSL repository: ${ex.getMessage}", ex)
        Done
      case Success(_) => Done
    }
  }

  private def pAdESDataToSign(document: InMemoryDocument, certChain: Seq[String], digestAlgorithm: DigestAlgorithm): Array[Byte] = {
    val signatureParams = getPadesSignatureParams(certChain, digestAlgorithm)
    logger.debug(s"DSS - creating data to sign from document")
    padesService.getDataToSign(document, signatureParams).getBytes
  }

  private def pAdESSign(document: InMemoryDocument, certChain: Seq[String], digestAlgorithm: DigestAlgorithm, signatureBytes: Array[Byte], outputPath: Option[String]): ByteString = {
    val sigParams = getPadesSignatureParams(certChain, digestAlgorithm)
    val signedDocument = padesService.signDocument(document, sigParams, new SignatureValue(PKIUtil.getDssSignatureAlgorithm(sigParams.getDigestAlgorithm), signatureBytes))
    val signedBytes = IOUtils.toByteArray(signedDocument.openStream())
    outputPath.foreach(op => Files.write(Paths.get(op), signedBytes))
    ByteString.fromArray(signedBytes)
  }

  private def getPadesSignatureParams(certificateChain: Seq[String], digestAlgorithm: DigestAlgorithm): PAdESSignatureParameters = {
    //certificateChain.foreach(cert => logger.debug(cert))
    val params = new PAdESSignatureParameters
    val signatureLevel = SignatureLevel.PAdES_BASELINE_B
    params.setSignatureLevel(signatureLevel)
    params.setContentSize(9472 * 2)
    //TODO Add reason for signing
    params.setReason("This is a test")
    params.setSignaturePackaging(SignaturePackaging.DETACHED)
    params.setSignWithExpiredCertificate(true)
    params.setDigestAlgorithm(digestAlgorithm)
    params.bLevel().setSigningDate(new Date())
    params.setSigningCertificate(DSSUtils.loadCertificateFromBase64EncodedString(certificateChain.head))
    params.setCertificateChain(certificateChain.map(certString => DSSUtils.loadCertificateFromBase64EncodedString(certString)).asJava)
    val timestampParameters = new PAdESTimestampParameters
    params.setSignatureTimestampParameters(timestampParameters)
    params.setArchiveTimestampParameters(timestampParameters)
    params
  }



  private def getProxyConfig: Option[ProxyConfig] = {
    //TODO add proxy config parsing
    Option.empty
  }

  private def getTimestampDataLoader = {
    val dataLoader = new TimestampDataLoader()
    getProxyConfig.foreach(dataLoader.setProxyConfig)
    dataLoader
  }

  private def getCommonsDataLoader = {
    val dataLoader = new CommonsDataLoader()
    getProxyConfig.foreach(dataLoader.setProxyConfig)
    dataLoader
  }

  private def getOCSPDataLoader = {
    val dataLoader = new OCSPDataLoader()
    getProxyConfig.foreach(dataLoader.setProxyConfig)
    dataLoader
  }
}