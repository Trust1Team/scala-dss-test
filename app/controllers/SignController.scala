package controllers

import eu.europa.esig.dss.enumerations.{DigestAlgorithm, EncryptionAlgorithm}
import models.{DataToSign, GetDataToSign, Sign}
import play.api.libs.json.Json
import play.api.mvc._
import services.SigningService

import javax.inject._
import scala.util.{Failure, Success, Try}

/**
 * This controller creates an `Action` to handle HTTP requests to the
 * application's home page.
 */
@Singleton
class SignController @Inject()(cc: ControllerComponents, signService: SigningService) extends AbstractController(cc) {

  def healthz: Action[AnyContent] = Action { Ok }

  def getDataToSign: Action[GetDataToSign] = Action(parse.json[GetDataToSign]) { req =>
    signService.getDataToSign(
      docPath = req.body.docPath,
      certificateChain = req.body.certChain,
      digestAlgorithm = DigestAlgorithm.forName(req.body.digestAlgo),
      encryptionAlgorithm = Try(EncryptionAlgorithm.forName(req.body.encryptionAlgo)).getOrElse(EncryptionAlgorithm.RSA)
    ) match {
      case Failure(ex) => throw ex
      case Success(dataToSign) => Ok(Json.toJson(DataToSign(dataToSign)))
    }

  }

  def getDataToSignDigest: Action[GetDataToSign] = Action(parse.json[GetDataToSign]) { req =>
    signService.getDataToSignDigest(
      docPath = req.body.docPath,
      certificateChain = req.body.certChain,
      digestAlgorithm = DigestAlgorithm.forName(req.body.digestAlgo),
      encryptionAlgorithm = Try(EncryptionAlgorithm.forName(req.body.encryptionAlgo)).getOrElse(EncryptionAlgorithm.RSA)
    ) match {
      case Failure(ex) => throw ex
      case Success(dataToSign) => Ok(Json.toJson(DataToSign(dataToSign)))
    }
  }

  def sign: Action[Sign] = Action(parse.json[Sign]) { req =>
    signService.sign(outputPath = req.body.outputPath, signatureBytes = req.body.signatureBytes) match {
      case Failure(ex) => throw ex
      case Success(outputPath) => Ok(outputPath)
    }
  }

}