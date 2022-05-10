package controllers

import akka.stream.scaladsl.Source
import eu.europa.esig.dss.enumerations.DigestAlgorithm
import models.{DataToSign, GetDataToSign, Sign}
import play.api.libs.json.Json
import play.api.mvc._
import services.SigningService

import javax.inject._

/**
 * This controller creates an `Action` to handle HTTP requests to the
 * application's home page.
 */
@Singleton
class SignController @Inject()(cc: ControllerComponents, signService: SigningService) extends AbstractController(cc) {

  def getDataToSign: Action[GetDataToSign] = Action(parse.json[GetDataToSign]) { req =>
    Ok(Json.toJson(DataToSign(signService.getDataToSign(docPath = req.body.docPath, certificateChain = req.body.certChain, digestAlgorithm = DigestAlgorithm.forName(req.body.digestAlgo)))))
  }

  def getHashedDataToSign: Action[GetDataToSign] = Action(parse.json[GetDataToSign]) { req =>
    Ok(Json.toJson(DataToSign(signService.getHashedDataToSign(docPath = req.body.docPath, certificateChain = req.body.certChain, digestAlgorithm = DigestAlgorithm.forName(req.body.digestAlgo)))))
  }

  def sign: Action[Sign] = Action(parse.json[Sign]) { req =>
    val bytes = signService.sign(docPath = req.body.docPath, outputPath = req.body.outputPath, signatureBytes = req.body.signatureBytes, certificateChain = req.body.certChain, digestAlgorithm = DigestAlgorithm.forName(req.body.digestAlgo))
    Ok.streamed(content = Source.single(bytes), Some(bytes.size), None)
  }

}