package models

import play.api.libs.json.{Format, Json}

case class GetDataToSign(docPath: String, certChain: Seq[String], digestAlgo: String, encryptionAlgo: String)
object GetDataToSign {
  implicit val fmt: Format[GetDataToSign] = Json.format
}

case class Sign(signatureBytes: String, outputPath: String)
object Sign {
  implicit val fmt: Format[Sign] = Json.format
}